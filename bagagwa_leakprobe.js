/*
 * bagagwa_leakprobe.js -- v=155
 *
 * Sweep the eight "get info" syscalls on PS5 that have never been probed on
 * 13.60. For each, try five argument shapes. Canary getpid between every call.
 *
 * Design goals:
 *  - One page, auto-runs, single-shot, no reuse after a wedge
 *  - Small buffer (0x40) to stay inside the WebProcess budget
 *  - Persist every "about to call X" line to localStorage BEFORE the call, so
 *    a mid-call OOM still leaves the argument shape in the log
 *  - No flushMark/syncMark during the sweep; only BEGIN, VERDICT, WEDGE
 *  - If any call writes NONZERO bytes to the buffer, log and stop that
 *    syscall and continue to the next
 *
 * READ-ONLY. No kernel writes. No num>=2 anywhere. Nothing except the
 * targeted syscalls.
 */
(function (root) {
    "use strict";
    if (root.__B155_LOADED) return;
    root.__B155_LOADED = true;

    var FW = root.fw_str || "?";
    var VERSION = "v155";

    var NR = {
        GETPID: 0x014,
        GETPPID: 0x027,
        THR_SELF: 0x1B0,
    };

    /* The eight untested syscalls, in order of promise. */
    var TARGETS = [
        { num: 0x29F, name: "get_page_table_stats" },
        { num: 0x286, name: "get_kernel_mem_statistics" },
        { num: 0x29B, name: "get_bio_usage_all" },
        { num: 0x24A, name: "dmem_container" },
        { num: 0x282, name: "get_map_statistics" },
        { num: 0x2A2, name: "virtual_query_all" },
        { num: 0x298, name: "aio_multi_poll" },
        { num: 0x295, name: "aio_submit" },
    ];

    function B(x) { return (typeof x === "bigint") ? x : BigInt(x); }
    function hex(v) {
        try {
            var b = BigInt(v);
            if (b < 0n) b = BigInt.asUintN(64, b);
            return "0x" + b.toString(16);
        } catch (e) { return String(v); }
    }
    function malloc(sz) { return B(root.malloc(sz)); }
    function readBytes(p, n) { return new Uint8Array(root.read_buffer(B(p), n)); }

    function canary() {
        try {
            var r = B(root.syscall(NR.GETPID, 0n, 0n, 0n, 0n, 0n, 0n));
            return r > 0n && r < 0x100000n;
        } catch (e) { return false; }
    }

    var st = { ourPid: 0n, ourPpid: 0n, ourTid: 0n, wedge: false };

    /* ---- minimal panel ---- */
    var styleEl = document.createElement("style");
    styleEl.textContent = [
        ".b155{position:fixed;inset:0;z-index:2147483647;background:#0c0c0f;color:#fff;",
        "font-family:Arial,sans-serif;display:flex;flex-direction:column;",
        "padding:12px 14px;box-sizing:border-box;}",
        ".b155-out{flex:1;overflow:auto;background:#16161a;border:1px solid #26262b;",
        "border-radius:.6rem;margin:0;padding:8px 10px;font:11.5px/1.45 Consolas,monospace;",
        "color:#c9c9d1;white-space:pre-wrap;word-break:break-all;}",
        ".ok{color:#5fdc90;}.err{color:#ff8080;}.warn{color:#ffce5c;}.dim{color:#6f7076;}",
        ".sec{color:#fff;font-weight:800;}",
    ].join("");
    document.head.appendChild(styleEl);

    var panel = document.createElement("div");
    panel.className = "b155";
    panel.innerHTML = '<pre class="b155-out" id="b-out"></pre>';
    document.body.appendChild(panel);

    var elOut = document.getElementById("b-out");
    var LOG = [];
    var LOGKEY = "b155_sc_log";

    function stamp() {
        var d = new Date();
        var p = function (n) { return String(n).padStart(2, "0"); };
        return p(d.getHours()) + ":" + p(d.getMinutes()) + ":" + p(d.getSeconds());
    }
    function persist(line) {
        try {
            var cur = localStorage.getItem(LOGKEY) || "";
            cur += line + "\n";
            if (cur.length > 24000) cur = cur.slice(-12000);
            localStorage.setItem(LOGKEY, cur);
        } catch (e) { }
    }
    function logLine(text, cls) {
        var line = "[" + stamp() + "] " + text;
        LOG.push(line);
        persist(line);
        var span = document.createElement("span");
        if (cls) span.className = cls;
        span.textContent = line + "\n";
        elOut.appendChild(span);
        elOut.scrollTop = elOut.scrollHeight;
    }
    function sec(tag, detail) { logLine("LEAK " + tag + (detail ? "  " + detail : ""), "sec"); }
    function ok(tag, detail)  { logLine("LEAK " + tag + (detail ? "  " + detail : ""), "ok"); }
    function warn(tag, detail){ logLine("LEAK " + tag + (detail ? "  " + detail : ""), "warn"); }
    function err(tag, detail) { logLine("LEAK " + tag + (detail ? "  " + detail : ""), "err"); }
    function dim(tag, detail) { logLine("LEAK " + tag + (detail ? "  " + detail : ""), "dim"); }
    function beacon(tag, detail) {
        try { if (root.flushMark) root.flushMark("LEAK-" + tag, String(detail || "")); } catch (e) { }
        try { if (root.syncMark) root.syncMark("LEAK-" + tag, String(detail || "")); } catch (e) { }
    }
    function notify(m) { try { if (root.send_notification) root.send_notification(m); } catch (e) { } }

    var OUTLEN = 0x40;
    var outBuf = null;

    function diff(got) {
        var firstOff = -1, changed = 0, nz = false;
        for (var i = 0; i < got.length; i++) {
            if (got[i] !== 0xEE) { if (firstOff < 0) firstOff = i; changed++; }
        }
        if (firstOff < 0) return { changed: 0, dump: "--", nz: false };
        var n = Math.min(16, got.length - firstOff);
        var s = "";
        for (var j = 0; j < n; j++) s += got[j] ? got[j].toString(16).padStart(2, "0") : "00";
        for (var k = 0; k < n; k++) if (got[firstOff + k] !== 0) { nz = true; break; }
        return { changed: changed, dump: s, nz: nz };
    }

    function call(nr, a1, a2, a3, a4, a5, a6) {
        var z = new Uint8Array(OUTLEN);
        for (var i = 0; i < OUTLEN; i++) z[i] = 0xEE;
        root.write_buffer(B(a5), z);

        var ret = B(root.syscall(nr, a1, a2, a3, a4, a5, a6));

        if (!canary()) {
            st.wedge = true;
            err("WEDGE", "nr=" + hex(nr) + " a1=" + hex(a1) + " a2=" + hex(a2)
                + " a3=" + hex(a3) + " a4=" + hex(a4) + " a5=" + hex(a5));
            return { wedge: true };
        }
        var got = readBytes(a5, OUTLEN);
        return { wedge: false, ret: ret, diff: diff(got) };
    }

    /* Five shapes per syscall. Order matters: simplest first. */
    function shapesFor(nr, ourPid) {
        return [
            { name: "out@1",    args: [outBuf, BigInt(OUTLEN), 0n, 0n, 0n, 0n] },
            { name: "out@2",    args: [0n, outBuf, BigInt(OUTLEN), 0n, 0n, 0n] },
            { name: "out@3",    args: [0n, 0n, outBuf, BigInt(OUTLEN), 0n, 0n] },
            { name: "out@5",    args: [0n, 0n, 0n, 0n, outBuf, 0n] },
            { name: "pid,1,1,1,out,0", args: [ourPid, 1n, 1n, 1n, outBuf, 0n] },
        ];
    }

    function run() {
        try {
            sec("BEGIN", "fw=" + FW + " " + VERSION + " AUTO-RUN");
            beacon("BEGIN", FW);

            if (!canary()) {
                err("VERDICT", "no executor");
                beacon("VERDICT", "no executor");
                return;
            }
            ok("CANARY", "getpid ok");

            var tidOut = malloc(8);
            var tz = new Uint8Array(8);
            root.write_buffer(tidOut, tz);
            try { root.syscall(NR.THR_SELF, tidOut, 0n, 0n, 0n, 0n, 0n); } catch (e) { }
            st.ourTid = B(root.read64(tidOut));
            st.ourPid = B(root.syscall(NR.GETPID, 0n, 0n, 0n, 0n, 0n, 0n));
            try { st.ourPpid = B(root.syscall(NR.GETPPID, 0n, 0n, 0n, 0n, 0n, 0n)); } catch (e) { }
            dim("IDS", "tid=" + hex(st.ourTid) + " pid=" + hex(st.ourPid)
                + " ppid=" + hex(st.ourPpid));

            outBuf = malloc(OUTLEN);

            var results = [];

            for (var ti = 0; ti < TARGETS.length && !st.wedge; ti++) {
                var t = TARGETS[ti];
                sec("TARGET", "0x" + t.num.toString(16) + " " + t.name);
                var shapes = shapesFor(t.num, st.ourPid);
                var syscallsHits = 0;

                for (var si = 0; si < shapes.length && !st.wedge; si++) {
                    var sh = shapes[si];
                    persist("[t] about to call nr=" + "0x" + t.num.toString(16)
                        + " shape=" + sh.name);
                    var r = call(t.num, sh.args[0], sh.args[1], sh.args[2],
                        sh.args[3], sh.args[4], sh.args[5]);
                    if (r.wedge) break;

                    var line = "0x" + t.num.toString(16) + " " + sh.name
                        + " -> ret=" + hex(r.ret);
                    if (r.diff.changed > 0) {
                        line += "  changed=" + r.diff.changed;
                        line += "  dump=" + r.diff.dump;
                    }
                    if (r.diff.nz) {
                        ok("CALL", line);
                        syscallsHits++;
                    } else if ((r.ret & 0xFFFFFFFFn) !== 0xen
                        && (r.ret & 0xFFFFFFFFn) !== 0x1n
                        && (r.ret & 0xFFFFFFFFn) !== 0x16n
                        && (r.ret & 0xFFFFFFFFn) !== 0x0n) {
                        warn("CALL", line);
                    } else {
                        dim("CALL", line);
                    }
                }

                results.push({
                    num: "0x" + t.num.toString(16),
                    name: t.name,
                    hits: syscallsHits,
                });
            }

            sec("SUMMARY");
            if (st.wedge) {
                err("VERDICT", "WEDGE — power-cycle. See last [t] line for the arg shape.");
                beacon("VERDICT", "wedge");
                notify("LEAK: WEDGE");
                return;
            }
            var totalHits = 0;
            for (var ri = 0; ri < results.length; ri++) {
                var rw = results[ri];
                if (rw.hits > 0) {
                    ok("SUMMARY", rw.num + " " + rw.name + " — " + rw.hits + " nonzero write(s)");
                    totalHits += rw.hits;
                } else {
                    dim("SUMMARY", rw.num + " " + rw.name + " — inert");
                }
            }
            if (totalHits > 0) {
                ok("VERDICT", totalHits + " nonzero write(s) across the sweep. LEAK CANDIDATE — check the log.");
                beacon("VERDICT", "candidates " + totalHits);
                notify("LEAK: " + totalHits + " candidates");
            } else {
                warn("VERDICT", "all eight syscalls inert. No AIO-family leak on 13.60.");
                beacon("VERDICT", "all inert");
                notify("LEAK: all inert");
            }
        } catch (e) {
            err("FATAL", String((e && e.message) || e).slice(0, 180));
            beacon("FATAL", String((e && e.message) || e).slice(0, 100));
        }
    }

    try {
        var saved = localStorage.getItem(LOGKEY);
        if (saved) {
            var tail = saved.slice(-2000).split("\n").filter(function (l) { return l; });
            for (var pi = 0; pi < tail.length; pi++) {
                var sp = document.createElement("span");
                sp.className = "dim";
                sp.textContent = "    " + tail[pi] + "\n";
                elOut.appendChild(sp);
            }
        }
    } catch (e) { }

    var AUTORUN = false;
    try { AUTORUN = /(^|[?&])scauto=1(&|$)/.test(root.location.search || ""); } catch (e) { }
    if (AUTORUN) {
        setTimeout(run, 400);
    } else {
        dim("IDLE", "autorun off — add ?scauto=1 to run");
    }
})(typeof window !== "undefined" ? window : globalThis);
