/*
 * bagagwa_727probe.js -- v=151
 * Focused follow-up to v150.
 *
 * v150 established:
 *   a1 = pid (must be ours; existing-not-ours -> EPERM; nonexistent -> ESRCH)
 *   a2 = untested against a4>=1
 *   a3 = any nonzero value passes, no effect observed so far
 *   a4 = [1, 0xffff] (uint16 flag)
 *   a5 = out pointer (writes exactly 4 bytes = 0x00000000)
 *   a6 = ignored
 *
 * v151 tests the missing dimension: a2 (count). Also retests a3 forms
 * against a2>=1, and prefills requests so a2=N has something to copy.
 */
(function (root) {
    "use strict";
    if (root.__B727_LOADED) return;
    root.__B727_LOADED = true;

    var FW = root.fw_str || "?";
    var VERSION = "v151";

    var NR = {
        GETPID: 0x014, GETPPID: 0x027, THR_SELF: 0x1B0,
        CLOSE: 0x006, WRITE: 0x004,
        SOCKETPAIR: 0x035, PIPE2: 0x2AF,
        AIO_SUBMIT_CMD: 0x29D,
        AIO_MULTI_CANCEL: 0x29A,
        AIO_MULTI_DELETE: 0x296,
        AIO_INIT: 0x29E,
        DEBUG727: 0x2D7,
        SCHED_YIELD: 0x14B,
    };

    function B(x) { return (typeof x === "bigint") ? x : BigInt(x); }
    function hex(v) {
        try {
            var b = BigInt(v);
            if (b < 0n) b = BigInt.asUintN(64, b);
            return "0x" + b.toString(16);
        } catch (e) { return String(v); }
    }
    function malloc(sz) { return B(root.malloc(sz)); }
    function zeros(p, n) {
        var z = new Uint8Array(n);
        root.write_buffer(B(p), z);
        return p;
    }
    function fillWith(p, n, b) {
        var z = new Uint8Array(n);
        for (var i = 0; i < n; i++) z[i] = b;
        root.write_buffer(B(p), z);
        return p;
    }
    function readBytes(p, n) { return new Uint8Array(root.read_buffer(B(p), n)); }

    function canary() {
        try {
            var r = B(root.syscall(NR.GETPID, 0n, 0n, 0n, 0n, 0n, 0n));
            return r > 0n && r < 0x100000n;
        } catch (e) { return false; }
    }
    function S(nr, a, b, c, d, e, f) {
        var args = [a, b, c, d, e, f].map(function (x) { return x === undefined ? 0n : B(x); });
        return B(root.syscall(nr, args[0], args[1], args[2], args[3], args[4], args[5]));
    }

    var st = {
        rfd: -1, wfd: -1,
        ourPid: 0n, ourPpid: 0n, ourTid: 0n,
        wedge: false,
        ids: 0n, reqs: 0n, id0: 0n,
    };

    /* ---------------- panel ---------------- */
    var CSS = [
        ".b727r{position:fixed;inset:0;z-index:2147483647;background:#0c0c0f;color:#fff;",
        "font-family:Arial,sans-serif;display:flex;flex-direction:column;",
        "padding:14px 16px 12px;box-sizing:border-box;-webkit-user-select:none;user-select:none;}",
        ".b727r *{box-sizing:border-box;}",
        ".b727r-h{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:6px;}",
        ".b727r-logo{font-size:1.2rem;font-weight:800;letter-spacing:.18em;}",
        ".b727r-chip{font-size:.72rem;font-weight:700;letter-spacing:.08em;padding:4px 9px;",
        "border-radius:999px;background:#202125;color:#a2a2a6;}",
        ".b727r-chip.run{background:#33290d;color:#ffce5c;}",
        ".b727r-chip.ok{background:#14361f;color:#5fdc90;}",
        ".b727r-chip.bad{background:#3a1717;color:#ff8080;}",
        ".b727r-spacer{flex:1;}",
        ".b727r-btn{padding:.5rem 1rem;border-radius:1rem;border:none;cursor:pointer;",
        "background:#202125;color:#fff;font:800 .85rem Arial;}",
        ".b727r-btn:hover{background:#a2a2a6;color:#202020;}",
        ".b727r-out{flex:1;overflow:auto;background:#16161a;border:1px solid #26262b;",
        "border-radius:.6rem;margin:0;padding:10px 12px;font:12px/1.5 Consolas,monospace;",
        "color:#c9c9d1;white-space:pre-wrap;word-break:break-all;}",
        ".sec{color:#fff;font-weight:800;}",
        ".ok{color:#5fdc90;}",
        ".err{color:#ff8080;}",
        ".warn{color:#ffce5c;}",
        ".dim{color:#6f7076;}",
    ].join("");

    var styleEl = document.createElement("style");
    styleEl.textContent = CSS;
    document.head.appendChild(styleEl);

    var panel = document.createElement("div");
    panel.className = "b727r";
    panel.innerHTML = [
        '<div class="b727r-h">',
        '  <span class="b727r-logo">727</span>',
        '  <span class="b727r-chip" id="b-v"></span>',
        '  <span class="b727r-chip" id="b-fw"></span>',
        '  <span class="b727r-chip run" id="b-s">starting</span>',
        '  <span class="b727r-spacer"></span>',
        '  <button class="b727r-btn" id="b-dl">download log</button>',
        '</div>',
        '<pre class="b727r-out" id="b-out"></pre>',
    ].join("");
    document.body.appendChild(panel);

    var elOut = document.getElementById("b-out");
    var elS = document.getElementById("b-s");
    document.getElementById("b-v").textContent = VERSION;
    document.getElementById("b-fw").textContent = "fw " + FW;

    var LOG = [];
    var LOGKEY = "b727r_sc_log";

    function stamp() {
        var d = new Date();
        var p = function (n) { return String(n).padStart(2, "0"); };
        return p(d.getHours()) + ":" + p(d.getMinutes()) + ":" + p(d.getSeconds());
    }
    function logLine(text, cls) {
        var line = "[" + stamp() + "] " + text;
        LOG.push(line);
        try {
            var cur = localStorage.getItem(LOGKEY) || "";
            cur += line + "\n";
            if (cur.length > 32000) cur = cur.slice(-16000);
            localStorage.setItem(LOGKEY, cur);
        } catch (e) { }
        var span = document.createElement("span");
        if (cls) span.className = cls;
        span.textContent = line + "\n";
        elOut.appendChild(span);
        elOut.scrollTop = elOut.scrollHeight;
    }
    function out(tag, detail, cls) {
        logLine("727 " + tag + (detail ? "  " + detail : ""), cls);
        try { if (root.flushMark) root.flushMark("727-" + tag, String(detail || "")); } catch (e) { }
        try { if (root.syncMark) root.syncMark("727-" + tag, String(detail || "")); } catch (e) { }
    }
    function notify(m) { try { if (root.send_notification) root.send_notification(m); } catch (e) { } }
    function setChip(cls, text) { elS.className = "b727r-chip " + cls; elS.textContent = text; }

    document.getElementById("b-dl").onclick = function () {
        try {
            var blob = new Blob([LOG.join("\n") + "\n"], { type: "text/plain" });
            var a = document.createElement("a");
            a.href = URL.createObjectURL(blob);
            a.download = "b727_" + FW + "_v151_" + Date.now() + ".txt";
            document.body.appendChild(a); a.click();
            setTimeout(function () { try { a.remove(); } catch (e) { } }, 0);
        } catch (e) { }
    };

    /* ---------------- output buffer ---------------- */
    var OUTLEN = 0x1000;
    var outBuf = null;

    function diffReport(got) {
        var firstOff = -1, changed = 0;
        for (var i = 0; i < got.length; i++) {
            if (got[i] !== 0xEE) { if (firstOff < 0) firstOff = i; changed++; }
        }
        if (firstOff < 0) return { changed: 0, off: -1, val8: "--", u32: 0, dump: "--" };
        var n = Math.min(32, got.length - firstOff);
        var s = "", d = "";
        for (var j = 0; j < n; j++) {
            var hx = got[firstOff + j].toString(16).padStart(2, "0");
            s += hx;
            d += hx + (j % 4 === 3 ? " " : "");
        }
        var u32 = 0;
        for (var k = 0; k < Math.min(4, n); k++) u32 |= (got[firstOff + k] << (k * 8));
        return { changed: changed, off: firstOff, val8: s, u32: (u32 >>> 0), dump: d };
    }

    function call727(a1, a2, a3, a4, a5, a6) {
        fillWith(a5, OUTLEN, 0xEE);
        var ret = S(NR.DEBUG727, a1, a2, a3, a4, a5, a6);
        if (!canary()) {
            st.wedge = true;
            out("WEDGE", "a1=" + hex(a1) + " a2=" + hex(a2) + " a3=" + hex(a3)
                + " a4=" + hex(a4) + " -> no canary", "err");
            return { wedge: true, ret: ret };
        }
        var got = readBytes(a5, OUTLEN);
        return { wedge: false, ret: ret, diff: diffReport(got) };
    }

    function logCall(tag, r) {
        if (r.wedge) return;
        var d = r.diff;
        var line = tag + " -> ret=" + hex(r.ret);
        if (d.changed > 0) {
            line += "  changed=" + d.changed + "  off=" + hex(d.off) + "  dump=" + d.dump;
        }
        var cls = "dim";
        if (d.changed > 0) {
            cls = (d.changed === 4 && d.val8.slice(0, 8) === "00000000") ? "dim" : "ok";
        } else if (r.ret !== 0n && r.ret !== 0x1n && r.ret !== 0x3n && r.ret !== 0x16n) {
            cls = "ok";
        }
        out("CALL", line, cls);
    }

    /* ---------------- phases ---------------- */

    function phase1_setup() {
        out("PHASE-1", "=== SETUP ===", "sec");

        var tidOut = malloc(8); zeros(tidOut, 8);
        S(NR.THR_SELF, tidOut, 0n, 0n, 0n, 0n, 0n);
        st.ourTid = B(root.read64(tidOut));
        st.ourPid = S(NR.GETPID, 0n, 0n, 0n, 0n, 0n, 0n);
        st.ourPpid = S(NR.GETPPID, 0n, 0n, 0n, 0n, 0n, 0n);
        out("IDS", "tid=" + hex(st.ourTid) + " pid=" + hex(st.ourPid)
            + " ppid=" + hex(st.ourPpid), "dim");

        var sfds = zeros(malloc(0x10), 0x10);
        var sp = S(NR.SOCKETPAIR, 1n, 1n, 0n, sfds, 0n, 0n);
        if ((sp & 0xFFFFFFFFn) === 0n) {
            var sv = readBytes(sfds, 8);
            st.rfd = new Int32Array(sv.buffer, 0, 2)[0];
            st.wfd = new Int32Array(sv.buffer, 0, 2)[1];
            out("SRC", "socketpair rfd=" + st.rfd + " wfd=" + st.wfd, "ok");
        } else {
            var pfds = zeros(malloc(8), 8);
            var pp = S(NR.PIPE2, pfds, 0n, 0n, 0n, 0n, 0n);
            if ((pp & 0xFFFFFFFFn) === 0n) {
                var pv = readBytes(pfds, 8);
                st.rfd = new Int32Array(pv.buffer, 0, 2)[0];
                st.wfd = new Int32Array(pv.buffer, 0, 2)[1];
                out("SRC", "pipe2 rfd=" + st.rfd + " wfd=" + st.wfd, "warn");
            } else {
                out("VERDICT", "no source: sp=" + hex(sp) + " pp=" + hex(pp), "err");
                setChip("bad", "no source");
                return false;
            }
        }

        var NREQ = 2;
        var reqs = zeros(malloc(0x28 * NREQ), 0x28 * NREQ);
        var fdb = new Uint8Array(8);
        fdb[0] = st.rfd & 0xff; fdb[1] = (st.rfd >> 8) & 0xff;
        fdb[2] = (st.rfd >> 16) & 0xff; fdb[3] = (st.rfd >> 24) & 0xff;
        for (var ri = 0; ri < NREQ; ri++)
            root.write_buffer(reqs + BigInt(ri * 0x28 + 0x20), fdb);
        var idsArr = zeros(malloc(NREQ * 8), NREQ * 8);
        var sub = S(NR.AIO_SUBMIT_CMD, 0x1001n, reqs, BigInt(NREQ), 3n, idsArr, 0n);
        st.reqs = reqs; st.ids = idsArr;
        if ((sub & 0xFFFFFFFFn) === 0n) {
            st.id0 = B(root.read64(idsArr));
            out("SUBMIT", "n=2 ret=0x0  id0=" + hex(st.id0), "ok");
        } else {
            out("SUBMIT", "ret=" + hex(sub), "warn");
        }

        var initShapes = [
            ["(0)",       [0n, 0n, 0n, 0n, 0n, 0n]],
            ["(pid,0)",   [st.ourPid, 0n, 0n, 0n, 0n, 0n]],
            ["(0,1)",     [0n, 1n, 0n, 0n, 0n, 0n]],
            ["(pid,1)",   [st.ourPid, 1n, 0n, 0n, 0n, 0n]],
            ["(1)",       [1n, 0n, 0n, 0n, 0n, 0n]],
            ["(0,0,1)",   [0n, 0n, 1n, 0n, 0n, 0n]],
            ["(0x1000,1)",[0x1000n, 1n, 0n, 0n, 0n, 0n]],
        ];
        for (var i = 0; i < initShapes.length; i++) {
            var a = initShapes[i][1];
            var r = S(NR.AIO_INIT, a[0], a[1], a[2], a[3], a[4], a[5]);
            var ok = (r & 0xFFFFFFFFn) === 0n;
            out("AIO-INIT", initShapes[i][0] + " -> " + hex(r)
                + (ok ? "  ok" : ""), ok ? "ok" : "dim");
            if (!canary()) { st.wedge = true; return false; }
        }

        return true;
    }

    function phase2_baseline() {
        out("PHASE-2", "=== BASELINE ===", "sec");
        var r = call727(st.ourPid, 0n, 1n, 1n, outBuf, 0n);
        logCall("base [pid,0,1,1,out,0]", r);
    }

    function phase3_a2_sweep() {
        out("PHASE-3", "=== a2 SWEEP with a3=1, a4=1 ===", "sec");
        out("P3", "THE KEY TEST: does a2>0 change the write?", "dim");
        var a2s = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 16, 24, 32, 48, 64,
                   96, 128, 192, 256, 512, 1024, 2048];
        for (var i = 0; i < a2s.length; i++) {
            var r = call727(st.ourPid, B(a2s[i]), 1n, 1n, outBuf, 0n);
            if (r.wedge) return;
            logCall("a2=" + a2s[i], r);
        }
    }

    function phase4_a3_sweep() {
        out("PHASE-4", "=== a3 SWEEP with a2=1, a4=1 ===", "sec");
        var a3s = [
            ["0x1", 1n], ["0x2", 2n], ["0x3", 3n], ["0x4", 4n], ["0x5", 5n],
            ["0x8", 8n], ["0x10", 0x10n], ["0x20", 0x20n], ["0x40", 0x40n],
            ["0x7f", 0x7Fn], ["0x80", 0x80n],
            ["0x10000", 0x10000n], ["0x10001", 0x10001n],
            ["0x20000", 0x20000n], ["0x80000", 0x80000n],
            ["0x100000", 0x100000n], ["0x400000", 0x400000n],
            ["0x7f0000", 0x7F0000n], ["0x7fffff", 0x7FFFFFn],
            ["0x800000", 0x800000n], ["0x800001", 0x800001n],
            ["0xffffff", 0xFFFFFFn], ["0x1000000", 0x1000000n],
            ["0x7f000000", 0x7F000000n], ["0x80000000", 0x80000000n],
            ["id0_hi32", st.id0 >> 32n],
            ["id0_lo32", st.id0 & 0xFFFFFFFFn],
            ["id0>>16", st.id0 >> 16n],
            ["id0>>32", st.id0 >> 32n],
            ["id0&0xffff", st.id0 & 0xFFFFn],
            ["id0>>16&0x7f", (st.id0 >> 16n) & 0x7Fn],
            ["id0>>48", st.id0 >> 48n],
        ];
        for (var i = 0; i < a3s.length; i++) {
            var r = call727(st.ourPid, 1n, a3s[i][1], 1n, outBuf, 0n);
            if (r.wedge) return;
            logCall("a3=" + a3s[i][0], r);
        }
    }

    function phase5_prefill_differential() {
        out("PHASE-5", "=== PREFILL N + a2=N + a3=1 ===", "sec");
        out("P5", "prefill N requests, then call with a2=N -- does the write grow?", "dim");
        var Ns = [1, 2, 4, 8, 16, 32, 48, 64];
        var summary = [];
        for (var ni = 0; ni < Ns.length; ni++) {
            var N = Ns[ni];
            var pfds = zeros(malloc(8), 8);
            var pp = S(NR.PIPE2, pfds, 0n, 0n, 0n, 0n, 0n);
            if ((pp & 0xFFFFFFFFn) !== 0n) { out("P5", "pipe2 N=" + N + " failed", "warn"); continue; }
            var pv = readBytes(pfds, 8);
            var prfd = new Int32Array(pv.buffer, 0, 2)[0];
            var pwfd = new Int32Array(pv.buffer, 0, 2)[1];

            var reqs = zeros(malloc(0x28 * N), 0x28 * N);
            var fdb = new Uint8Array(8);
            fdb[0] = prfd & 0xff; fdb[1] = (prfd >> 8) & 0xff;
            fdb[2] = (prfd >> 16) & 0xff; fdb[3] = (prfd >> 24) & 0xff;
            for (var ri = 0; ri < N; ri++)
                root.write_buffer(reqs + BigInt(ri * 0x28 + 0x20), fdb);
            var idsArr = zeros(malloc(N * 8), N * 8);
            var sub = S(NR.AIO_SUBMIT_CMD, 0x1001n, reqs, BigInt(N), 3n, idsArr, 0n);
            if ((sub & 0xFFFFFFFFn) !== 0n) {
                out("P5", "N=" + N + " submit failed ret=" + hex(sub), "warn");
                S(NR.CLOSE, BigInt(prfd)); S(NR.CLOSE, BigInt(pwfd));
                continue;
            }

            var r1 = call727(st.ourPid, B(N), 1n, 1n, outBuf, 0n);
            if (r1.wedge) { st.wedge = true; break; }
            logCall("N=" + N + " pending a2=" + N, r1);

            if (N > 1) {
                var r1b = call727(st.ourPid, B(N - 1), 1n, 1n, outBuf, 0n);
                if (r1b.wedge) { st.wedge = true; break; }
                logCall("N=" + N + " pending a2=" + (N - 1), r1b);
            }
            var r1c = call727(st.ourPid, B(N + 1), 1n, 1n, outBuf, 0n);
            if (r1c.wedge) { st.wedge = true; break; }
            logCall("N=" + N + " pending a2=" + (N + 1), r1c);

            var wb = malloc(0x200);
            var wd = new Uint8Array(0x200);
            for (var w = 0; w < 0x200; w++) wd[w] = 0x41 + (w & 0x3f);
            root.write_buffer(wb, wd);
            S(NR.WRITE, BigInt(pwfd), wb, BigInt(N), 0n, 0n, 0n);
            for (var yi = 0; yi < 300; yi++) S(NR.SCHED_YIELD, 0n, 0n, 0n, 0n, 0n, 0n);
            if (!canary()) { st.wedge = true; out("WEDGE", "after P5 N=" + N, "err"); break; }

            var r2 = call727(st.ourPid, B(N), 1n, 1n, outBuf, 0n);
            if (r2.wedge) { st.wedge = true; break; }
            logCall("N=" + N + " completed a2=" + N, r2);

            summary.push("N=" + N + ":" + r1.diff.dump.slice(0, 24) + "/" + r2.diff.dump.slice(0, 24));

            var stc = zeros(malloc(0x20), 0x20);
            S(NR.AIO_MULTI_CANCEL, idsArr, BigInt(N), stc, 0n, 0n, 0n);
            S(NR.AIO_MULTI_DELETE, idsArr, BigInt(N), stc, 0n, 0n, 0n);
            S(NR.CLOSE, BigInt(prfd));
            S(NR.CLOSE, BigInt(pwfd));
        }
        out("P5-SUM", "pending/completed: " + (summary.join("   ") || "none"), "dim");
    }

    function phase6_a2_large() {
        out("PHASE-6", "=== a2 LARGE + boundary ===", "sec");
        var a2s = [64, 128, 256, 512, 1024, 2048, 4096, 8192, 0x4000, 0x8000,
                   0x10000, 0x20000, 0x40000, 0x80000, 0x100000, 0x228, 0x2280];
        for (var i = 0; i < a2s.length; i++) {
            var r = call727(st.ourPid, B(a2s[i]), 1n, 1n, outBuf, 0n);
            if (r.wedge) return;
            logCall("a2=" + a2s[i], r);
        }
    }

    function phase7_cleanup() {
        out("PHASE-7", "=== CLEANUP ===", "sec");
        try {
            var stc = zeros(malloc(0x20), 0x20);
            S(NR.AIO_MULTI_CANCEL, st.ids, 2n, stc, 0n, 0n, 0n);
            S(NR.AIO_MULTI_DELETE, st.ids, 2n, stc, 0n, 0n, 0n);
        } catch (e) { }
        try { S(NR.CLOSE, BigInt(st.rfd)); } catch (e) { }
        try { S(NR.CLOSE, BigInt(st.wfd)); } catch (e) { }
        out("P7", "cancel/delete/close issued", "dim");
    }

    function phase8_summary() {
        out("PHASE-8", "=== SUMMARY ===", "sec");
        if (st.wedge) {
            out("VERDICT", "WEDGE. Power-cycle.", "err");
            setChip("bad", "wedge");
            notify("727: WEDGE");
            return;
        }
        out("SUMMARY", "all phases complete. Look for CALL lines with 'changed' != 4 or dump != 00000000", "ok");
        setChip("ok", "complete");
        notify("727 v151 complete on " + FW);
    }

    function runAll() {
        try {
            setChip("run", "running");
            out("BEGIN", "fw=" + FW + " " + VERSION + " AUTO-RUN", "sec");
            if (!canary()) {
                out("VERDICT", "no executor", "err");
                setChip("bad", "no executor");
                return;
            }
            out("CANARY", "getpid ok", "ok");

            outBuf = malloc(OUTLEN);
            fillWith(outBuf, OUTLEN, 0xEE);

            if (!phase1_setup()) return;
            if (st.wedge) return phase8_summary();

            phase2_baseline();
            if (st.wedge) return phase8_summary();

            phase3_a2_sweep();
            if (st.wedge) return phase8_summary();

            phase4_a3_sweep();
            if (st.wedge) return phase8_summary();

            phase5_prefill_differential();
            if (st.wedge) return phase8_summary();

            phase6_a2_large();
            if (st.wedge) return phase8_summary();

            phase7_cleanup();
            phase8_summary();
        } catch (e) {
            out("FATAL", String((e && e.message) || e).slice(0, 200), "err");
            setChip("bad", "threw");
        }
    }

    try {
        var saved = localStorage.getItem(LOGKEY);
        if (saved) {
            var tail = saved.slice(-3000).split("\n").filter(function (l) { return l; });
            for (var pi = 0; pi < tail.length; pi++) {
                var sp = document.createElement("span");
                sp.className = "dim";
                sp.textContent = "    " + tail[pi] + "\n";
                elOut.appendChild(sp);
            }
        }
    } catch (e) { }

    setTimeout(runAll, 400);

})(typeof window !== "undefined" ? window : globalThis);

