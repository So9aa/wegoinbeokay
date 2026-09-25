/*
 * bagagwa_727probe.js -- v=150
 *
 * Loaded INSTEAD OF bagagwa_probe.js when the URL carries &probe727=1.
 * AUTO-RUNS on load. Prints a consolidated SUMMARY at the end.
 *
 * CONFIRMED ABI (prior hardware runs on 13.60):
 *   syscall 0x2D7 = get_aio_debug_request_info
 *   a1 = target pid    (ourPid works; 0, 1, 2 -> EPERM; other -> ESRCH)
 *   a2 = unused in observed range (0..32768 tested, no effect)
 *   a3 = req_id/slot   (0 -> EFAULT; nonzero -> passes, value ignored so far)
 *   a4 = flag          (must be >= 1; 0 -> EINVAL)
 *   a5 = out buffer    (NULL -> EFAULT; any valid ptr -> write happens)
 *   a6 = unprobed
 *   return 0x0 on success, 4 bytes written, value 0x00000000 so far
 *
 * WHAT THIS PROBE ANSWERS:
 *   P3: prefilling N pending/completed AIO requests -- does the value change?
 *   P4: a1 fine sweep 0..0x4000 -- where is the pid/slot boundary?
 *   P5: high-pid sweep + ourTid + ourPpid
 *   P6: a6 sweep -- never tested
 *   P7: a3 fine sweep around 0x80, 0x7F0000, 0x800000 -- the writeup's bound
 *   P8: a4 fine sweep around 1..0x10
 *   P9: exact write offset -- find first-changed byte, not just count
 *
 * READ-ONLY. No num>=2 anywhere. Canary getpid after every 727 call.
 */
(function (root) {
    "use strict";
    if (root.__B727_LOADED) return;
    root.__B727_LOADED = true;

    var FW = root.fw_str || "?";
    var VERSION = "v150";

    var NR = {
        GETPID: 0x014, GETPPID: 0x027, THR_SELF: 0x1B0,
        CLOSE: 0x006, WRITE: 0x004,
        SOCKETPAIR: 0x035, PIPE2: 0x2AF,
        AIO_SUBMIT_CMD: 0x29D,
        AIO_MULTI_CANCEL: 0x29A,
        AIO_MULTI_DELETE: 0x296,
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
    function hexU8(u8) {
        var s = "";
        for (var i = 0; i < u8.length; i++) s += u8[i].toString(16).padStart(2, "0");
        return s;
    }

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
    };

    /* ------------------------------------------------------------------ panel */
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
        "color:#c9c9d1;white-space:pre-wrap;word-break:break-all;-webkit-user-select:text;user-select:text;}",
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
    var elV = document.getElementById("b-v");
    var elFw = document.getElementById("b-fw");
    var elS = document.getElementById("b-s");
    elV.textContent = VERSION;
    elFw.textContent = "fw " + FW;

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
            a.download = "b727_" + FW + "_" + Date.now() + ".txt";
            document.body.appendChild(a); a.click();
            setTimeout(function () { try { a.remove(); } catch (e) { } }, 0);
        } catch (e) { }
    };

    /* ------------------------------------------------------------------ diff */
    var OUTLEN = 0x4000;
    var outBuf = null;

    function diffReport(got) {
        var firstOff = -1, changed = 0;
        for (var i = 0; i < got.length; i++) {
            if (got[i] !== 0xEE) { if (firstOff < 0) firstOff = i; changed++; }
        }
        if (firstOff < 0) return { changed: 0, off: -1, val8: "--", u32: 0 };
        var n = Math.min(8, got.length - firstOff);
        var s = "";
        for (var j = 0; j < n; j++) s += got[firstOff + j].toString(16).padStart(2, "0");
        var u32 = 0;
        for (var k = 0; k < Math.min(4, n); k++) u32 |= (got[firstOff + k] << (k * 8));
        return { changed: changed, off: firstOff, val8: s, u32: (u32 >>> 0) };
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
            line += "  changed=" + d.changed + "  off=" + hex(d.off) + "  val=" + d.val8;
        }
        var cls = "dim";
        if (d.changed > 0) cls = "ok";
        else if (r.ret !== 0x1n && r.ret !== 0x3n && r.ret !== 0x16n) cls = "ok";
        out("CALL", line, cls);
    }

    /* ------------------------------------------------------------------ phases */

    function phase01_setup() {
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
                out("VERDICT", "no live-request source: sp=" + hex(sp) + " pp=" + hex(pp), "err");
                setChip("bad", "no source");
                notify("727: no source");
                return false;
            }
        }

        /* Prefill one pair of AIO requests so 727 has something to look at. */
        var NREQ = 2;
        var reqs = zeros(malloc(0x28 * NREQ), 0x28 * NREQ);
        var fdb = new Uint8Array(8);
        fdb[0] = st.rfd & 0xff; fdb[1] = (st.rfd >> 8) & 0xff;
        fdb[2] = (st.rfd >> 16) & 0xff; fdb[3] = (st.rfd >> 24) & 0xff;
        for (var ri = 0; ri < NREQ; ri++)
            root.write_buffer(reqs + BigInt(ri * 0x28 + 0x20), fdb);
        var idsArr = zeros(malloc(NREQ * 8), NREQ * 8);
        var sub = S(NR.AIO_SUBMIT_CMD, 0x1001n, reqs, BigInt(NREQ), 3n, idsArr, 0n);
        out("SUBMIT", "n=" + NREQ + " ret=" + hex(sub)
            + ((sub & 0xFFFFFFFFn) === 0n ? " (ok)" : " (FAIL)"),
            (sub & 0xFFFFFFFFn) === 0n ? "ok" : "err");
        st.reqs = reqs;
        st.ids = idsArr;

        if (!canary()) { setChip("bad", "wedge"); return false; }
        return true;
    }

    function phase02_baseline() {
        out("PHASE-2", "=== BASELINE ===", "sec");
        var r = call727(st.ourPid, 0n, 1n, 1n, outBuf, 0n);
        logCall("base [pid,0,1,1,out,0]", r);
        if (r.wedge) return;
        if (r.diff.changed === 0) {
            out("BASE", "baseline did not write -- something changed upstream", "warn");
        } else {
            out("BASE", "confirmed write: changed=" + r.diff.changed
                + " off=" + hex(r.diff.off) + " val=" + r.diff.val8, "ok");
        }
    }

    function phase03_prefill() {
        out("PHASE-3", "=== PREFILL DIFFERENTIAL ===", "sec");
        out("P3", "does the leaked value change with N pending/completed requests?", "dim");

        var Ns = [1, 2, 4, 8, 16, 32];
        var results = [];

        for (var ni = 0; ni < Ns.length; ni++) {
            var N = Ns[ni];
            var pfds = zeros(malloc(8), 8);
            var pp = S(NR.PIPE2, pfds, 0n, 0n, 0n, 0n, 0n);
            if ((pp & 0xFFFFFFFFn) !== 0n) { out("P3", "pipe2 N=" + N + " failed", "warn"); continue; }
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
                out("P3", "N=" + N + " submit failed ret=" + hex(sub), "warn");
                S(NR.CLOSE, BigInt(prfd)); S(NR.CLOSE, BigInt(pwfd));
                continue;
            }

            var r1 = call727(st.ourPid, 0n, 1n, 1n, outBuf, 0n);
            logCall("N=" + N + " pending", r1);
            if (r1.wedge) { st.wedge = true; break; }

            var wb = malloc(0x80);
            var wd = new Uint8Array(0x80);
            for (var w = 0; w < 0x80; w++) wd[w] = 0x41 + (w & 0x3f);
            root.write_buffer(wb, wd);
            S(NR.WRITE, BigInt(pwfd), wb, BigInt(N), 0n, 0n, 0n);
            for (var yi = 0; yi < 200; yi++) S(NR.SCHED_YIELD, 0n, 0n, 0n, 0n, 0n, 0n);
            if (!canary()) { st.wedge = true; out("WEDGE", "after P3 N=" + N, "err"); break; }

            var r2 = call727(st.ourPid, 0n, 1n, 1n, outBuf, 0n);
            logCall("N=" + N + " completed", r2);
            if (r2.wedge) { st.wedge = true; break; }

            results.push({ N: N, pending: r1.diff, completed: r2.diff });

            var stc = zeros(malloc(0x20), 0x20);
            S(NR.AIO_MULTI_CANCEL, idsArr, BigInt(N), stc, 0n, 0n, 0n);
            S(NR.AIO_MULTI_DELETE, idsArr, BigInt(N), stc, 0n, 0n, 0n);
            S(NR.CLOSE, BigInt(prfd));
            S(NR.CLOSE, BigInt(pwfd));
        }

        var vals = results.map(function (r) { return r.pending.val8 + "/" + r.completed.val8; });
        out("P3-SUM", "values across N: " + (vals.join("  ") || "none"), "dim");
    }

    function phase04_pid_fine() {
        out("PHASE-4", "=== a1 FINE SWEEP (0x0 .. 0x4000) ===", "sec");
        var pids = [];
        for (var i = 0; i <= 16; i++) pids.push(i);
        [0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0xa0, 0xc0, 0xe0,
         0x100, 0x200, 0x300, 0x400, 0x800, 0x1000, 0x2000, 0x4000].forEach(function (p) {
            pids.push(p);
        });
        for (var pi = 0; pi < pids.length; pi++) {
            var r = call727(BigInt(pids[pi]), 0n, 1n, 1n, outBuf, 0n);
            if (r.wedge) return;
            if (r.diff.changed > 0 || (r.ret !== 0x1n && r.ret !== 0x3n && r.ret !== 0x16n)) {
                logCall("a1=" + hex(pids[pi]), r);
            } else if (pids[pi] <= 4) {
                logCall("a1=" + hex(pids[pi]), r);
            }
        }
        out("P4", "fine sweep done (only interesting rows shown above)", "dim");
    }

    function phase05_pid_special() {
        out("PHASE-5", "=== a1 SPECIAL VALUES ===", "sec");
        var specials = [
            ["ourPid", st.ourPid],
            ["ourPid-2", st.ourPid - 2n],
            ["ourPid-1", st.ourPid - 1n],
            ["ourPid+1", st.ourPid + 1n],
            ["ourPid+2", st.ourPid + 2n],
            ["ourPpid", st.ourPpid],
            ["ourTid", st.ourTid],
            ["ourTid>>32", st.ourTid >> 32n],
            ["ourTid&0xffff", st.ourTid & 0xFFFFn],
            ["0xffffffffffffffff", 0xFFFFFFFFFFFFFFFFn],
            ["-1", 0xFFFFFFFFFFFFFFFFn],
            ["0x7fffffff", 0x7FFFFFFFn],
            ["0x80000000", 0x80000000n],
            ["0x100000000", 0x100000000n],
        ];
        for (var i = 0; i < specials.length; i++) {
            var r = call727(specials[i][1], 0n, 1n, 1n, outBuf, 0n);
            if (r.wedge) return;
            logCall("a1=" + specials[i][0], r);
        }
    }

    function phase06_a6() {
        out("PHASE-6", "=== a6 SWEEP (never tested) ===", "sec");
        var a6s = [
            ["0", 0n], ["1", 1n], ["2", 2n], ["3", 3n], ["4", 4n],
            ["0x10", 0x10n], ["0x40", 0x40n], ["0x80", 0x80n],
            ["0x100", 0x100n], ["0x228", 0x228n], ["0x1000", 0x1000n],
            ["0x8000000000000000", 0x8000000000000000n],
            ["0xffffffffffffffff", 0xFFFFFFFFFFFFFFFFn],
            ["idsPtr", st.ids],
            ["reqsPtr", st.reqs],
            ["outBuf", outBuf],
        ];
        for (var i = 0; i < a6s.length; i++) {
            var r = call727(st.ourPid, 0n, 1n, 1n, outBuf, a6s[i][1]);
            if (r.wedge) return;
            logCall("a6=" + a6s[i][0], r);
        }
    }

    function phase07_a3_fine() {
        out("PHASE-7", "=== a3 FINE SWEEP around the writeup's >>16 < 0x80 check ===", "sec");
        var a3s = [
            ["0x1", 1n], ["0x7f", 0x7Fn], ["0x80", 0x80n],
            ["0x8000", 0x8000n], ["0x8001", 0x8001n],
            ["0x7fff", 0x7FFFn], ["0xffff", 0xFFFFn],
            ["0x10000", 0x10000n], ["0x7f0000", 0x7F0000n],
            ["0x800000", 0x800000n], ["0x800001", 0x800001n],
            ["0x7fffff", 0x7FFFFFn], ["0xffffff", 0xFFFFFFn],
            ["0x1000000", 0x1000000n], ["0x7f000000", 0x7F000000n],
            ["0x80000000", 0x80000000n],
            ["0x7f0000<<16", 0x7F0000n << 16n],
            ["0x80<<16", 0x80n << 16n],
            ["0x7f<<16", 0x7Fn << 16n],
        ];
        for (var i = 0; i < a3s.length; i++) {
            var r = call727(st.ourPid, 0n, a3s[i][1], 1n, outBuf, 0n);
            if (r.wedge) return;
            logCall("a3=" + a3s[i][0], r);
        }
    }

    function phase08_a4() {
        out("PHASE-8", "=== a4 FINE SWEEP (flag boundary) ===", "sec");
        var a4s = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 0x10, 0x20, 0x40, 0x80,
                   0x100, 0x200, 0x400, 0x800, 0x1000, 0x10000, 0x1000000,
                   0x100000000, 0x7fffffff, 0x80000000, 0xffffffff,
                   0xffffffffffffffff];
        for (var i = 0; i < a4s.length; i++) {
            var r = call727(st.ourPid, 0n, 1n, B(a4s[i]), outBuf, 0n);
            if (r.wedge) return;
            logCall("a4=" + hex(a4s[i]), r);
        }
    }

    function phase09_offset() {
        out("PHASE-9", "=== a5 OFFSET -- where does the write land? ===", "sec");
        var offs = [0, 4, 8, 0x10, 0x20, 0x28, 0x40, 0x80, 0x100, 0x200];
        for (var i = 0; i < offs.length; i++) {
            var p = outBuf + BigInt(offs[i]);
            var r = call727(st.ourPid, 0n, 1n, 1n, p, 0n);
            if (r.wedge) return;
            logCall("a5=out+" + hex(offs[i]), r);
        }
    }

    function phase10_cleanup() {
        out("PHASE-10", "=== CLEANUP ===", "sec");
        try {
            var stc = zeros(malloc(0x20), 0x20);
            S(NR.AIO_MULTI_CANCEL, st.ids, 2n, stc, 0n, 0n, 0n);
            S(NR.AIO_MULTI_DELETE, st.ids, 2n, stc, 0n, 0n, 0n);
        } catch (e) { }
        try { S(NR.CLOSE, BigInt(st.rfd)); } catch (e) { }
        try { S(NR.CLOSE, BigInt(st.wfd)); } catch (e) { }
        out("P10", "cancel/delete/close issued", "dim");
    }

    function phase11_summary() {
        out("PHASE-11", "=== SUMMARY ===", "sec");
        if (st.wedge) {
            out("VERDICT", "WEDGE -- the kernel stopped answering. Power-cycle.", "err");
            setChip("bad", "wedge");
            notify("727: WEDGE");
            return;
        }
        out("SUMMARY", "all phases completed without wedge. See the WRITES lines above.", "ok");
        setChip("ok", "complete");
        notify("727 probe complete on " + FW);
    }

    /* ------------------------------------------------------------------ run */

    function runAll() {
        try {
            setChip("run", "running");
            out("BEGIN", "fw=" + FW + " " + VERSION + " AUTO-RUN", "sec");
            if (!canary()) {
                out("VERDICT", "no executor -- getpid did not answer", "err");
                setChip("bad", "no executor");
                notify("727: no executor");
                return;
            }
            out("CANARY", "getpid ok", "ok");

            outBuf = malloc(OUTLEN);
            fillWith(outBuf, OUTLEN, 0xEE);

            if (!phase01_setup()) return;
            if (st.wedge) return phase11_summary();

            phase02_baseline();
            if (st.wedge) return phase11_summary();

            phase03_prefill();
            if (st.wedge) return phase11_summary();

            phase04_pid_fine();
            if (st.wedge) return phase11_summary();

            phase05_pid_special();
            if (st.wedge) return phase11_summary();

            phase06_a6();
            if (st.wedge) return phase11_summary();

            phase07_a3_fine();
            if (st.wedge) return phase11_summary();

            phase08_a4();
            if (st.wedge) return phase11_summary();

            phase09_offset();
            if (st.wedge) return phase11_summary();

            phase10_cleanup();
            phase11_summary();
        } catch (e) {
            out("FATAL", String((e && e.message) || e).slice(0, 200), "err");
            setChip("bad", "threw");
        }
    }

    /* restore saved log tail */
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

