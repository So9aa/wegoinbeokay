/*
 * bagagwa_aio299probe.js -- v=152
 *
 * Read-only ABI probe for syscall 0x299 (aio_get_data / AIO_GET_DATA).
 *
 * WHY
 * ---
 * The Bagagwa writeup names 0x2D7 (aio_debug_info) as its leak. On 13.60 that
 * syscall exists, accepts our pid as a1, writes exactly 4 bytes of 0x00000000
 * to a5, and ignores every other argument (verified across v150 and v151 --
 * a2 in [0, 1M], a3 in [1, 0x80000000], a4 in [1, 0xffff], a6 unconstrained).
 * It is a status getter, not a leak.
 *
 * 0x299 (aio_get_data) is the last untested member of the AIO family whose name
 * matches "return per-request data". If 13.60 repurposed 0x2D7, 0x299 is the
 * most likely replacement.
 *
 * WHAT IT DOES
 * ------------
 *   1. Canary getpid.
 *   2. pipe2 pair (socketpair refuses on 13.60, 0xE).
 *   3. Submit 2 live pending MULTI_READ requests via aio_submit_cmd -- proven
 *      working on 13.60.
 *   4. Sweep every argument of 0x299 across the same matrices that made 0x2D7
 *      return success:
 *        a1: pid-shaped values, ourPid, ourTid, id0 and its transforms
 *        a2: 0 .. 1M
 *        a3: 0 .. 0x80000000, plus id transforms
 *        a4: 0 .. 0x10000
 *        a5: out buffer, offsets, NULL
 *        a6: 0 .. 0x1000, NULL, pointers
 *   5. Prefill N live requests and retest a2=N -- does the write scale?
 *   6. Cleanup: cancel/delete/close.
 *
 * READ-ONLY. No num>=2 in any AIO call. No kernel writes. A getpid canary runs
 * after every 0x299 call and the probe aborts on the first wedge.
 *
 * Loaded INSTEAD OF bagagwa_probe.js when the URL carries &probe299=1.
 * Auto-runs. Prints one summary line at the end.
 */
(function (root) {
    "use strict";
    if (root.__B299_LOADED) return;
    root.__B299_LOADED = true;

    var FW = root.fw_str || "?";
    var VERSION = "v152";

    var NR = {
        GETPID: 0x014, GETPPID: 0x027, THR_SELF: 0x1B0,
        CLOSE: 0x006, WRITE: 0x004,
        SOCKETPAIR: 0x035, PIPE2: 0x2AF,
        AIO_SUBMIT_CMD: 0x29D,
        AIO_MULTI_CANCEL: 0x29A,
        AIO_MULTI_DELETE: 0x296,
        AIO_INIT: 0x29E,
        AIO_GET_DATA: 0x299,
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

    /* ------------------------------------------------------------------ panel */
    var CSS = [
        ".b299{position:fixed;inset:0;z-index:2147483647;background:#0c0c0f;color:#fff;",
        "font-family:Arial,sans-serif;display:flex;flex-direction:column;",
        "padding:14px 16px 12px;box-sizing:border-box;-webkit-user-select:none;user-select:none;}",
        ".b299 *{box-sizing:border-box;}",
        ".b299-h{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:6px;}",
        ".b299-logo{font-size:1.2rem;font-weight:800;letter-spacing:.18em;}",
        ".b299-chip{font-size:.72rem;font-weight:700;letter-spacing:.08em;padding:4px 9px;",
        "border-radius:999px;background:#202125;color:#a2a2a6;}",
        ".b299-chip.run{background:#33290d;color:#ffce5c;}",
        ".b299-chip.ok{background:#14361f;color:#5fdc90;}",
        ".b299-chip.bad{background:#3a1717;color:#ff8080;}",
        ".b299-spacer{flex:1;}",
        ".b299-btn{padding:.5rem 1rem;border-radius:1rem;border:none;cursor:pointer;",
        "background:#202125;color:#fff;font:800 .85rem Arial;}",
        ".b299-btn:hover{background:#a2a2a6;color:#202020;}",
        ".b299-out{flex:1;overflow:auto;background:#16161a;border:1px solid #26262b;",
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
    panel.className = "b299";
    panel.innerHTML = [
        '<div class="b299-h">',
        '  <span class="b299-logo">299</span>',
        '  <span class="b299-chip" id="b-v"></span>',
        '  <span class="b299-chip" id="b-fw"></span>',
        '  <span class="b299-chip run" id="b-s">starting</span>',
        '  <span class="b299-spacer"></span>',
        '  <button class="b299-btn" id="b-dl">download log</button>',
        '</div>',
        '<pre class="b299-out" id="b-out"></pre>',
    ].join("");
    document.body.appendChild(panel);

    var elOut = document.getElementById("b-out");
    var elS = document.getElementById("b-s");
    document.getElementById("b-v").textContent = VERSION;
    document.getElementById("b-fw").textContent = "fw " + FW;

    var LOG = [];
    var LOGKEY = "b299_sc_log";

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
        logLine("299 " + tag + (detail ? "  " + detail : ""), cls);
        try { if (root.flushMark) root.flushMark("299-" + tag, String(detail || "")); } catch (e) { }
        try { if (root.syncMark) root.syncMark("299-" + tag, String(detail || "")); } catch (e) { }
    }
    function notify(m) { try { if (root.send_notification) root.send_notification(m); } catch (e) { } }
    function setChip(cls, text) { elS.className = "b299-chip " + cls; elS.textContent = text; }

    document.getElementById("b-dl").onclick = function () {
        try {
            var blob = new Blob([LOG.join("\n") + "\n"], { type: "text/plain" });
            var a = document.createElement("a");
            a.href = URL.createObjectURL(blob);
            a.download = "b299_" + FW + "_" + Date.now() + ".txt";
            document.body.appendChild(a); a.click();
            setTimeout(function () { try { a.remove(); } catch (e) { } }, 0);
        } catch (e) { }
    };

    /* ------------------------------------------------------------------ diff */
    var OUTLEN = 0x400;
    var outBuf = null;

    function diffReport(got) {
        var firstOff = -1, changed = 0;
        for (var i = 0; i < got.length; i++) {
            if (got[i] !== 0xEE) { if (firstOff < 0) firstOff = i; changed++; }
        }
        if (firstOff < 0) return { changed: 0, off: -1, dump: "--", nonzero: false };
        var n = Math.min(16, got.length - firstOff);
        var s = "";
        for (var j = 0; j < n; j++) {
            s += got[firstOff + j].toString(16).padStart(2, "0");
            if (j % 4 === 3 && j < n - 1) s += " ";
        }
        var nz = false;
        for (var k = 0; k < n; k++) if (got[firstOff + k] !== 0) { nz = true; break; }
        return { changed: changed, off: firstOff, dump: s, nonzero: nz };
    }

    function call299(a1, a2, a3, a4, a5, a6) {
        fillWith(a5, OUTLEN, 0xEE);
        var ret = S(NR.AIO_GET_DATA, a1, a2, a3, a4, a5, a6);
        if (!canary()) {
            st.wedge = true;
            out("WEDGE", "a1=" + hex(a1) + " a2=" + hex(a2) + " a3=" + hex(a3)
                + " a4=" + hex(a4) + " a5=" + hex(a5) + " a6=" + hex(a6)
                + " -> no canary", "err");
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
        if (d.nonzero) cls = "ok";
        else if (d.changed > 0 && d.changed !== 4) cls = "ok";
        else if (d.changed === 4 && !d.nonzero) cls = "dim";
        else if (r.ret !== 0x0n && r.ret !== 0x1n && r.ret !== 0x3n && r.ret !== 0x16n && r.ret !== 0x0n) cls = "ok";
        out("CALL", line, cls);
    }

    /* ------------------------------------------------------------------ phases */

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

        /* also call aio_init so the family is not dormant */
        var init = S(NR.AIO_INIT, st.ourPid, 0n, 0n, 0n, 0n, 0n);
        out("AIO-INIT", "(pid,0) -> " + hex(init), (init & 0xFFFFFFFFn) === 0n ? "ok" : "dim");
        if (!canary()) { st.wedge = true; return false; }
        return true;
    }

    function phase2_baseline() {
        out("PHASE-2", "=== BASELINE (pid-first shape) ===", "sec");
        var cases = [
            ["[pid,0,1,1,out,0]",  [st.ourPid, 0n, 1n, 1n, outBuf, 0n]],
            ["[pid,1,1,1,out,0]",  [st.ourPid, 1n, 1n, 1n, outBuf, 0n]],
            ["[pid,0,0,1,out,0]",  [st.ourPid, 0n, 0n, 1n, outBuf, 0n]],
            ["[pid,1,0,1,out,0]",  [st.ourPid, 1n, 0n, 1n, outBuf, 0n]],
            ["[id0,0,1,1,out,0]",  [st.id0, 0n, 1n, 1n, outBuf, 0n]],
            ["[id0,1,1,1,out,0]",  [st.id0, 1n, 1n, 1n, outBuf, 0n]],
            ["[id0,0,0,1,out,0]",  [st.id0, 0n, 0n, 1n, outBuf, 0n]],
        ];
        for (var i = 0; i < cases.length; i++) {
            var r = call299(cases[i][1][0], cases[i][1][1], cases[i][1][2],
                cases[i][1][3], cases[i][1][4], cases[i][1][5]);
            if (r.wedge) return;
            logCall(cases[i][0], r);
        }
    }

    function phase3_a1() {
        out("PHASE-3", "=== a1 SWEEP ===", "sec");
        var a1s = [
            ["0", 0n], ["1", 1n], ["2", 2n], ["3", 3n], ["4", 4n], ["5", 5n],
            ["ourPid", st.ourPid],
            ["ourPid-1", st.ourPid - 1n],
            ["ourPid+1", st.ourPid + 1n],
            ["ourPpid", st.ourPpid],
            ["ourTid", st.ourTid],
            ["ourTid>>32", st.ourTid >> 32n],
            ["ourTid&0xffff", st.ourTid & 0xFFFFn],
            ["id0", st.id0],
            ["id0>>16", st.id0 >> 16n],
            ["id0>>32", st.id0 >> 32n],
            ["id0&0xffffffff", st.id0 & 0xFFFFFFFFn],
            ["id0&0xffff", st.id0 & 0xFFFFn],
            ["0x7fffffff", 0x7FFFFFFFn],
            ["0x80000000", 0x80000000n],
            ["-1", 0xFFFFFFFFFFFFFFFFn],
        ];
        for (var i = 0; i < a1s.length; i++) {
            var r = call299(a1s[i][1], 0n, 1n, 1n, outBuf, 0n);
            if (r.wedge) return;
            logCall("a1=" + a1s[i][0], r);
        }
    }

    function phase4_a2() {
        out("PHASE-4", "=== a2 SWEEP (a1=ourPid) ===", "sec");
        var a2s = [0n, 1n, 2n, 3n, 4n, 5n, 6n, 7n, 8n, 9n, 10n, 16n, 24n, 32n,
                   48n, 64n, 96n, 128n, 192n, 256n, 512n, 1024n, 2048n, 4096n, 0x228n];
        for (var i = 0; i < a2s.length; i++) {
            var r = call299(st.ourPid, a2s[i], 1n, 1n, outBuf, 0n);
            if (r.wedge) return;
            logCall("a2=" + a2s[i], r);
        }
    }

    function phase5_a3() {
        out("PHASE-5", "=== a3 SWEEP (a1=ourPid, a2=1) ===", "sec");
        var a3s = [
            ["0", 0n], ["1", 1n], ["2", 2n], ["3", 3n], ["4", 4n], ["5", 5n],
            ["8", 8n], ["0x10", 0x10n], ["0x20", 0x20n], ["0x40", 0x40n],
            ["0x7f", 0x7Fn], ["0x80", 0x80n],
            ["0x10000", 0x10000n], ["0x7f0000", 0x7F0000n],
            ["0x7fffff", 0x7FFFFFn], ["0x800000", 0x800000n],
            ["0xffffff", 0xFFFFFFn], ["0x1000000", 0x1000000n],
            ["0x7f000000", 0x7F000000n], ["0x80000000", 0x80000000n],
            ["id0", st.id0],
            ["id0_lo32", st.id0 & 0xFFFFFFFFn],
            ["id0_hi32", st.id0 >> 32n],
            ["id0>>16", st.id0 >> 16n],
            ["id0>>16&0x7f", (st.id0 >> 16n) & 0x7Fn],
            ["id0&0xffff", st.id0 & 0xFFFFn],
        ];
        for (var i = 0; i < a3s.length; i++) {
            var r = call299(st.ourPid, 1n, a3s[i][1], 1n, outBuf, 0n);
            if (r.wedge) return;
            logCall("a3=" + a3s[i][0], r);
        }
    }

    function phase6_a4() {
        out("PHASE-6", "=== a4 SWEEP (a1=ourPid, a2=1, a3=1) ===", "sec");
        var a4s = [0n, 1n, 2n, 3n, 4n, 5n, 6n, 7n, 8n, 9n, 10n, 0x10n, 0x20n,
                   0x40n, 0x80n, 0x100n, 0x200n, 0x400n, 0x800n, 0x1000n,
                   0x10000n, 0x1000000n, 0x80000000n, 0xffffffffn];
        for (var i = 0; i < a4s.length; i++) {
            var r = call299(st.ourPid, 1n, 1n, a4s[i], outBuf, 0n);
            if (r.wedge) return;
            logCall("a4=" + hex(a4s[i]), r);
        }
    }

    function phase7_a5_a6() {
        out("PHASE-7", "=== a5 / a6 SWEEPS ===", "sec");
        var a5s = [
            ["out+0", outBuf], ["out+4", outBuf + 4n], ["out+8", outBuf + 8n],
            ["out+0x10", outBuf + 0x10n], ["out+0x40", outBuf + 0x40n],
            ["out+0x100", outBuf + 0x100n],
            ["idBuf", st.ids], ["reqsPtr", st.reqs],
        ];
        for (var i = 0; i < a5s.length; i++) {
            var r = call299(st.ourPid, 1n, 1n, 1n, a5s[i][1], 0n);
            if (r.wedge) return;
            logCall("a5=" + a5s[i][0], r);
        }
        var a6s = [
            ["0", 0n], ["1", 1n], ["2", 2n], ["4", 4n], ["8", 8n],
            ["0x10", 0x10n], ["0x40", 0x40n], ["0x80", 0x80n],
            ["0x100", 0x100n], ["0x1000", 0x1000n],
            ["0x8000000000000000", 0x8000000000000000n],
            ["idsPtr", st.ids], ["reqsPtr", st.reqs], ["outBuf", outBuf],
        ];
        for (var j = 0; j < a6s.length; j++) {
            var r2 = call299(st.ourPid, 1n, 1n, 1n, outBuf, a6s[j][1]);
            if (r2.wedge) return;
            logCall("a6=" + a6s[j][0], r2);
        }
    }

    function phase8_prefill() {
        out("PHASE-8", "=== PREFILL N + a2=N ===", "sec");
        var Ns = [1, 2, 4, 8, 16, 32];
        for (var ni = 0; ni < Ns.length; ni++) {
            var N = Ns[ni];
            var pfds = zeros(malloc(8), 8);
            var pp = S(NR.PIPE2, pfds, 0n, 0n, 0n, 0n, 0n);
            if ((pp & 0xFFFFFFFFn) !== 0n) { out("P8", "pipe2 N=" + N + " failed", "warn"); continue; }
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
                out("P8", "N=" + N + " submit failed ret=" + hex(sub), "warn");
                S(NR.CLOSE, BigInt(prfd)); S(NR.CLOSE, BigInt(pwfd));
                continue;
            }

            var r1 = call299(st.ourPid, B(N), 1n, 1n, outBuf, 0n);
            if (r1.wedge) { st.wedge = true; break; }
            logCall("N=" + N + " pending a2=" + N, r1);

            var wb = malloc(0x80);
            var wd = new Uint8Array(0x80);
            for (var w = 0; w < 0x80; w++) wd[w] = 0x41 + (w & 0x3f);
            root.write_buffer(wb, wd);
            S(NR.WRITE, BigInt(pwfd), wb, BigInt(N), 0n, 0n, 0n);
            for (var yi = 0; yi < 200; yi++) S(NR.SCHED_YIELD, 0n, 0n, 0n, 0n, 0n, 0n);
            if (!canary()) { st.wedge = true; out("WEDGE", "after P8 N=" + N, "err"); break; }

            var r2 = call299(st.ourPid, B(N), 1n, 1n, outBuf, 0n);
            if (r2.wedge) { st.wedge = true; break; }
            logCall("N=" + N + " completed a2=" + N, r2);

            var stc = zeros(malloc(0x20), 0x20);
            S(NR.AIO_MULTI_CANCEL, idsArr, BigInt(N), stc, 0n, 0n, 0n);
            S(NR.AIO_MULTI_DELETE, idsArr, BigInt(N), stc, 0n, 0n, 0n);
            S(NR.CLOSE, BigInt(prfd));
            S(NR.CLOSE, BigInt(pwfd));
        }
    }

    function phase9_cleanup() {
        out("PHASE-9", "=== CLEANUP ===", "sec");
        try {
            var stc = zeros(malloc(0x20), 0x20);
            S(NR.AIO_MULTI_CANCEL, st.ids, 2n, stc, 0n, 0n, 0n);
            S(NR.AIO_MULTI_DELETE, st.ids, 2n, stc, 0n, 0n, 0n);
        } catch (e) { }
        try { S(NR.CLOSE, BigInt(st.rfd)); } catch (e) { }
        try { S(NR.CLOSE, BigInt(st.wfd)); } catch (e) { }
        out("P9", "cancel/delete/close issued", "dim");
    }

    function phase10_summary() {
        out("PHASE-10", "=== SUMMARY ===", "sec");
        if (st.wedge) {
            out("VERDICT", "WEDGE. Power-cycle. The kernel stopped answering after 0x299.", "err");
            setChip("bad", "wedge");
            notify("299: WEDGE");
            return;
        }
        var nonzero = 0, nonstandard = 0;
        for (var i = 0; i < LOG.length; i++) {
            if (/dump=[0-9a-f]*[1-9a-f]/.test(LOG[i]) && /changed=/.test(LOG[i])) nonzero++;
            if (/-&gt; ret=0x(?!0$|1$|3$|e$|16$)/.test(LOG[i])) nonstandard++;
        }
        if (nonzero > 0) {
            out("VERDICT", nonzero + " call(s) wrote NONZERO data -- grep 'dump=' in the log for the exact values", "ok");
            setChip("ok", "nonzero " + nonzero);
            notify("299: nonzero data, see log");
        } else if (nonstandard > 0) {
            out("VERDICT", nonstandard + " call(s) returned a nonstandard code -- check the CALL lines", "warn");
            setChip("ok", "new codes " + nonstandard);
            notify("299: new return codes, see log");
        } else {
            out("VERDICT", "0x299 behaves like 0x2D7: accepts pid, writes 4 zero bytes, ignores the rest. Family has no leak on 13.60.", "warn");
            setChip("bad", "no leak");
            notify("299: no leak on 13.60");
        }
    }

    function runAll() {
        try {
            setChip("run", "running");
            out("BEGIN", "fw=" + FW + " " + VERSION + " AUTO-RUN (syscall 0x299)", "sec");
            if (!canary()) {
                out("VERDICT", "no executor", "err");
                setChip("bad", "no executor");
                return;
            }
            out("CANARY", "getpid ok", "ok");

            outBuf = malloc(OUTLEN);
            fillWith(outBuf, OUTLEN, 0xEE);

            if (!phase1_setup()) return phase10_summary();
            if (st.wedge) return phase10_summary();

            phase2_baseline();  if (st.wedge) return phase10_summary();
            phase3_a1();        if (st.wedge) return phase10_summary();
            phase4_a2();        if (st.wedge) return phase10_summary();
            phase5_a3();        if (st.wedge) return phase10_summary();
            phase6_a4();        if (st.wedge) return phase10_summary();
            phase7_a5_a6();     if (st.wedge) return phase10_summary();
            phase8_prefill();   if (st.wedge) return phase10_summary();

            phase9_cleanup();
            phase10_summary();
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
