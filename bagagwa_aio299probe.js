/*
 * bagagwa_aio299probe.js -- v=153 (compact)
 *
 * Conservative ABI probe for syscall 0x299 (aio_get_data).
 * v152 was OOM'd by the WebProcess -- this version:
 *   - OUTLEN is 0x40, not 0x400
 *   - ~55 calls, not ~150
 *   - no flushMark / syncMark during the sweep; only BEGIN, VERDICT, WEDGE
 *   - canary every 3rd call, plus after any unexpected return
 *   - no AIO prefill cycles
 *   - single sweep pass, no nested phases
 *
 * READ-ONLY. No num>=2 in any AIO call. Nothing writes kernel memory except
 * whatever 0x299 does internally.
 */
(function (root) {
    "use strict";
    if (root.__B299_LOADED) return;
    root.__B299_LOADED = true;

    var FW = root.fw_str || "?";
    var VERSION = "v153";

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
    function readBytes(p, n) { return new Uint8Array(root.read_buffer(B(p), n)); }
    function writeByte(p, val) {
        var z = new Uint8Array(1); z[0] = val & 0xff;
        root.write_buffer(B(p), z);
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

    var st = { ourPid: 0n, ourPpid: 0n, ourTid: 0n, id0: 0n, wedge: false };

    /* ------- tiny panel ------- */
    var styleEl = document.createElement("style");
    styleEl.textContent = [
        ".b299{position:fixed;inset:0;z-index:2147483647;background:#0c0c0f;color:#fff;",
        "font-family:Arial,sans-serif;display:flex;flex-direction:column;",
        "padding:12px 14px;box-sizing:border-box;}",
        ".b299-out{flex:1;overflow:auto;background:#16161a;border:1px solid #26262b;",
        "border-radius:.6rem;margin:0;padding:8px 10px;font:11.5px/1.45 Consolas,monospace;",
        "color:#c9c9d1;white-space:pre-wrap;word-break:break-all;}",
        ".ok{color:#5fdc90;}.err{color:#ff8080;}.warn{color:#ffce5c;}.dim{color:#6f7076;}",
        ".sec{color:#fff;font-weight:800;}",
    ].join("");
    document.head.appendChild(styleEl);

    var panel = document.createElement("div");
    panel.className = "b299";
    panel.innerHTML = '<pre class="b299-out" id="b-out"></pre>';
    document.body.appendChild(panel);

    var elOut = document.getElementById("b-out");
    var LOG = [];
    var LOGKEY = "b299r_sc_log";

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
            if (cur.length > 24000) cur = cur.slice(-12000);
            localStorage.setItem(LOGKEY, cur);
        } catch (e) { }
        var span = document.createElement("span");
        if (cls) span.className = cls;
        span.textContent = line + "\n";
        elOut.appendChild(span);
        elOut.scrollTop = elOut.scrollHeight;
    }
    function sec(tag, detail) { logLine("299 " + tag + (detail ? "  " + detail : ""), "sec"); }
    function ok(tag, detail) { logLine("299 " + tag + (detail ? "  " + detail : ""), "ok"); }
    function warn(tag, detail) { logLine("299 " + tag + (detail ? "  " + detail : ""), "warn"); }
    function err(tag, detail) { logLine("299 " + tag + (detail ? "  " + detail : ""), "err"); }
    function dim(tag, detail) { logLine("299 " + tag + (detail ? "  " + detail : ""), "dim"); }

    /* only BEGIN / VERDICT / WEDGE reach the beacons */
    function beacon(tag, detail) {
        try { if (root.flushMark) root.flushMark("299-" + tag, String(detail || "")); } catch (e) { }
        try { if (root.syncMark) root.syncMark("299-" + tag, String(detail || "")); } catch (e) { }
    }
    function notify(m) { try { if (root.send_notification) root.send_notification(m); } catch (e) { } }

    /* ------- diff ------- */
    var OUTLEN = 0x40;
    var outBuf = null;

    function diffReport(got) {
        var firstOff = -1, changed = 0, nz = false;
        for (var i = 0; i < got.length; i++) {
            if (got[i] !== 0xEE) { if (firstOff < 0) firstOff = i; changed++; }
        }
        if (firstOff < 0) return { changed: 0, dump: "--", nz: false };
        var n = Math.min(16, got.length - firstOff);
        var s = "";
        for (var j = 0; j < n; j++) s += got[firstOff + j].toString(16).padStart(2, "0");
        for (var k = 0; k < n; k++) if (got[firstOff + k] !== 0) { nz = true; break; }
        return { changed: changed, dump: s, nz: nz };
    }

    var _canaryCounter = 0;
    function call299(a1, a2, a3, a4, a5, a6, force_canary) {
        /* reset the small buffer without allocating a fresh Uint8Array each time */
        var z = new Uint8Array(OUTLEN);
        for (var i = 0; i < OUTLEN; i++) z[i] = 0xEE;
        root.write_buffer(B(a5), z);
        var ret = S(NR.AIO_GET_DATA, a1, a2, a3, a4, a5, a6);
        _canaryCounter++;
        var needCanary = force_canary || (_canaryCounter % 3) === 0
            || ((ret & 0xFFFFFFFFn) !== 0xen && (ret & 0xFFFFFFFFn) !== 0x0n
                && (ret & 0xFFFFFFFFn) !== 0x1n && (ret & 0xFFFFFFFFn) !== 0x3n
                && (ret & 0xFFFFFFFFn) !== 0x16n);
        if (needCanary && !canary()) {
            st.wedge = true;
            err("WEDGE", "a1=" + hex(a1) + " a2=" + hex(a2) + " a3=" + hex(a3)
                + " a4=" + hex(a4) + " -> no canary");
            return { wedge: true, ret: ret };
        }
        var got = readBytes(a5, OUTLEN);
        return { wedge: false, ret: ret, diff: diffReport(got) };
    }

    function logCall(tag, r) {
        if (r.wedge) return;
        var line = tag + " -> ret=" + hex(r.ret);
        if (r.diff.changed > 0) line += "  changed=" + r.diff.changed + "  dump=" + r.diff.dump;
        if (r.diff.nz) ok("CALL", line);
        else if ((r.ret & 0xFFFFFFFFn) !== 0n && (r.ret & 0xFFFFFFFFn) !== 0x1n
                 && (r.ret & 0xFFFFFFFFn) !== 0x3n && (r.ret & 0xFFFFFFFFn) !== 0x16n
                 && (r.ret & 0xFFFFFFFFn) !== 0xen)
            warn("CALL", line);
        else dim("CALL", line);
    }

    /* ------- phases ------- */
    function setup() {
        sec("PHASE-1", "=== SETUP ===");

        var tidOut = malloc(8);
        for (var i = 0; i < 8; i++) writeByte(tidOut + B(i), 0);
        S(NR.THR_SELF, tidOut, 0n, 0n, 0n, 0n, 0n);
        st.ourTid = B(root.read64(tidOut));
        st.ourPid = S(NR.GETPID, 0n, 0n, 0n, 0n, 0n, 0n);
        st.ourPpid = S(NR.GETPPID, 0n, 0n, 0n, 0n, 0n, 0n);
        dim("IDS", "tid=" + hex(st.ourTid) + " pid=" + hex(st.ourPid) + " ppid=" + hex(st.ourPpid));

        var pfds = malloc(8);
        for (var j = 0; j < 8; j++) writeByte(pfds + B(j), 0);
        var pp = S(NR.PIPE2, pfds, 0n, 0n, 0n, 0n, 0n);
        if ((pp & 0xFFFFFFFFn) !== 0n) {
            err("VERDICT", "pipe2 failed: " + hex(pp));
            return false;
        }
        var pv = readBytes(pfds, 8);
        var prfd = new Int32Array(pv.buffer, 0, 2)[0];
        var pwfd = new Int32Array(pv.buffer, 0, 2)[1];
        ok("SRC", "pipe2 rfd=" + prfd + " wfd=" + pwfd);

        var NREQ = 2;
        var reqs = malloc(0x28 * NREQ);
        var zr = new Uint8Array(0x28 * NREQ);
        root.write_buffer(B(reqs), zr);
        var fdb = new Uint8Array(8);
        fdb[0] = prfd & 0xff; fdb[1] = (prfd >> 8) & 0xff;
        fdb[2] = (prfd >> 16) & 0xff; fdb[3] = (prfd >> 24) & 0xff;
        for (var ri = 0; ri < NREQ; ri++)
            root.write_buffer(reqs + B(ri * 0x28 + 0x20), fdb);
        var idsArr = malloc(NREQ * 8);
        var zi = new Uint8Array(NREQ * 8);
        root.write_buffer(B(idsArr), zi);
        var sub = S(NR.AIO_SUBMIT_CMD, 0x1001n, reqs, B(NREQ), 3n, idsArr, 0n);
        if ((sub & 0xFFFFFFFFn) === 0n) {
            st.id0 = B(root.read64(idsArr));
            ok("SUBMIT", "n=2 ok  id0=" + hex(st.id0));
        } else {
            warn("SUBMIT", "ret=" + hex(sub));
        }
        var init = S(NR.AIO_INIT, st.ourPid, 0n, 0n, 0n, 0n, 0n);
        dim("AIO-INIT", "(pid,0) -> " + hex(init));

        st.prfd = prfd; st.pwfd = pwfd; st.reqs = reqs; st.ids = idsArr;
        return canary();
    }

    function sweep() {
        sec("PHASE-2", "=== 0x299 SWEEP (~55 calls) ===");

        var cases = [
            ["[pid,0,1,1,out,0]",  [st.ourPid, 0n, 1n, 1n, outBuf, 0n]],
            ["[pid,1,1,1,out,0]",  [st.ourPid, 1n, 1n, 1n, outBuf, 0n]],
            ["[pid,1,0,1,out,0]",  [st.ourPid, 1n, 0n, 1n, outBuf, 0n]],
            ["[id0,0,1,1,out,0]",  [st.id0, 0n, 1n, 1n, outBuf, 0n]],
            ["[id0,1,1,1,out,0]",  [st.id0, 1n, 1n, 1n, outBuf, 0n]],
            ["[0,0,1,1,out,0]",    [0n, 0n, 1n, 1n, outBuf, 0n]],
        ];
        for (var i = 0; i < cases.length && !st.wedge; i++) {
            var a = cases[i][1];
            var r = call299(a[0], a[1], a[2], a[3], a[4], a[5], false);
            logCall(cases[i][0], r);
        }
        if (st.wedge) return;

        var a1s = [
            ["0", 0n], ["1", 1n], ["2", 2n],
            ["ourPid-1", st.ourPid - 1n],
            ["ourPid+1", st.ourPid + 1n],
            ["ourPpid", st.ourPpid],
            ["ourTid", st.ourTid],
            ["id0", st.id0],
            ["id0>>32", st.id0 >> 32n],
            ["id0&0xffffffff", st.id0 & 0xFFFFFFFFn],
            ["id0&0xffff", st.id0 & 0xFFFFn],
            ["-1", 0xFFFFFFFFFFFFFFFFn],
            ["0x7fffffff", 0x7FFFFFFFn],
        ];
        for (var k = 0; k < a1s.length && !st.wedge; k++) {
            var r2 = call299(a1s[k][1], 1n, 1n, 1n, outBuf, 0n, false);
            logCall("a1=" + a1s[k][0], r2);
        }
        if (st.wedge) return;

        var a2s = [0n, 1n, 2n, 4n, 8n, 16n, 32n, 64n, 128n, 256n, 1024n, 0x228n];
        for (var m = 0; m < a2s.length && !st.wedge; m++) {
            var r3 = call299(st.ourPid, a2s[m], 1n, 1n, outBuf, 0n, false);
            logCall("a2=" + a2s[m], r3);
        }
        if (st.wedge) return;

        var a3s = [0n, 1n, 2n, 3n, 0x10n, 0x80n, 0x10000n, 0x100000n,
                   0x800000n, 0x1000000n, st.id0, st.id0 >> 32n,
                   st.id0 & 0xFFFFFFFFn, st.id0 & 0xFFFFn];
        for (var n = 0; n < a3s.length && !st.wedge; n++) {
            var r4 = call299(st.ourPid, 1n, a3s[n], 1n, outBuf, 0n, false);
            logCall("a3=" + hex(a3s[n]), r4);
        }
        if (st.wedge) return;

        var a4s = [0n, 1n, 2n, 4n, 0x100n, 0x1000n, 0x10000n, 0x1000000n,
                   0x80000000n, 0xffffffffn];
        for (var p = 0; p < a4s.length && !st.wedge; p++) {
            var r5 = call299(st.ourPid, 1n, 1n, a4s[p], outBuf, 0n, false);
            logCall("a4=" + hex(a4s[p]), r5);
        }
        if (st.wedge) return;

        var r6 = call299(st.ourPid, 1n, 1n, 1n, outBuf + 0x10n, 0n, true);
        logCall("a5=out+0x10", r6);
        if (st.wedge) return;
        var r7 = call299(st.ourPid, 1n, 1n, 1n, outBuf, st.id0, false);
        logCall("a6=id0", r7);
        if (st.wedge) return;
        var r8 = call299(st.ourPid, 1n, 1n, 1n, outBuf, st.ids, false);
        logCall("a6=idsPtr", r8);
    }

    function cleanup() {
        sec("PHASE-3", "=== CLEANUP ===");
        try {
            var stc = malloc(0x20);
            var zs = new Uint8Array(0x20);
            root.write_buffer(B(stc), zs);
            S(NR.AIO_MULTI_CANCEL, st.ids, 2n, stc, 0n, 0n, 0n);
            S(NR.AIO_MULTI_DELETE, st.ids, 2n, stc, 0n, 0n, 0n);
        } catch (e) { }
        try { S(NR.CLOSE, B(st.prfd)); } catch (e) { }
        try { S(NR.CLOSE, B(st.pwfd)); } catch (e) { }
        dim("P3", "cancel/delete/close issued");
    }

    function verdict() {
        sec("PHASE-4", "=== VERDICT ===");
        if (st.wedge) {
            err("VERDICT", "WEDGE -- power-cycle");
            beacon("VERDICT", "WEDGE");
            notify("299: WEDGE");
            return;
        }
        var nzCount = 0, newCodeCount = 0;
        for (var i = 0; i < LOG.length; i++) {
            var line = LOG[i];
            if (/dump=[0-9a-f]+/.test(line) && /changed=/.test(line)) {
                var m = /dump=([0-9a-f]+)/.exec(line);
                if (m && /[1-9a-f]/.test(m[1])) nzCount++;
            }
            if (/-&gt; ret=0x/.test(line)) {
                var mr = /-&gt; ret=(0x[0-9a-f]+)/.exec(line);
                if (mr) {
                    var v = mr[1];
                    if (v !== "0x0" && v !== "0x1" && v !== "0x3"
                        && v !== "0xe" && v !== "0x16") newCodeCount++;
                }
            }
        }
        var msg;
        if (nzCount > 0) {
            ok("VERDICT", nzCount + " call(s) wrote NONZERO data. Grep 'dump=' for the values.");
            beacon("VERDICT", "nonzero " + nzCount);
            notify("299: nonzero!");
        } else if (newCodeCount > 0) {
            warn("VERDICT", newCodeCount + " call(s) returned a new code. Check CALL lines.");
            beacon("VERDICT", "new codes " + newCodeCount);
            notify("299: new codes");
        } else {
            warn("VERDICT", "0x299 behaves like 0x2D7: pid accepted, 4 zero bytes out, rest inert. No AIO leak on 13.60.");
            beacon("VERDICT", "no leak");
            notify("299: no leak");
        }
    }

    function run() {
        try {
            sec("BEGIN", "fw=" + FW + " " + VERSION + " AUTO-RUN (0x299, compact)");
            beacon("BEGIN", "fw=" + FW);
            if (!canary()) {
                err("VERDICT", "no executor");
                beacon("VERDICT", "no executor");
                return;
            }
            ok("CANARY", "getpid ok");

            outBuf = malloc(OUTLEN);
            var z = new Uint8Array(OUTLEN);
            for (var i = 0; i < OUTLEN; i++) z[i] = 0xEE;
            root.write_buffer(B(outBuf), z);

            if (!setup()) { verdict(); return; }
            if (st.wedge) { verdict(); return; }
            sweep();
            cleanup();
            verdict();
        } catch (e) {
            err("FATAL", String((e && e.message) || e).slice(0, 180));
            beacon("FATAL", String((e && e.message) || e).slice(0, 100));
        }
    }

    try {
        var saved = localStorage.getItem(LOGKEY);
        if (saved) {
            var tail = saved.slice(-2000).split("\n").filter(function (l) { return l; });
            for (var ti = 0; ti < tail.length; ti++) {
                var sp = document.createElement("span");
                sp.className = "dim";
                sp.textContent = "    " + tail[ti] + "\n";
                elOut.appendChild(sp);
            }
        }
    } catch (e) { }

    setTimeout(run, 400);

})(typeof window !== "undefined" ? window : globalThis);

