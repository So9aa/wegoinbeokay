/*
 * bagagwa_aio299min.js -- v154
 *
 * Minimal single-shot probe for syscall 0x299 (aio_get_data).
 * v153 (compact) still triggered a WebProcess OOM during the sweep.
 * The likely cause: 0x299 with a1=ourPid does real kernel-side work.
 *
 * This version does exactly TWO 0x299 calls:
 *   1. a1 = 0 (the safe path; 0x2D7 returns EPERM for this)
 *   2. a1 = ourPid (the risky path; likely the OOM trigger)
 *
 * Every call is preceded by a persist() line, so a mid-call OOM still leaves
 * the last argument in localStorage. On the next boot, open the same URL
 * WITHOUT ?scauto=1 to just display the tail.
 *
 * Read-only. No num>=2. No kernel writes beyond whatever 0x299 itself does.
 */
(function (root) {
    "use strict";
    if (root.__B299M_LOADED) return;
    root.__B299M_LOADED = true;

    var FW = root.fw_str || "?";
    var VERSION = "v154";
    var LOGKEY = "b299m_log";

    var NR = { GETPID: 0x014, AIO_INIT: 0x29E, AIO_GET_DATA: 0x299, MALLOC: null };

    function B(x) { return (typeof x === "bigint") ? x : BigInt(x); }
    function hex(v) {
        try {
            var b = BigInt(v);
            if (b < 0n) b = BigInt.asUintN(64, b);
            return "0x" + b.toString(16);
        } catch (e) { return String(v); }
    }
    function persist(line) {
        try {
            var cur = localStorage.getItem(LOGKEY) || "";
            cur += line + "\n";
            if (cur.length > 6000) cur = cur.slice(-3000);
            localStorage.setItem(LOGKEY, cur);
        } catch (e) { }
    }
    function log(line) {
        persist(line);
        try {
            var d = document.getElementById("b-output");
            if (d) d.textContent += line + "\n";
        } catch (e) { }
    }

    /* minimal panel */
    var p = document.createElement("pre");
    p.id = "b-output";
    p.style.cssText = "position:fixed;inset:0;z-index:2147483647;background:#0c0c0f;"
        + "color:#c9c9d1;font:11px/1.4 Consolas,monospace;padding:8px 10px;margin:0;"
        + "white-space:pre-wrap;word-break:break-all;overflow:auto;";
    document.body.appendChild(p);

    try {
        var tail = localStorage.getItem(LOGKEY) || "";
        if (tail) {
            var lines = tail.split("\n").slice(-30);
            for (var ti = 0; ti < lines.length; ti++) {
                if (!lines[ti]) continue;
                var s = document.createElement("span");
                s.style.color = "#6f7076";
                s.textContent = "    " + lines[ti] + "\n";
                p.appendChild(s);
            }
        }
    } catch (e) { }

    log("");
    log("=== 299 MINIMAL " + VERSION + " fw=" + FW + " ===");

    function run() {
        try {
            var canary1 = B(root.syscall(NR.GETPID, 0n, 0n, 0n, 0n, 0n, 0n));
            log("[t] canary1 getpid=" + hex(canary1));
            if (canary1 === 0n || canary1 > 0x100000n) {
                log("CANARY1 FAILED -- executor not up, aborting");
                return;
            }
            var pid = canary1;

            log("[t] about to call aio_init(pid, 0)");
            var init = B(root.syscall(NR.AIO_INIT, pid, 0n, 0n, 0n, 0n, 0n));
            log("[t] aio_init -> " + hex(init));

            var canary2 = B(root.syscall(NR.GETPID, 0n, 0n, 0n, 0n, 0n, 0n));
            log("[t] canary2 getpid=" + hex(canary2));
            if (canary2 === 0n || canary2 > 0x100000n) {
                log("CANARY2 FAILED -- kernel wedged after aio_init, aborting");
                return;
            }

            var out = B(root.malloc(0x40));
            var z = new Uint8Array(0x40);
            for (var i = 0; i < 0x40; i++) z[i] = 0xEE;
            root.write_buffer(out, z);

            log("[t] about to call 0x299(0,1,1,1,out,0)");
            var ret1 = B(root.syscall(NR.AIO_GET_DATA, 0n, 1n, 1n, 1n, out, 0n));
            log("[t] 0x299(0,1,1,1,out,0) -> " + hex(ret1));

            var canary3 = B(root.syscall(NR.GETPID, 0n, 0n, 0n, 0n, 0n, 0n));
            log("[t] canary3 getpid=" + hex(canary3));
            if (canary3 === 0n || canary3 > 0x100000n) {
                log("CANARY3 FAILED -- kernel wedged after 0x299(a1=0), aborting");
                return;
            }
            var got1 = new Uint8Array(root.read_buffer(out, 0x40));
            var s1 = "";
            for (var j = 0; j < 0x10; j++) s1 += got1[j].toString(16).padStart(2, "0");
            log("[t] out[0..0x10] = " + s1);

            var z2 = new Uint8Array(0x40);
            for (var k = 0; k < 0x40; k++) z2[k] = 0xEE;
            root.write_buffer(out, z2);
            log("[t] about to call 0x299(pid=" + hex(pid) + ",1,1,1,out,0)  <-- RISK");
            var ret2 = B(root.syscall(NR.AIO_GET_DATA, pid, 1n, 1n, 1n, out, 0n));
            log("[t] 0x299(pid,1,1,1,out,0) -> " + hex(ret2));

            var canary4 = B(root.syscall(NR.GETPID, 0n, 0n, 0n, 0n, 0n, 0n));
            log("[t] canary4 getpid=" + hex(canary4));

            var got2 = new Uint8Array(root.read_buffer(out, 0x40));
            var s2 = "";
            for (var m = 0; m < 0x10; m++) s2 += got2[m].toString(16).padStart(2, "0");
            log("[t] out[0..0x10] = " + s2);

            log("DONE");
        } catch (e) {
            log("FATAL: " + String((e && e.message) || e).slice(0, 180));
        }
    }

    var AUTORUN = false;
    try { AUTORUN = /(^|[?&])scauto=1(&|$)/.test(root.location.search || ""); } catch (e) { }
    if (AUTORUN) {
        setTimeout(run, 400);
    } else {
        log("(autorun off -- pass ?scauto=1 in the URL to run, omit it to just display this tail)");
    }
})(typeof window !== "undefined" ? window : globalThis);
