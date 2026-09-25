#!/usr/bin/env node
/* Standalone host for the whole site, including the api/payload/<name> endpoint.
 *
 *     node api/serve.js [port]        (run it from the site root; default port 8080)
 *
 * Why this exists: the ELF tile menu cannot deliver a payload from the browser -
 * JavaScript has no raw sockets, and an HTTP POST straight to port 9021 would
 * prepend HTTP headers so elfldr would not see \x7fELF at offset 0. The page asks
 * the server to make the TCP connection instead.
 *
 * The console is the one making the request, so its address is the socket's own
 * remote address. Nothing to configure.
 *
 * Static files are served relative to the directory you run this from, so hosting
 * under a subdirectory works the same way as at a root.
 */
"use strict";
const http = require("http"), net = require("net"), fs = require("fs"),
      path = require("path"), url = require("url");

const ROOT = process.cwd();
const PORT = parseInt(process.argv[2] || "8080", 10);
const ELFLDR_PORT = 9021;
const LOGS_FILE = path.join(ROOT, "logs.txt");

function appendServerLog(entry) {
    const line = `${new Date().toISOString()} ${entry}\n`;
    fs.appendFile(LOGS_FILE, line, (err) => {
        if (err) console.error("[logs] failed to write:", err.message);
    });
}

const MIME = {
    ".html": "text/html; charset=utf-8", ".js": "application/javascript",
    ".css": "text/css", ".png": "image/png", ".gif": "image/gif",
    ".jpg": "image/jpeg", ".json": "application/json",
    ".elf": "application/octet-stream", ".bin": "application/octet-stream",
    ".txt": "text/plain; charset=utf-8"
};

function sendPayload(name, ip, cb) {
    if (!/^[A-Za-z0-9._-]+\.(elf|bin)$/.test(name)) return cb(new Error("bad payload name"));
    const file = path.join(ROOT, "payloads", name);
    // resolved path must still be inside payloads/ - no traversal
    if (!file.startsWith(path.join(ROOT, "payloads") + path.sep))
        return cb(new Error("bad payload path"));
    fs.readFile(file, (err, buf) => {
        if (err) return cb(new Error("payload not found: " + name));
        const sock = net.connect(ELFLDR_PORT, ip);
        let done = false;
        const finish = (e) => { if (!done) { done = true; sock.destroy(); cb(e, buf.length); } };
        sock.setTimeout(15000, () => finish(new Error("timeout talking to " + ip)));
        sock.on("error", (e) => finish(new Error("connect " + ip + ":" + ELFLDR_PORT + " - " + e.message)));
        sock.on("connect", () => sock.end(buf, () => finish(null)));
    });
}

http.createServer((req, res) => {
    const p = decodeURIComponent(url.parse(req.url).pathname);
    const ip = (req.socket.remoteAddress || "").replace(/^::ffff:/, "");

    if (p === "/api/logs") {
        if (req.method === "GET") {
            fs.readFile(LOGS_FILE, "utf8", (err, text) => {
                if (err) {
                    res.writeHead(200, { "Content-Type": "text/plain; charset=utf-8" });
                    return res.end("");
                }
                res.writeHead(200, { "Content-Type": "text/plain; charset=utf-8" });
                res.end(text);
            });
            return;
        }
        if (req.method === "POST") {
            let body = "";
            req.on("data", (chunk) => {
                body += chunk;
                if (body.length > 1_000_000) {
                    body = body.slice(0, 1_000_000);
                    req.socket.destroy();
                }
            });
            req.on("end", () => {
                let raw = body;
                try {
                    const parsed = JSON.parse(body);
                    if (parsed && typeof parsed.log === "string") raw = parsed.log;
                } catch (_) { }
                const stamp = new Date().toISOString();
                const entry = `${stamp} source=browser from=${ip}\n${raw || "<empty>"}\n---\n`;
                fs.appendFile(LOGS_FILE, entry, (err) => {
                    if (err) {
                        res.writeHead(500, { "Content-Type": "application/json" });
                        res.end(JSON.stringify({ ok: false, error: err.message }));
                        appendServerLog(`POST /api/logs failed from=${ip} error=${err.message}`);
                        return;
                    }
                    res.writeHead(200, { "Content-Type": "application/json" });
                    res.end(JSON.stringify({ ok: true, saved: true, file: "logs.txt", from: ip }));
                    appendServerLog(`POST /api/logs ok from=${ip} bytes=${String(raw).length}`);
                    console.log(`[logs] saved ${String(raw).length} bytes from ${ip}`);
                });
            });
            return;
        }
    }

    const m = p.match(/\/api\/payload\/([^/]+)$/);

    if (m) {
        let ip2 = req.socket.remoteAddress || "";
        if (ip2.startsWith("::ffff:")) ip2 = ip2.slice(7);          // IPv4-mapped IPv6
        sendPayload(m[1], ip2, (err, bytes) => {
            res.writeHead(err ? 502 : 200, { "Content-Type": "application/json" });
            res.end(JSON.stringify(err
                ? { ok: false, error: err.message }
                : { ok: true, bytes, name: m[1], to: ip2 + ":" + ELFLDR_PORT }));
            console.log(`[payload] ${m[1]} -> ${ip2}  ${err ? "FAILED: " + err.message : bytes + " bytes"}`);
        });
        return;
    }

    // the site's own beacons; answer them so they do not 404-spam the log
    if (p.indexOf("/log/") >= 0) { res.writeHead(204); return res.end(); }

    let file = path.join(ROOT, p);
    if (p.endsWith("/")) file = path.join(file, "index.html");
    if (!file.startsWith(ROOT)) { res.writeHead(403); return res.end("forbidden"); }
    fs.readFile(file, (err, buf) => {
        if (err) { res.writeHead(404); console.log("[404] " + p); return res.end("not found"); }
        res.writeHead(200, { "Content-Type": MIME[path.extname(file).toLowerCase()] || "application/octet-stream" });
        res.end(buf);
    });
}).listen(PORT, () => {
    console.log(`serving ${ROOT} on port ${PORT}`);
    console.log(`api/payload/<name> will connect back to the requesting console on :${ELFLDR_PORT}`);
    console.log(`api/logs accepts POSTs and writes to ${LOGS_FILE}`);
});
