#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");

const WEBHOOK = process.env.DISCORD_WEBHOOK_URL || "https://discordapp.com/api/webhooks/1522997605850812438/X8kBdpeLt9YDlW6eS44iJtVXSgcrqpEJernRvnmf9weJQZ80QvpWSn5d-HMCYJ91MT6p";
const DEFAULT_FILES = ["logs.txt", "log.txt", "debug.log", "output.log"];

function pickLogFile() {
  const target = process.argv[2];
  if (target) {
    const resolved = path.resolve(process.cwd(), target);
    if (!fs.existsSync(resolved)) {
      throw new Error(`file not found: ${target}`);
    }
    return resolved;
  }

  for (const name of DEFAULT_FILES) {
    const candidate = path.resolve(process.cwd(), name);
    if (fs.existsSync(candidate)) return candidate;
  }

  throw new Error("no log file found. pass a file path, e.g. node local-discord-send.js logs.txt");
}

function buildMultipartBody(filePath, fileName, username, message) {
  const boundary = "----markimods-" + Date.now().toString(16);
  const fileBuffer = fs.readFileSync(filePath);
  const parts = [
    `--${boundary}\r\nContent-Disposition: form-data; name="username"\r\n\r\n${username}\r\n`,
    `--${boundary}\r\nContent-Disposition: form-data; name="content"\r\n\r\n${message}\r\n`,
    `--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="${fileName}"\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n`,
    fileBuffer,
    `\r\n--${boundary}--\r\n`
  ];

  const totalLength = parts.reduce((sum, part) => {
    if (Buffer.isBuffer(part)) return sum + part.length;
    return sum + Buffer.byteLength(part, "utf8");
  }, 0);

  const chunks = [];
  let offset = 0;
  for (const part of parts) {
    if (Buffer.isBuffer(part)) {
      chunks.push(Buffer.from(part));
    } else {
      chunks.push(Buffer.from(part, "utf8"));
    }
  }

  return {
    body: Buffer.concat(chunks),
    contentType: `multipart/form-data; boundary=${boundary}`,
    totalLength,
  };
}

function postToDiscord(filePath) {
  return new Promise((resolve, reject) => {
    const url = new URL(WEBHOOK);
    const fileName = path.basename(filePath);
    const bodyInfo = buildMultipartBody(filePath, fileName, "Local Log Sender", `Local log upload: ${fileName}`);

    const transport = url.protocol === "https:" ? require("https") : require("http");
    const req = transport.request(
      {
        protocol: url.protocol,
        hostname: url.hostname,
        port: url.port || (url.protocol === "https:" ? 443 : 80),
        path: url.pathname + url.search,
        method: "POST",
        headers: {
          "Content-Type": bodyInfo.contentType,
          "Content-Length": bodyInfo.totalLength,
          "User-Agent": "markimods-local-log-sender/1.0",
        },
      },
      (res) => {
        let data = "";
        res.on("data", (chunk) => {
          data += chunk.toString("utf8");
        });
        res.on("end", () => {
          if (res.statusCode >= 200 && res.statusCode < 300) {
            resolve({ ok: true, status: res.statusCode, response: data });
          } else {
            reject(new Error(`Discord upload failed: ${res.statusCode} ${data}`));
          }
        });
      }
    );

    req.on("error", (err) => reject(err));
    req.write(bodyInfo.body);
    req.end();
  });
}

(async function main() {
  try {
    const filePath = pickLogFile();
    const result = await postToDiscord(filePath);
    console.log("Discord upload ok:", result.status);
    console.log(result.response || "sent");
  } catch (err) {
    console.error("FAILED:", err.message);
    process.exit(1);
  }
})();
