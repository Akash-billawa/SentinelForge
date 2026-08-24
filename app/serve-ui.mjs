#!/usr/bin/env node
/**
 * SentinelForge incident console - serves the mission-control UI and bridges
 * it to TrueForge through MissionControl.
 *
 *   node serve-ui.mjs            # http://localhost:8090
 *
 * API:
 *   GET  /api/state              current snapshot (status, events, pending)
 *   GET  /api/events             SSE stream of live events
 *   POST /api/start              begin the investigation
 *   POST /api/approve            approve the pending checkpoint
 *   POST /api/deny  {reason?}    deny the pending checkpoint
 */

import http from "node:http";
import { readFileSync, existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { MissionControl } from "./lib/mission-control.mjs";
import { config } from "./lib/config.mjs";

const APP_DIR = path.dirname(fileURLToPath(import.meta.url));
const PUBLIC_DIR = path.join(APP_DIR, "public");

let mc = new MissionControl({ logPath: null });

const json = (res, code, body) => {
  const data = JSON.stringify(body);
  res.writeHead(code, {
    "content-type": "application/json",
    "cache-control": "no-store",
    "access-control-allow-origin": "*",
  });
  res.end(data);
};

async function readBody(req) {
  const chunks = [];
  for await (const c of req) chunks.push(c);
  const raw = Buffer.concat(chunks).toString("utf8");
  try {
    return raw ? JSON.parse(raw) : {};
  } catch {
    return {};
  }
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);

  if (url.pathname === "/api/state") {
    return json(res, 200, mc.snapshot());
  }

  if (url.pathname === "/api/events") {
    res.writeHead(200, {
      "content-type": "text/event-stream",
      "cache-control": "no-cache",
      connection: "keep-alive",
      "access-control-allow-origin": "*",
    });
    let lastSeq = Number(url.searchParams.get("after") ?? 0);
    const send = (evt) => {
      if (evt.seq > lastSeq) {
        lastSeq = evt.seq;
        res.write(`id: ${evt.seq}\ndata: ${JSON.stringify(evt)}\n\n`);
      }
    };
    for (const evt of mc.events) send(evt);
    const unsub = mc.subscribe(send);
    const keepAlive = setInterval(() => res.write(": ping\n\n"), 15000);
    req.on("close", () => {
      clearInterval(keepAlive);
      unsub();
    });
    return;
  }

  if (req.method === "POST" && url.pathname === "/api/start") {
    if (mc.status === "INVESTIGATING" || mc.status === "RETRYING") {
      return json(res, 409, { error: "investigation already in progress" });
    }
    // Reuse the SAME MissionControl instance so existing SSE subscribers keep
    // receiving events across runs (a fresh instance would orphan them).
    mc.reset();
    mc.start().catch((err) => mc.recordStartupError(String(err.message ?? err)));
    return json(res, 202, { started: true, note: "stream /api/events for progress" });
  }

  if (req.method === "POST" && url.pathname === "/api/approve") {
    try {
      await mc.decide(true);
    } catch (err) {
      return json(res, 409, { error: err.message });
    }
    return json(res, 200, mc.snapshot());
  }

  if (req.method === "POST" && url.pathname === "/api/deny") {
    const body = await readBody(req);
    try {
      await mc.decide(false, body.reason ?? "");
    } catch (err) {
      return json(res, 409, { error: err.message });
    }
    return json(res, 200, mc.snapshot());
  }

  // static files
  let filePath = url.pathname === "/" ? "/index.html" : url.pathname;
  filePath = path.normalize(filePath).replace(/^(\.\.[/\\])+/, "");
  const abs = path.join(PUBLIC_DIR, filePath);
  if (!abs.startsWith(PUBLIC_DIR) || !existsSync(abs)) {
    res.writeHead(404);
    return res.end("not found");
  }
  const ext = path.extname(abs);
  const mime = { ".html": "text/html", ".js": "text/javascript", ".css": "text/css", ".svg": "image/svg+xml" }[ext] ?? "application/octet-stream";
  res.writeHead(200, { "content-type": mime });
  res.end(readFileSync(abs));
});

server.listen(config.uiPort, () => {
  console.log(`SentinelForge incident console -> http://localhost:${config.uiPort}`);
});
