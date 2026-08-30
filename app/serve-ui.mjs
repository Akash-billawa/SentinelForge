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
import { spawn } from "node:child_process";
import { MissionControl } from "./lib/mission-control.mjs";
import { config, REPO_ROOT } from "./lib/config.mjs";

const APP_DIR = path.dirname(fileURLToPath(import.meta.url));
const PUBLIC_DIR = path.join(APP_DIR, "public");

// ---------------------------------------------------------------------------
// Stack supervisor: serve-ui owns the other two services. One command boots
// the application stack, and a watchdog respawns anything that dies. This also
// makes children survive shell exits on Windows (serve-ui outlives shells).
// ---------------------------------------------------------------------------

const TF_PORT = Number(new URL(config.trueforgeBaseUrl).port || 8790);
const MCP_PORT = Number(new URL(config.mcpUrl).port || 8765);

function portAlive(port) {
  // Probe by binding: if the bind FAILS the port is occupied (service up);
  // if it succeeds nothing is listening (service down).
  return new Promise((resolve) => {
    const net = http.createServer();
    net.once("error", () => resolve(true));
    net.once("listening", () => net.close(() => resolve(false)));
    net.listen(port, "127.0.0.1");
  });
}

function spawnDetached(cmd, args) {
  const child = spawn(cmd, args, {
    cwd: REPO_ROOT,
    env: process.env,
    detached: true,
    stdio: "ignore",
    windowsHide: true,
  });
  child.unref();
  return child.pid;
}

async function ensureService(port, label, spawnFn) {
  if (await portAlive(port)) {
    console.log(`[supervisor] ${label} already up on :${port}`);
    return;
  }
  console.log(`[supervisor] starting ${label} on :${port}...`);
  spawnFn();
  for (let i = 0; i < 40; i += 1) {
    await new Promise((r) => setTimeout(r, 1000));
    if (await portAlive(port)) {
      console.log(`[supervisor] ${label} is up`);
      return;
    }
  }
  console.error(`[supervisor] ${label} failed to come up on :${port}`);
}

async function supervise() {
  const venvPython = path.join(REPO_ROOT, ".venv", "Scripts", "python.exe");
  const pythonCmd = existsSync(venvPython) ? venvPython : "python";

  await ensureService(MCP_PORT, "sentinelforge-mcp", () =>
    spawnDetached(pythonCmd, ["mcp-server/server.py"]),
  );
  await ensureService(TF_PORT, "trueforge", () =>
    spawnDetached(process.execPath, ["scripts/run-trueforge.mjs"]),
  );

  // Watchdog: respawn any service that dies while we run.
  setInterval(async () => {
    if (!(await portAlive(MCP_PORT))) {
      console.warn("[supervisor] mcp server died - respawning");
      spawnDetached(pythonCmd, ["mcp-server/server.py"]);
    }
    if (!(await portAlive(TF_PORT))) {
      console.warn("[supervisor] trueforge died - respawning");
      spawnDetached(process.execPath, ["scripts/run-trueforge.mjs"]);
    }
  }, 60_000).unref();
}


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

  if (req.method === "POST" && url.pathname === "/api/resume") {
    try {
      mc.resume().catch((err) => mc.recordStartupError(String(err.message ?? err)));
    } catch (err) {
      return json(res, 409, { error: err.message });
    }
    return json(res, 202, { resumed: true });
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
  // no-store: the console JS evolves between investigation runs; a cached stale page
  // renders nonsense (this bit us during testing).
  res.writeHead(200, { "content-type": mime, "cache-control": "no-store" });
  res.end(readFileSync(abs));
});

server.listen(config.uiPort, async () => {
  console.log(`SentinelForge incident console -> http://localhost:${config.uiPort}`);
  supervise().catch((err) => console.error("[supervisor] fatal:", err));
});
