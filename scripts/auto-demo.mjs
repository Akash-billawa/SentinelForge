/**
 * Patient auto-demo launcher.
 *
 * The stealth/ox-alpha shared pool is congested at peak hours: small probes
 * sometimes pass while demo-sized streaming requests 429. This script probes
 * with a DEMO-SHAPED request (large prompt, stream:true) every PROBE_EVERY
 * seconds; the moment one passes it launches a clean investigation via the
 * incident console, auto-approves at the TrueForge checkpoint, and writes the
 * final report summary to the log.
 *
 * Log: state/auto-demo.log
 */

import { writeFileSync, appendFileSync, mkdirSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { config, REPO_ROOT, preflightModel, ensureMcpServerRegistered } from "../app/lib/config.mjs";
import { McpHttpClient } from "../app/lib/mcp-client.mjs";

const LOG = path.join(REPO_ROOT, "state", "auto-demo.log");
const KEY = process.env.OPENROUTER_KEY;
const PROBE_EVERY_MS = 5 * 60 * 1000;
const MAX_WAIT_MS = 3 * 60 * 60 * 1000;
const RUN_TIMEOUT_MS = 32 * 60 * 1000;
const MAX_RUN_ATTEMPTS = 6;

mkdirSync(path.dirname(LOG), { recursive: true });
writeFileSync(LOG, "");

function log(msg) {
  const line = `[${new Date().toISOString()}] ${msg}`;
  console.log(line);
  appendFileSync(LOG, line + "\n");
}

/** Demo-shaped probe: large prompt + streaming, like the real kickoff. */
async function probe() {
  const filler = "Investigate the alert timeline carefully and cite evidence. ".repeat(420);
  const res = await fetch("https://openrouter.ai/api/v1/chat/completions", {
    method: "POST",
    headers: {
      authorization: `Bearer ${KEY}`,
      "content-type": "application/json",
    },
    body: JSON.stringify({
      model: "stealth/ox-alpha",
      max_tokens: 16,
      stream: true,
      messages: [{ role: "user", content: `${filler}\nReply with OK only.` }],
    }),
  });
  if (!res.ok) {
    res.body?.cancel?.();
    return false;
  }
  await res.text(); // drain the stream
  return true;
}

async function resetDemoState() {
  const alert = JSON.parse(
    readFileSync(path.join(REPO_ROOT, "scenarios", config.scenario, "alert.json"), "utf8"),
  );
  const mcp = new McpHttpClient(config.mcpUrl);
  await mcp.init();
  await mcp.call("reset_demo", { incident_id: alert.incident_id, host: alert.hostname });
}

async function runOnce() {
  await resetDemoState();
  const uiBase = `http://localhost:${config.uiPort}`;
  const res = await fetch(`${uiBase}/api/start`, { method: "POST" });
  if (!res.ok) throw new Error(`start failed: HTTP ${res.status}`);

  const deadline = Date.now() + RUN_TIMEOUT_MS;
  let lastSeq = 0;
  let approved = false;
  while (Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, 15000));
    let s;
    try {
      s = await (await fetch(`${uiBase}/api/state`)).json();
    } catch {
      continue;
    }
    for (const e of s.events ?? []) {
      if (e.seq <= lastSeq) continue;
      lastSeq = e.seq;
      const interesting =
        ["subagent_start", "subagent_done", "approval_required", "decision", "risk", "harness"].includes(e.type) ||
        ["error", "danger", "warn"].includes(e.level);
      if (interesting) log(`    [${e.type}] ${e.text}`);
    }
    if (s.status === "WAITING_FOR_APPROVAL" && !approved && s.pendingApproval) {
      const names = (s.pendingApproval.toolCalls ?? []).map((t) => t.name).join(", ");
      log(`>>> CHECKPOINT reached (${names}) - auto-approving`);
      approved = true;
      await fetch("http://localhost:8090/api/approve", { method: "POST" });
      log(">>> approval sent");
    }
    if (s.status === "CLOSED" || s.status === "ERROR") return s;
  }
  return { status: "TIMEOUT" };
}

async function main() {
  log("auto-demo launcher started");
  log(`model=${config.model} trueforge=${config.trueforgeBaseUrl} mcp=${config.mcpUrl}`);

  const pre = await preflightModel(config.trueforgeBaseUrl, config.model);
  if (!pre.ok) {
    log(`PREFLIGHT FAILED: ${pre.reason}`);
    return;
  }
  await ensureMcpServerRegistered(
    config.trueforgeBaseUrl,
    "sentinelforge-security",
    config.mcpUrl,
    "SentinelForge SOC investigation tools",
  );
  log("preflight OK, MCP connector verified");

  // Phase 1: wait for the shared pool to accept a demo-shaped request.
  const waitDeadline = Date.now() + MAX_WAIT_MS;
  let ready = false;
  let n = 0;
  while (Date.now() < waitDeadline) {
    n += 1;
    let ok = false;
    try {
      ok = await probe();
    } catch (err) {
      log(`probe ${n}: network error (${String(err.message ?? err).slice(0, 80)})`);
    }
    log(`probe ${n}: ${ok ? "PASS" : "congested"}`);
    if (ok) {
      ready = true;
      break;
    }
    await new Promise((r) => setTimeout(r, PROBE_EVERY_MS));
  }
  if (!ready) {
    log("GAVE UP: pool congested for the entire wait window");
    return;
  }

  // Phase 2: launch, monitor, auto-approve. Retry on transient-failure runs.
  for (let attempt = 1; attempt <= MAX_RUN_ATTEMPTS; attempt += 1) {
    log(`=== RUN ATTEMPT ${attempt}/${MAX_RUN_ATTEMPTS} ===`);
    let result;
    try {
      result = await runOnce();
    } catch (err) {
      log(`run attempt ${attempt} threw: ${String(err.message ?? err).slice(0, 200)}`);
      result = { status: "ERROR" };
    }
    log(`run attempt ${attempt} -> ${result.status}`);
    if (result.status === "CLOSED") {
      const fr = result.finalReport;
      if (fr) {
        log("=== DEMO COMPLETE ===");
        log(`incident ${fr.incident_id} | risk ${fr.risk.score}/${fr.risk.severity} | confidence ${fr.confidence}`);
        log(`response=${fr.response_state} approval=${fr.approval_state} | findings=${fr.findings.length} evidence=${fr.evidence_refs.length} iocs=${fr.iocs.length}`);
        log(`summary: ${fr.executive_summary}`);
      } else {
        log("=== DEMO COMPLETE (closed, report not captured in snapshot) ===");
      }
      return;
    }
    log("transient failure - re-probing before next attempt...");
    const waitDeadline2 = Date.now() + 10 * 60 * 1000;
    let ok2 = false;
    while (Date.now() < waitDeadline2) {
      try {
        ok2 = await probe();
      } catch {
        ok2 = false;
      }
      if (ok2) break;
      await new Promise((r) => setTimeout(r, PROBE_EVERY_MS));
    }
    if (!ok2) log("pool still congested between attempts");
  }
  log("GAVE UP: all run attempts failed");
}

main().catch((err) => log(`FATAL: ${err.stack ?? err}`));
