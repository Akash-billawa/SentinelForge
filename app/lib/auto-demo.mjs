/**
 * Auto-demo loop: probe the model pool with a demo-shaped request until it
 * accepts, then launch a clean investigation, auto-approve at the checkpoint,
 * and report. Designed to run inside the serve-ui process (which survives
 * across shell sessions, unlike detached child processes on this machine).
 */

import { appendFileSync, mkdirSync, readFileSync } from "node:fs";
import path from "node:path";
import { config, REPO_ROOT, preflightModel, ensureMcpServerRegistered } from "./config.mjs";
import { McpHttpClient } from "./mcp-client.mjs";

const LOG = path.join(REPO_ROOT, "state", "auto-demo.log");
const PROBE_EVERY_MS = 5 * 60 * 1000;
const MAX_WAIT_MS = 3 * 60 * 60 * 1000;
const RUN_TIMEOUT_MS = 32 * 60 * 1000;
const MAX_RUN_ATTEMPTS = 6;

export class AutoDemo {
  static instance = null;

  static start(apiKey) {
    if (AutoDemo.instance) return { started: false, note: "already running" };
    AutoDemo.instance = new AutoDemo(apiKey);
    AutoDemo.instance.run().catch((err) => {
      AutoDemo.instance?.log(`FATAL: ${err?.stack ?? err}`);
      AutoDemo.instance = null;
    });
    return { started: true };
  }

  constructor(apiKey) {
    this.apiKey = apiKey;
    mkdirSync(path.dirname(LOG), { recursive: true });
    appendFileSync(LOG, "");
  }

  log(msg) {
    const line = `[${new Date().toISOString()}] ${msg}`;
    console.log(`[auto-demo] ${msg}`);
    try {
      appendFileSync(LOG, line + "\n");
    } catch {
      /* logging must never break the loop */
    }
  }

  /** Demo-shaped probe: large prompt + streaming, like the real kickoff. */
  async probe() {
    const filler = "Investigate the alert timeline carefully and cite evidence. ".repeat(420);
    const res = await fetch("https://openrouter.ai/api/v1/chat/completions", {
      method: "POST",
      headers: { authorization: `Bearer ${this.apiKey}`, "content-type": "application/json" },
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
    await res.text();
    return true;
  }

  async resetDemoState() {
    const alert = JSON.parse(
      readFileSync(path.join(REPO_ROOT, "scenarios", config.scenario, "alert.json"), "utf8"),
    );
    const mcp = new McpHttpClient(config.mcpUrl);
    await mcp.init();
    await mcp.call("reset_demo", { incident_id: alert.incident_id, host: alert.hostname });
  }

  uiBase() {
    return `http://localhost:${config.uiPort}`;
  }

  async runOnce() {
    await this.resetDemoState();
    const res = await fetch(`${this.uiBase()}/api/start`, { method: "POST" });
    if (!res.ok) throw new Error(`start failed: HTTP ${res.status}`);

    const deadline = Date.now() + RUN_TIMEOUT_MS;
    let lastSeq = 0;
    let approved = false;
    while (Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 15000));
      let s;
      try {
        s = await (await fetch(`${this.uiBase()}/api/state`)).json();
      } catch {
        continue;
      }
      for (const e of s.events ?? []) {
        if (e.seq <= lastSeq) continue;
        lastSeq = e.seq;
        const interesting =
          ["subagent_start", "subagent_done", "approval_required", "decision", "risk", "harness"].includes(e.type) ||
          ["error", "danger", "warn"].includes(e.level);
        if (interesting) this.log(`    [${e.type}] ${e.text}`);
      }
      if (s.status === "WAITING_FOR_APPROVAL" && !approved && s.pendingApproval) {
        const names = (s.pendingApproval.toolCalls ?? []).map((t) => t.name).join(", ");
        this.log(`>>> CHECKPOINT reached (${names}) - auto-approving`);
        approved = true;
        await fetch(`${this.uiBase()}/api/approve`, { method: "POST" });
        this.log(">>> approval sent");
      }
      if (s.status === "CLOSED" || s.status === "ERROR") return s;
    }
    return { status: "TIMEOUT" };
  }

  async run() {
    this.log("auto-demo loop started (in-process)");
    this.log(`model=${config.model} trueforge=${config.trueforgeBaseUrl} mcp=${config.mcpUrl}`);

    const pre = await preflightModel(config.trueforgeBaseUrl, config.model);
    if (!pre.ok) {
      this.log(`PREFLIGHT FAILED: ${pre.reason}`);
      return;
    }
    await ensureMcpServerRegistered(
      config.trueforgeBaseUrl,
      "sentinelforge-security",
      config.mcpUrl,
      "SentinelForge SOC investigation tools",
    );
    this.log("preflight OK, MCP connector verified");

    const waitDeadline = Date.now() + MAX_WAIT_MS;
    let ready = false;
    let n = 0;
    while (Date.now() < waitDeadline) {
      n += 1;
      let ok = false;
      try {
        ok = await this.probe();
      } catch (err) {
        this.log(`probe ${n}: network error (${String(err.message ?? err).slice(0, 80)})`);
      }
      this.log(`probe ${n}: ${ok ? "PASS" : "congested"}`);
      if (ok) {
        ready = true;
        break;
      }
      await new Promise((r) => setTimeout(r, PROBE_EVERY_MS));
    }
    if (!ready) {
      this.log("GAVE UP: pool congested for the entire wait window");
      return;
    }

    for (let attempt = 1; attempt <= MAX_RUN_ATTEMPTS; attempt += 1) {
      this.log(`=== RUN ATTEMPT ${attempt}/${MAX_RUN_ATTEMPTS} ===`);
      let result;
      try {
        result = await this.runOnce();
      } catch (err) {
        this.log(`run attempt ${attempt} threw: ${String(err.message ?? err).slice(0, 200)}`);
        result = { status: "ERROR" };
      }
      this.log(`run attempt ${attempt} -> ${result.status}`);
      if (result.status === "CLOSED") {
        const fr = result.finalReport;
        this.log("=== DEMO COMPLETE ===");
        if (fr) {
          this.log(`incident ${fr.incident_id} | risk ${fr.risk.score}/${fr.risk.severity} | confidence ${fr.confidence}`);
          this.log(`response=${fr.response_state} approval=${fr.approval_state} | findings=${fr.findings.length} evidence=${fr.evidence_refs.length} iocs=${fr.iocs.length}`);
          this.log(`summary: ${fr.executive_summary}`);
        }
        return;
      }
      this.log("transient failure - re-probing before next attempt...");
      const retryDeadline = Date.now() + 10 * 60 * 1000;
      let ok2 = false;
      while (Date.now() < retryDeadline) {
        try {
          ok2 = await this.probe();
        } catch {
          ok2 = false;
        }
        if (ok2) break;
        await new Promise((r) => setTimeout(r, PROBE_EVERY_MS));
      }
      if (!ok2) this.log("pool still congested between attempts");
    }
    this.log("GAVE UP: all run attempts failed");
  }
}
