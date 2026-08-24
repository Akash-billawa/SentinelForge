/**
 * MissionControl - drives the SOC Commander through TrueForge.
 *
 * One instance = one incident investigation. Streams turn events to any
 * subscriber (CLI or SSE UI), detects the TrueForge approval pause, and
 * resumes it with a human APPROVE/DENY decision.
 */

import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import path from "node:path";
import {
  config,
  buildCommanderSpec,
  kickoffPrompt,
  REPO_ROOT,
  preflightModel,
  ensureMcpServerRegistered,
} from "./config.mjs";

const EVENTS_LOG = path.join(REPO_ROOT, "state", "ui-events.jsonl");

// Provider hiccups worth an automatic resume (free-tier 503/overload/429,
// plus transient network failures between the harness and the provider).
const TRANSIENT_ERROR_RE = /\b(429|500|502|503|504|529)\b|high demand|overloaded|rate.?limit|temporarily|try again later|connect timeout|connection (error|refused|reset|closed)|econn(reset|refused|aborted)|etimedout|enotfound|socket hang up|fetch failed|network (error|timeout)/i;
const MAX_TRANSIENT_RETRIES = Number(process.env.SENTINELFORGE_MAX_RETRIES ?? 4);
const TRANSIENT_RETRY_BASE_MS = Number(process.env.SENTINELFORGE_RETRY_DELAY_MS ?? 20000);

function loadSdk() {
  // Imported lazily so the module can be inspected without node_modules.
  return import("@truefoundry/trueforge-sdk");
}

export class MissionControl {
  #turnErrorMessage = null;
  /** id -> accumulated streaming model.message fragments (content + toolCalls). */
  #msgAcc = new Map();
  /** Incremented on reset; stale async writers (timed retries) are dropped. */
  #runSeq = 0;
  /** id -> last non-delta event per stream; lets handlers resolve approvals. */
  #eventsIndex = new Map();

  constructor({ logPath = null } = {}) {
    this.logPath = logPath;
    this.sessionId = null;
    this.events = []; // normalized UI events
    this.pendingApproval = null; // { threadId, toolCalls: [{id,name,args}] }
    this.status = "IDLE"; // IDLE|INVESTIGATING|WAITING_FOR_APPROVAL|CONTAINED|DENIED|CLOSED|ERROR
    this.subscribers = new Set();
    this.incidentId = null;
    this.finalReport = null;
  }

  #emit(evt) {
    const runSeq = this.#runSeq;
    const record = { seq: this.events.length + 1, at: new Date().toISOString(), ...evt };
    if (runSeq !== this.#runSeq) return record; // stale writer from a pre-reset run
    this.events.push(record);
    if (this.logPath) {
      try {
        mkdirSync(path.dirname(this.logPath), { recursive: true });
        writeFileSync(this.logPath, JSON.stringify(record) + "\n", { flag: "a" });
      } catch {
        /* logging must never break the demo */
      }
    }
    for (const fn of this.subscribers) {
      try {
        fn(record);
      } catch {
        /* ignore subscriber errors */
      }
    }
    return record;
  }

  subscribe(fn) {
    this.subscribers.add(fn);
    return () => this.subscribers.delete(fn);
  }

  /** Record a startup failure so the UI can surface it. */
  recordStartupError(message) {
    this.status = "ERROR";
    this.#emit({ type: "harness", level: "error", text: `Startup failed: ${quotaHint(message)}` });
  }

  snapshot() {
    return {
      status: this.status,
      sessionId: this.sessionId,
      incidentId: this.incidentId,
      pendingApproval: this.pendingApproval,
      finalReport: this.finalReport,
      events: this.events,
    };
  }

  /** Resolve a pending approval's tool name/args from its source model.message. */
  static #resolveToolCall(eventsIndex, pending) {
    return (pending.toolCalls ?? []).map((ref) => {
      const msg = eventsIndex.get(ref.sourceEventId);
      const call = msg?.toolCalls?.find((tc) => tc.id === ref.id);
      let args = {};
      try {
        args = call ? JSON.parse(call.function.arguments || "{}") : {};
      } catch {
        args = { _raw: call?.function?.arguments };
      }
      return { id: ref.id, name: call?.toolInfo?.name ?? "unknown", args };
    });
  }

  /** Clear state for a fresh run. Safe while IDLE/CLOSED/ERROR; refuses mid-run. */
  reset() {
    if (this.status === "INVESTIGATING" || this.status === "RETRYING") {
      throw new Error("investigation already in progress");
    }
    this.#runSeq += 1;
    this.sessionId = null;
    this.events = [];
    this.pendingApproval = null;
    this.status = "IDLE";
    this.incidentId = null;
    this.finalReport = null;
    this.riskAssessment = null;
    this.#msgAcc.clear();
    this.#turnErrorMessage = null;
    this.#emit({ type: "console", level: "info", text: "Console reset - ready for a new investigation." });
  }

  async start() {
    if (this.status === "INVESTIGATING" || this.status === "RETRYING") {
      throw new Error("investigation already in progress");
    }
    if (this.status !== "IDLE") this.reset();

    const pre = await preflightModel(config.trueforgeBaseUrl, config.model);
    if (!pre.ok) throw new Error(pre.reason);

    const reg = await ensureMcpServerRegistered(
      config.trueforgeBaseUrl,
      "sentinelforge-security",
      config.mcpUrl,
      "SentinelForge SOC investigation tools: logs, DNS, flows, process tree, IOCs, sandbox analysis, gated response.",
    );
    this.#emit({
      type: "console",
      level: "info",
      text: reg.changed
        ? `MCP connector registered: sentinelforge-security -> ${config.mcpUrl}`
        : `MCP connector verified: sentinelforge-security`,
    });

    const { TrueForge } = await loadSdk();
    this.client = new TrueForge({
      baseUrl: config.trueforgeBaseUrl,
      timeoutInSeconds: 900,
    });
    const spec = buildCommanderSpec();
    const { data: session, error } = await this.client.sessions.create({
      agent: { spec },
    });
    if (error) throw new Error(`failed to create session: ${JSON.stringify(error)}`);
    this.sessionId = session.id;
    this.status = "INVESTIGATING";
    this.#emit({
      type: "console",
      level: "info",
      text: `Session ${session.id} opened on ${config.trueforgeBaseUrl} - SOC Commander online.`,
    });
    await this.#runTurn([{ type: "user.message", content: kickoffPrompt() }]);
    return this.snapshot();
  }

  /** Human decision on the approval checkpoint. */
  async decide(approve, reason = "") {
    if (!this.pendingApproval) throw new Error("no approval pending");
    const input = this.pendingApproval.toolCalls.map((tc) => ({
      type: "user.tool_approval",
      threadId: this.pendingApproval.threadId,
      toolCallId: tc.id,
      approval: approve ? { status: "allow" } : { status: "deny", reason: reason || "denied by operator" },
    }));
    this.#emit({
      type: "decision",
      level: approve ? "approve" : "deny",
      text: approve
        ? "Operator APPROVED containment."
        : `Operator DENIED containment${reason ? `: ${reason}` : ""}.`,
    });
    this.pendingApproval = null;
    await this.#runTurn(input);
    return this.snapshot();
  }

  async #runTurn(input, attempt = 0) {
    this.#eventsIndex = new Map();
    this.#turnErrorMessage = null;
    const stream = await this.client.sessions.createTurnStream(this.sessionId, { input });

    for await (const { data: event } of stream.withMetadata()) {
      this.#eventsIndex.set(event.id, event);
      this.#handleEvent(event);
    }
    this.#flushMessages();

    // Transient provider failures (free-tier 503/overload/429) do not have to
    // kill the investigation: session context persists, so we resume with a
    // continuation turn after a backoff - the operator-visible equivalent of
    // "wait and try again".
    if (this.#turnErrorMessage) {
      if (TRANSIENT_ERROR_RE.test(this.#turnErrorMessage)) {
        if (attempt >= MAX_TRANSIENT_RETRIES) {
          this.status = "ERROR";
          this.#emit({
            type: "harness",
            level: "error",
            text: `Provider still failing after ${MAX_TRANSIENT_RETRIES} retries: ${quotaHint(this.#turnErrorMessage)}`,
          });
          return;
        }
        const delay = Math.min(
          Math.max(parseRetryAfterSeconds(this.#turnErrorMessage), TRANSIENT_RETRY_BASE_MS),
          120000,
        );
        this.status = "RETRYING";
        this.#emit({
          type: "console",
          level: "warn",
          text: `Provider hiccup (${this.#turnErrorMessage.slice(0, 90)}) - resuming in ${Math.round(delay / 1000)}s (attempt ${attempt + 1}/${MAX_TRANSIENT_RETRIES}); incident context is preserved.`,
        });
        await new Promise((resolve) => setTimeout(resolve, delay));
        return this.#runTurn(
          [{ type: "user.message", content: "Continue the investigation from exactly where you stopped." }],
          attempt + 1,
        );
      }
      // non-transient errors were already surfaced as ERROR by the handler
    }
  }

  /** Emit accumulated tool calls (and main-thread text) from merged deltas. */
  #flushMessages() {
    for (const [id, acc] of this.#msgAcc) {
      if (acc.flushed) continue;
      acc.flushed = true;
      for (const call of acc.calls) {
        let args = {};
        try {
          args = JSON.parse(call.args || "{}");
        } catch {
          /* partial args - show what we have as raw */
          args = { _raw: call.args?.slice(0, 200) };
        }
        this.#emit({
          type: "tool_call",
          text: call.name ?? "unknown",
          tool: call.name,
          args,
          level: String(call.name ?? "").includes("isolate") ? "danger" : "info",
        });
      }
      const text = acc.content.trim();
      if (text) this.#emit({ type: "agent_message", threadId: "main", text });
    }
    this.#msgAcc.clear();
  }

  #handleEvent(event) {
    switch (event.type) {
      case "mcp.initialize": {
        const names = (event.mcpServers ?? []).map((s) => s.name).join(", ");
        this.#emit({ type: "harness", text: `MCP initialized: ${names}` });
        break;
      }
      case "thread.created": {
        this.#emit({
          type: "subagent_start",
          threadId: event.threadId,
          text: `Delegated -> ${event.title}`,
        });
        break;
      }
      case "thread.done": {
        const ok = event.state?.status === "done";
        this.#emit({
          type: "subagent_done",
          threadId: event.threadId,
          text: `${event.title} finished (${ok ? "ok" : "error"})`,
          level: ok ? "ok" : "error",
        });
        break;
      }
      case "model.message.delta": {
        // Live streams carry model output as fragments: merge content and
        // tool-call chunks (by array index) so tool names/args are visible.
        const acc = this.#msgAcc.get(event.id) ?? { content: "", calls: [], flushed: false };
        if (typeof event.content === "string" && event.content) acc.content += event.content;
        (event.toolCalls ?? []).forEach((frag, i) => {
          const slot = (acc.calls[i] ??= { name: null, args: "" });
          const name = frag?.function?.name ?? frag?.toolInfo?.name;
          if (name && !slot.name) slot.name = name;
          if (typeof frag?.function?.arguments === "string") slot.args += frag.function.arguments;
        });
        this.#msgAcc.set(event.id, acc);
        break;
      }
      case "model.message": {
        const content = typeof event.content === "string" ? event.content : "";
        const calls = event.toolCalls ?? [];
        for (const call of calls) {
          let args = {};
          try {
            args = JSON.parse(call.function?.arguments || "{}");
          } catch {
            /* keep empty */
          }
          this.#emit({
            type: "tool_call",
            threadId: event.threadId,
            text: `${call.function?.name ?? "?"}`,
            tool: call.function?.name,
            args,
            level: args && String(call.function?.name).includes("isolate") ? "danger" : "info",
          });
        }
        if (content.trim()) {
          this.#emit({ type: "agent_message", threadId: event.threadId, text: content.trim() });
        }
        break;
      }
      case "tool.response": {
        let evidence = [];
        let parsed = null;
        try {
          parsed = JSON.parse(event.content ?? "null");
        } catch {
          /* non-JSON payload */
        }
        const collect = (obj) => {
          if (!obj || typeof obj !== "object") return;
          if (typeof obj.evidence_ref === "string") evidence.push(obj.evidence_ref);
          if (Array.isArray(obj)) return obj.forEach(collect);
          for (const v of Object.values(obj)) if (v && typeof v === "object") collect(v);
        };
        collect(parsed);
        this.#emit({
          type: "tool_result",
          threadId: event.threadId,
          text: evidence.length ? `evidence: ${evidence.slice(0, 6).join(", ")}` : "result received",
          evidence,
          preview: truncate(event.content ?? "", 240),
        });
        if (parsed?.incident_id) this.incidentId ||= parsed.incident_id;
        if (parsed && typeof parsed.score === "number" && parsed.severity && parsed.signals) {
          this.riskAssessment = parsed;
          this.#emit({
            type: "risk",
            level: parsed.score >= 70 ? "danger" : "info",
            text: `Risk ${parsed.score}/100 (${parsed.severity}) - confidence ${Math.round((parsed.confidence ?? 0) * 100)}%`,
            risk: parsed,
          });
        }
        if (parsed?.final_report) {
          this.finalReport = parsed.final_report ?? parsed;
          this.status = "CLOSED";
        }
        break;
      }
      case "tool.approval_required": {
        this.status = "WAITING_FOR_APPROVAL";
        const toolCalls = MissionControl.#resolveToolCall(this.#eventsIndex, event);
        this.pendingApproval = { threadId: event.threadId, toolCalls };
        this.#emit({
          type: "approval_required",
          level: "danger",
          text: `TrueForge checkpoint: human approval required for ${toolCalls
            .map((t) => t.name)
            .join(", ")}`,
          toolCalls,
        });
        break;
      }
      case "turn.done": {
        const st = event.state ?? {};
        if (st.status === "done") {
          if (!this.pendingApproval) {
            if (this.finalReport) {
              this.status = "CLOSED";
              this.#emit({ type: "harness", level: "ok", text: "Investigation complete." });
            } else if (this.status === "INVESTIGATING") {
              this.#emit({ type: "harness", text: "Turn finished." });
            }
          }
        } else if (st.status === "error") {
          this.#turnErrorMessage = st.message ?? "unknown turn error";
          if (!TRANSIENT_ERROR_RE.test(this.#turnErrorMessage)) {
            this.status = "ERROR";
            this.#emit({ type: "harness", level: "error", text: `Turn error: ${quotaHint(this.#turnErrorMessage)}` });
          }
        }
        break;
      }
      default:
        break;
    }
  }
}

function truncate(s, n) {
  return s.length <= n ? s : s.slice(0, n) + "...";
}

/** Honor the provider's own "Please retry in Ns" hint when present (Gemini sends it). */
function parseRetryAfterSeconds(message) {
  const m = /retry in ([\d.]+)\s*s/i.exec(String(message ?? ""));
  return m ? Math.ceil(Number(m[1]) * 1000) + 1000 : 0;
}

/** Turn raw provider errors into operator-actionable guidance. */
function quotaHint(message) {  const msg = String(message ?? "");
  if (/429|quota|RESOURCE_EXHAUSTED/i.test(msg)) {
      if (/gemini/i.test(msg)) {
        return (
          msg.split("\n")[0] +
          " -> Gemini FREE tier has zero quota for pro models. Use google-gemini/gemini-3-6-flash: " +
          "set SENTINELFORGE_MODEL=google-gemini/gemini-3-6-flash in .env and restart, or enable billing on your AI Studio project."
        );
      }
    return msg.split("\n")[0] + " -> provider rate limit hit; wait, switch model via SENTINELFORGE_MODEL, or enable billing.";
  }
  return message;
}
