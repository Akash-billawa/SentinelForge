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

/**
 * Derive the compact judge-facing report fields (headline, verdict_line,
 * top_findings, host, account, c2, beacon, persistence, evidence) from the
 * verbose final_report when the model didn't fill them in. This keeps the
 * UI's top-of-page summary meaningful even for older prompt versions that
 * only passed executive_summary and conclusion.
 */
function backfillCompactReport(report) {
  if (!report || typeof report !== "object") return report;
  const out = { ...report };
  const risk = out.risk || {};
  const findings = Array.isArray(out.findings) ? out.findings : [];
  const evidence = Array.isArray(out.evidence) ? out.evidence : [];
  const iocs = Array.isArray(out.iocs) ? out.iocs : [];
  const alert = out.alert || {};
  const score = risk.score;
  const severity = (risk.severity || "PENDING").toUpperCase();
  const scoreText = (score != null) ? `${score}/100` : "—";

  // Verdict line + headline
  if (!out.verdict_line) out.verdict_line = `${severity} — ${scoreText}`;
  if (!out.headline) {
    out.headline = score != null && score >= 70
      ? `CONFIRMED ${severity} — containment recommended`
      : `${severity} — review recommended`;
  }

  // Recommended action label
  if (!out.recommended_action_label) {
    const ra = (out.recommended_action || "monitor").toUpperCase();
    out.recommended_action_label = ra === "ISOLATE_ENDPOINT" ? "ISOLATE ENDPOINT" : (ra || "NO ACTION");
  }

  // Host / account from alert + findings text
  if (!out.host) out.host = alert.hostname || "";
  if (!out.account) {
    // Look in summary, conclusion, and all findings for service-style accounts
    const haystack = [
      out.executive_summary || "",
      out.conclusion || "",
      ...findings.map(f => (f.finding || "").toString()),
    ].join(" ");
    let m = haystack.match(/\b(?:[A-Z][\w-]{1,12}\\)?(svc_\w+|\w+_(?:backup|admin|service))\b/);
    if (m) out.account = m[1];
    if (!out.account) {
      m = haystack.match(/\b([A-Z]{2,12}\\[A-Za-z][\w.-]{2,})\b/);
      if (m) out.account = m[1];
    }
  }

  // C2 destination (IP / domain) — search across the whole report
  if (!out.c2) {
    // Prefer the IP/domain mentioned in a beacon_pattern or threat_intel_match
    // finding, since those are the real C2 destinations (not DNS resolution IPs).
    const beaconOrTI = findings.filter(f =>
      f.category === "beacon_pattern" || f.category === "threat_intel_match"
    );
    const haystacks = [
      ...beaconOrTI.map(f => (f.finding || "").toString()),
      out.executive_summary || "",
      out.conclusion || "",
      ...findings.map(f => (f.finding || "").toString()),
    ];
    let found = null;
    for (const text of haystacks) {
      const ipMatch = text.match(/\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/);
      if (ipMatch) { found = ipMatch[1]; break; }
    }
    if (!found) {
      for (const text of haystacks) {
        const domMatch = text.match(/\b([a-z0-9][a-z0-9-]+-[a-z0-9-]+\.[a-z]{2,})\b/i);
        if (domMatch) { found = domMatch[1]; break; }
      }
    }
    out.c2 = found || "—";
  }

  // Beacon pattern
  if (!out.beacon) {
    const beaconFinding = findings.find(f => f.category === "beacon_pattern");
    if (beaconFinding) {
      const text = (beaconFinding.finding || "").toString();
      // Prefer "every Ns", "N-second", "N second interval/cadence", or "N gaps"
      let m = text.match(/every\s+(\d+)\s*s(?:econds?)?/i)
            || text.match(/(\d+)\s*[-\s]*second\s+(?:interval|cadence|gaps?|beacon)/i)
            || text.match(/cadence[:\s]+(\d+)\s*s/i);
      if (m) {
        out.beacon = `every ${m[1]}s`;
      } else {
        // Fall back to the largest "Ns" that's not "sampled" / "sandbox" / "seconds total"
        const all = text.match(/\b(\d+)\s*s\b/g) || [];
        const candidates = all
          .map(s => parseInt(s))
          .filter(n => n >= 2 && n <= 600)
          .sort((a, b) => b - a);
        if (candidates.length) out.beacon = `every ${candidates[0]}s`;
        else out.beacon = "periodic";
      }
    }
  }

  // Persistence
  if (!out.persistence) {
    // Try to find a registry key in any finding (cap the captured path length)
    for (const f of findings) {
      const text = (f.finding || "").toString();
      const m = text.match(/\b(HK(?:CU|LM|CR|U|CC)(?:\\[A-Za-z0-9_\-.()]+){2,6})(?:\b|,|\.|\s|$)/);
      if (m) {
        // Truncate to a clean key without trailing prose
        let key = m[1].trim();
        if (key.length > 80) key = key.split(/[,\s]/)[0];
        out.persistence = key;
        break;
      }
    }
    // Try Scheduled Task name
    if (!out.persistence) {
      for (const f of findings) {
        const text = (f.finding || "").toString();
        const m = text.match(/\bScheduled\s+Task\s+[`"']?([A-Za-z0-9_.-]+)/i)
                || text.match(/\bTask\s+[`"']?([A-Za-z0-9_.-]+)[`"']?/i);
        if (m) { out.persistence = `Scheduled Task \\${m[1]}`; break; }
      }
    }
    // Try service name
    if (!out.persistence) {
      for (const f of findings) {
        const text = (f.finding || "").toString();
        const m = text.match(/\b(?:Service|sc create)\s+[`"']?([A-Za-z0-9_.-]{3,})[`"']?/i);
        if (m) { out.persistence = `Service: ${m[1]}`; break; }
      }
    }
    // Fall back to a descriptive label
    if (!out.persistence) {
      for (const f of findings) {
        const text = (f.finding || "").toLowerCase();
        if (text.includes("run-key") || text.includes("run key")) {
          out.persistence = "Run-key (autorun)"; break;
        }
        if (text.includes("persistence") || text.includes("persist ")) {
          out.persistence = "Persistence mechanism"; break;
        }
      }
    }
    if (!out.persistence) out.persistence = "—";
  }

  // Top findings (max 6 short bullets)
  if (!Array.isArray(out.top_findings) || out.top_findings.length === 0) {
    const priority = ["beacon_pattern", "encoded_command", "powershell_execution",
                      "suspicious_artifact", "threat_intel_match", "suspicious_dns"];
    const seen = new Set();
    const labels = {
      beacon_pattern: "C2 beacon pattern",
      encoded_command: "Encoded PowerShell",
      powershell_execution: "Suspicious PowerShell execution",
      suspicious_artifact: "Suspicious on-disk artifact",
      threat_intel_match: "Threat-intel match",
      suspicious_dns: "Suspicious DNS",
    };
    const ordered = priority
      .map(cat => findings.find(f => f.category === cat))
      .filter(f => f && !seen.has(f.finding) && seen.add(f.finding));
    out.top_findings = ordered.slice(0, 6).map(f => labels[f.category] || f.category);
  }

  // User-facing evidence labels (max 6)
  if (!Array.isArray(out.evidence) || out.evidence.length === 0) {
    out.evidence = (out.top_findings || []).slice(0, 6);
  }

  return out;
}

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
  /** tool-call id -> normalized call metadata across turns. */
  #toolCalls = new Map();

  constructor({ logPath = null } = {}) {
    this.logPath = logPath;
    this.sessionId = null;
    this.events = []; // normalized UI events
    this.pendingApproval = null; // { threadId, toolCalls: [{id,name,args}] }
    this.status = "IDLE"; // IDLE|INVESTIGATING|RETRYING|WAITING_FOR_APPROVAL|CONTAINED|DENIED|CLOSED|ERROR
    this.lastEventAt = Date.now();
    this.subscribers = new Set();
    this.incidentId = null;
    this.finalReport = null;
    this.riskAssessment = null;
  }

  #emit(evt) {
    this.lastEventAt = Date.now();
    const record = { seq: this.events.length + 1, at: new Date().toISOString(), ...evt };
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
    const toolEvents = this.events.filter((event) => event.type === "tool_call");
    const toolResults = this.events.filter((event) => event.type === "tool_result");
    const evidenceCount = new Set(
      this.events.flatMap((event) => Array.isArray(event.evidence) ? event.evidence : []),
    ).size;
    return {
      status: this.status,
      sessionId: this.sessionId,
      incidentId: this.incidentId,
      pendingApproval: this.pendingApproval,
      finalReport: this.finalReport,
      events: this.events,
      // Some TrueForge/provider combinations omit the assistant's persisted
      // model.message tool_calls but still emit tool.response. Count those
      // results too so the console never reports zero tools after real MCP
      // activity.
      toolCount: Math.max(toolEvents.length, toolResults.length),
      evidenceCount,
    };
  }

  /** Resolve a pending approval's tool name/args from stream-merged data. */
  #resolvePendingToolCalls(pending) {
    return (pending.toolCalls ?? []).map((ref) => {
      let name = "unknown";
      let rawArgs = null;
      const msg = this.#eventsIndex.get(ref.sourceEventId);
      const call = (msg?.toolCalls ?? msg?.tool_calls ?? msg?.message?.toolCalls ?? msg?.message?.tool_calls ?? [])
        .find((tc) => tc.id === ref.id);
      if (call) {
        name = call.toolInfo?.name ?? call.function?.name ?? call.name ?? name;
        rawArgs = call.function?.arguments ?? call.arguments;
      }
      const remembered = this.#toolCalls.get(ref.id);
      if (remembered) {
        name = remembered.name || name;
        rawArgs = remembered.args ?? rawArgs;
      }
      if (name === "unknown") {
        // Live streams carry tool calls as delta fragments merged in #msgAcc.
        const acc = this.#msgAcc.get(ref.sourceEventId);
        const slot =
          acc?.calls?.find((c) => c.id === ref.id) ??
          acc?.calls?.find((c) => c.name) ??
          null;
        if (slot?.name) {
          name = slot.name;
          rawArgs = slot.args;
        }
      }
      let args = {};
      try {
        args = JSON.parse(rawArgs || "{}");
      } catch {
        args = { _raw: String(rawArgs ?? "").slice(0, 200) };
      }
      // Deferred-tool harnesses wrap real tools in call_tool(mcp_server,
      // tool_name, arguments) - surface the INNER tool for humans.
      if ((name === "call_tool" || name === "call-group-tool") && args.tool_name) {
        name = args.tool_name;
        if (args.arguments !== undefined) {
          try {
            args = typeof args.arguments === "string" ? JSON.parse(args.arguments) : args.arguments;
          } catch {
            /* keep wrapper args */
          }
        }
      }
      return { id: ref.id, name, args };
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
    this.#toolCalls.clear();
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

  /**
   * Resume a stalled investigation on the existing session (e.g. after a
   * server-execution-timeout cancelled the turn). The agent keeps its full
   * session context, so a single continuation prompt is enough.
   */
  async resume() {
    if (!this.client || !this.sessionId) throw new Error("no session to resume");
    if (this.status === "INVESTIGATING" || this.status === "RETRYING") {
      const idleForMs = Date.now() - this.lastEventAt;
      if (idleForMs < 90_000) {
        throw new Error(`turn looks alive (last event ${Math.round(idleForMs / 1000)}s ago)`);
      }
      // Stale stream: treat as dead and resume on the same session.
    }
    this.pendingApproval = null;
    this.status = "INVESTIGATING";
    this.#emit({
      type: "console",
      level: "info",
      text: `Resuming session ${this.sessionId} from where it stopped...`,
    });
    await this.#runTurn([
      {
        type: "user.message",
        content:
          "Continue the investigation from exactly where you stopped. Complete the remaining workflow steps: if risk >= 70 request human authorization via request_response_authorization, attempt isolate_endpoint (TrueForge will pause for the human checkpoint), record the human decision if denied, and finish with finalize_incident_report plus a concise summary.",
      },
    ]);
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
    const runSeq = this.#runSeq;
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
        if (runSeq !== this.#runSeq) return; // console was reset while we waited
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
        const tool = call.name ?? "unknown";
        if (call.id) this.#toolCalls.set(call.id, { name: tool, args: args });
        this.#emit({
          type: "tool_call",
          text: tool,
          tool,
          callId: call.id,
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
        (event.toolCalls ?? event.tool_calls ?? event.message?.toolCalls ?? event.message?.tool_calls ?? []).forEach((frag, i) => {
          const slot = (acc.calls[i] ??= { id: null, name: null, args: "" });
          if (!slot.id && frag?.id) slot.id = frag.id;
          const name = frag?.function?.name ?? frag?.toolInfo?.name;
          if (name && !slot.name) slot.name = name;
          if (typeof frag?.function?.arguments === "string") slot.args += frag.function.arguments;
        });
        this.#msgAcc.set(event.id, acc);
        break;
      }
      case "model.message": {
        const rawContent = event.content ?? event.message?.content;
        const content = typeof rawContent === "string" ? rawContent : "";
        const calls = event.toolCalls ?? event.tool_calls ?? event.message?.toolCalls ?? event.message?.tool_calls ?? [];
        for (const call of calls) {
          let args = {};
          try {
            args = JSON.parse(call.function?.arguments ?? call.arguments ?? "{}");
          } catch {
            /* keep empty */
          }
          const tool = call.toolInfo?.name ?? call.function?.name ?? call.name ?? "?";
          if (call.id) this.#toolCalls.set(call.id, { name: tool, args });
          this.#emit({
            type: "tool_call",
            threadId: event.threadId,
            text: tool,
            tool,
            callId: call.id,
            args,
          level: String(tool).includes("isolate") ? "danger" : "info",
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
          parsed = typeof event.content === "string" ? JSON.parse(event.content) : event.content;
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
          toolCallId: event.toolCallId ?? event.tool_call_id,
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
        // finalize_incident_report returns the report FLAT (no wrapper key).
        // Only looking for parsed.final_report meant the run never reached
        // CLOSED, so the CLI and auto-demo waited forever for a finished run.
        const report = parsed?.final_report ?? (isFinalReport(parsed) ? parsed : null);
        if (report) {
          this.finalReport = backfillCompactReport(report);
          this.status = "CLOSED";
        }
        break;
      }
      case "tool.approval_required": {
        this.status = "WAITING_FOR_APPROVAL";
        const toolCalls = this.#resolvePendingToolCalls(event);
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

/** Recognize a finalize_incident_report payload by its required fields. */
function isFinalReport(payload) {
  return Boolean(
    payload &&
      typeof payload === "object" &&
      payload.incident_id &&
      typeof payload.executive_summary === "string" &&
      typeof payload.conclusion === "string",
  );
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
