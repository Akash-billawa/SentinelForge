/** SentinelForge app configuration and SOC Commander AgentSpec builder. */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";

const APP_DIR = path.dirname(fileURLToPath(import.meta.url));
// this file lives in app/lib/, so the repo root is two levels up
export const REPO_ROOT = path.resolve(APP_DIR, "..", "..");

/** Minimal .env loader so SENTINELFORGE_* settings work without extra deps. */
function loadDotEnv() {
  const envPath = path.join(REPO_ROOT, ".env");
  let raw;
  try {
    raw = readFileSync(envPath, "utf8");
  } catch {
    return;
  }
  for (const line of raw.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const eq = trimmed.indexOf("=");
    if (eq <= 0) continue;
    const key = trimmed.slice(0, eq).trim();
    const value = trimmed.slice(eq + 1).trim().replace(/^["']|["']$/g, "");
    if (!(key in process.env)) process.env[key] = value;
  }
}
loadDotEnv();

export const config = {
  trueforgeBaseUrl: process.env.TRUEFORGE_BASE_URL ?? "http://localhost:8790",
  model: process.env.SENTINELFORGE_MODEL ?? "google-gemini/gemini-3-6-flash",
  mcpUrl:
    process.env.SENTINELFORGE_MCP_URL ??
    `http://127.0.0.1:${process.env.SENTINELFORGE_MCP_PORT ?? 8765}/mcp`,
  uiPort: Number(process.env.SENTINELFORGE_UI_PORT ?? 8090),
  scenario: process.env.SENTINELFORGE_SCENARIO ?? "powershell_c2_beaconing",
};

/** Build the inline AgentSpec for the SOC Commander from agent/ files. */
export function buildCommanderSpec() {
  const specFile = JSON.parse(
    readFileSync(path.join(REPO_ROOT, "agent", "schemas", "agentspec.sentinelforge.json"), "utf8"),
  );
  const instructions = readFileSync(
    path.join(REPO_ROOT, "agent", "prompts", "commander.md"),
    "utf8",
  );
  const server = specFile.mcp_servers[0];
  return {
    model: { name: config.model, params: specFile.model.params },
    instructions,
    mcp_servers: [
      {
        name: server.name,
        url: config.mcpUrl,
        enable_tools: server.enable_tools,
        require_approval_for_tools: server.require_approval_for_tools,
      },
    ],
    config: specFile.config,
  };
}

/** The kickoff prompt that starts an investigation (never contains the answer). */
export function kickoffPrompt(scenario = config.scenario) {
  return [
    "A new security alert arrived in the SOC queue.",
    `Load it with get_alert for scenario "${scenario}" and investigate it end-to-end.`,
    "Efficiency rules: create the incident session YOURSELF first (do not delegate",
    "that, and do not spawn subagents to inspect tool schemas - you already have",
    "the tools). Then delegate the three specialists in parallel, record their",
    "findings with record_finding, record every discovered indicator with",
    "add_iocs_to_incident, then correlate, calculate risk, and request human",
    "authorization before any consequential action.",
    "Finish with the incident report and a concise summary to me.",
  ].join(" ");
}

/**
 * Ensure the SentinelForge MCP server is registered as a TrueForge connector.
 * Agents reference connectors BY NAME - an unregistered name is rejected with
 * 422 at session creation. Idempotent: re-PUT only when missing or URL changed.
 */
export async function ensureMcpServerRegistered(baseUrl, name, url, description) {
  const base = baseUrl.replace(/\/$/, "");
  let existing = [];
  try {
    const res = await fetch(`${base}/api/v1/settings/mcp-servers`);
    if (res.ok) existing = (await res.json())?.data ?? [];
  } catch {
    /* reachability already handled by preflightModel */
  }
  const match = existing.find((s) => s?.manifest?.name === name);
  if (match && match.manifest.url === url) {
    return { changed: false };
  }
  const put = await fetch(`${base}/api/v1/settings/mcp-servers`, {
    method: "PUT",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      manifest: { type: "remote", name, url, description },
    }),
  });
  if (!put.ok) {
    throw new Error(
      `Failed to register MCP server "${name}" with TrueForge: HTTP ${put.status} ${await put.text()}`,
    );
  }
  return { changed: true };
}

/**
 * Preflight the configured model against the running TrueForge server.
 * Catches "provider not configured" and free-tier quota traps (e.g. choosing
 * gemini-3.1-pro-preview on a Gemini free key - its quota is literally 0)
 * BEFORE burning an agent turn on a guaranteed failure.
 */
export async function preflightModel(baseUrl, model) {
  let payload;
  try {
    const res = await fetch(`${baseUrl.replace(/\/$/, "")}/api/v1/models`);
    if (!res.ok) return { ok: true, note: `models endpoint HTTP ${res.status}; skipping check` };
    payload = await res.json();
  } catch (err) {
    return { ok: false, reason: `TrueForge is not reachable at ${baseUrl}. Start it with: node scripts/run-trueforge.mjs` };
  }
  const models = Array.isArray(payload?.data) ? payload.data : [];
  const ids = models
    .map((m) => m?.name ?? m?.id ?? m?.model_id ?? null)
    .filter((x) => typeof x === "string");

  if (ids.length === 0 && models.length === 0) {
    return {
      ok: false,
      reason:
        "No model providers are configured in TrueForge. Open http://localhost:8790 -> Settings -> Models, add a provider + API key, then retry.",
    };
  }

  const bare = model.includes("/") ? model.split("/").pop() : model;
  if (ids.length > 0 && !ids.some((id) => id === model || id.endsWith(`/${bare}`) || id === bare)) {
    return {
      ok: false,
      reason:
        `Configured model "${model}" was not found among TrueForge models [${ids.join(", ")}]. ` +
        `Fix: set SENTINELFORGE_MODEL to one of those ids in .env (free Gemini keys must use google/gemini-3.6-flash - pro models have zero free-tier quota), or enable billing for "${model}".`,
    };
  }
  return { ok: true, models: ids };
}
