#!/usr/bin/env node
/**
 * SentinelForge CLI demo driver.
 *
 *   node run-demo.mjs                 # run investigation; prompt at the checkpoint
 *   node run-demo.mjs --approve       # auto-approve at the checkpoint
 *   node run-demo.mjs --deny          # auto-deny  at the checkpoint
 *
 * Requires: TrueForge running (npx @truefoundry/trueforge) with a model
 * provider configured, and the SentinelForge MCP server running.
 */

import { createInterface } from "node:readline/promises";
import { MissionControl } from "./lib/mission-control.mjs";
import { config } from "./lib/config.mjs";

const args = new Set(process.argv.slice(2));
const autoDecision = args.has("--approve") ? "approve" : args.has("--deny") ? "deny" : null;

const dim = (s) => `\x1b[2m${s}\x1b[0m`;
const bold = (s) => `\x1b[1m${s}\x1b[0m`;
const red = (s) => `\x1b[31m${s}\x1b[0m`;
const green = (s) => `\x1b[32m${s}\x1b[0m`;
const cyan = (s) => `\x1b[36m${s}\x1b[0m`;

function render(evt) {
  const t = evt.at ? new Date(evt.at).toLocaleTimeString("en-GB", { hour12: false }) : "";
  switch (evt.type) {
    case "console":
    case "harness":
      console.log(dim(`[${t}] `) + cyan(`TrueForge: ${evt.text}`));
      break;
    case "subagent_start":
      console.log(dim(`[${t}] `) + bold(`  -> delegate: ${evt.text.replace("Delegated -> ", "")}`));
      break;
    case "subagent_done":
      console.log(dim(`[${t}] `) + `  <- ${evt.text}`);
      break;
    case "tool_call": {
      const argStr = Object.keys(evt.args ?? {}).length
        ? dim(JSON.stringify(evt.args).slice(0, 120))
        : "";
      console.log(
        dim(`[${t}] `) +
          `${evt.threadId === "main" ? "Commander" : "Specialist"} calls ${bold(evt.tool)} ${argStr}`,
      );
      break;
    }
    case "tool_result":
      if (evt.evidence.length) console.log(dim(`[${t}] `) + green(`     evidence ${evt.evidence.join(", ")}`));
      else console.log(dim(`[${t}] `) + dim("     result received"));
      break;
    case "agent_message":
      console.log(
        dim(`[${t}] `) + `${evt.threadId === "main" ? bold("Commander:") : dim("specialist:")} ${evt.text.slice(0, 400)}${evt.text.length > 400 ? dim("...") : ""}`,
      );
      break;
    case "approval_required":
      console.log("\n" + red(bold("  ============================================================")));
      console.log(red(bold("   HUMAN CHECKPOINT - CONSEQUENTIAL ACTION REQUESTED")));
      for (const tc of evt.toolCalls ?? []) {
        console.log(red(`   tool: ${tc.name}`));
        console.log(red(`   args: ${JSON.stringify(tc.args)}`));
      }
      console.log(red(bold("  ============================================================")) + "\n");
      break;
    case "decision":
      console.log((evt.level === "approve" ? green : red)(`\n[${t}] ${evt.text}\n`));
      break;
    default:
      break;
  }
}

async function main() {
  console.log(bold("\nSentinelForge") + dim(" - investigate autonomously, act only with permission\n"));
  console.log(dim(`TrueForge : ${config.trueforgeBaseUrl}`));
  console.log(dim(`MCP tools : ${config.mcpUrl}\n`));

  const mc = new MissionControl({ logPath: null });
  mc.subscribe(render);

  try {
    await mc.start();
  } catch (err) {
    console.error(red(`Failed to start investigation: ${err.message}`));
    process.exit(1);
  }

  while (mc.status === "WAITING_FOR_APPROVAL") {
    let decision = autoDecision;
    if (!decision) {
      const rl = createInterface({ input: process.stdin, output: process.stdout });
      // readline/promises exposes question(), not ask().
      decision = await rl.question(bold("APPROVE or DENY containment? "));
      rl.close();
      decision = decision.trim().toUpperCase().startsWith("A") ? "approve" : "deny";
    }
    try {
      await mc.decide(decision === "approve");
    } catch (err) {
      console.error(red(`Turn error: ${err.message}`));
      process.exit(1);
    }
  }

  console.log(dim("\n--- audit timeline ---"));
  console.log(dim(`${mc.events.filter((e) => e.type !== "agent_message").length} events recorded.`));
  if (mc.finalReport) {
    const fr = mc.finalReport;
    console.log(green(bold(`\nIncident ${fr.incident_id} closed.`)));
    console.log(`Risk: ${fr.risk?.score}/100 (${fr.risk?.severity}) | Confidence: ${fr.confidence}`);
    console.log(`Response state: ${fr.response_state} | Approval: ${fr.approval_state}`);
  }
  console.log(dim("\nDone.\n"));
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
