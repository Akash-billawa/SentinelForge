# Demo Script (~3 minutes)

## 0:00-0:20 - The problem

Show the alert (`scenarios/.../alert.json` or the console header).

> "A SOC analyst doesn't need another chatbot. They need an investigator that
> collects evidence, runs analysis, and stops before a risky action. This alert
> isn't the investigation - SentinelForge turns it into a controlled workflow."

## 0:20-0:45 - Agent begins

Click **START INVESTIGATION** in `http://localhost:8090`.   node app\serve-ui.mjs → open http://localhost:8090

Narrate: TrueForge opens a session for INC-2026-0042; the Commander plans the
investigation. Point at the status chip and the first timeline entries.

## 0:45-1:20 - Delegation (the proof)

As events stream:

- `thread.created` x3 -> Log / Network / Malware investigators appear in the tree.
- MCP calls visible: `search_windows_logs`, `search_dns_logs`,
  `search_network_flows`, `analyze_powershell`.
- Evidence refs land in the evidence panel.

> "Real tool calls through MCP - logs, DNS, flows - and a sandboxed analyzer
> that decodes the artifact without executing it."

## 1:20-1:50 - Evidence fusion

Findings recorded; risk computed with fixed public weights.

```text
PowerShell + encoded command   +40
Suspicious DNS                 +15
Beacon behavior                +20
Threat-intel match             +10
Artifact analysis              +15  => CRITICAL
```

> "Risk is explainable - every point maps to a cited finding."

## 1:50-2:20 - The safety gate (the moment)

TrueForge pauses: `tool.approval_required` for `isolate_endpoint`. The APPROVE
button unlocks.

> "The agent wants to isolate WKS-042. It cannot. Consequential actions wait
> for a human - this checkpoint is enforced by the harness, not by politeness."

Click **APPROVE**.

## 2:20-2:40 - Response

Endpoint registry flips to ISOLATED (mock, idempotent); incident phase ->
CONTAINED -> CLOSED; report finalized with full evidence chain.

## 2:40-3:00 - Close

Show `docs/architecture.md` diagram briefly.

> "TrueForge is the runtime layer: it runs the agent loop, connects MCP tools,
> spawns specialist subagents, keeps session state, and enforces the human
> checkpoint before consequential actions. SentinelForge investigates
> autonomously - and acts only with permission."

## Failure recovery

| Breaks | Do |
|---|---|
| Tool call fails | Show the error event; Commander recovers via another read-only path |
| Sandbox fails | Say so honestly; fall back to precomputed scenario evidence, labelled as fallback |
| UI fails | Run `node run-demo.mjs --approve` (same flow, terminal) |
| Approval breaks | Never bypass - demonstrate the DENY path instead |

## Rehearsal notes

- Reset state before recording: restart console (fresh session) or `reset_demo`.
- Keep the checkpoint click deliberate - it is the money shot.
- Do not tour features; one story, three minutes.
