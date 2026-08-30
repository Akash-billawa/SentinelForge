# Architecture

## Components

```text
┌──────────────────────────────────────────────────────────────┐
│                        TrueForge (harness)                    │
│   agent loop · MCP client · approvals · subagents · sessions │
└───────────────┬───────────────────────────┬──────────────────┘
                │ streamable-http           │ SDK events
     ┌──────────▼─────────┐       ┌─────────▼──────────┐
     │ SentinelForge MCP   │       │ app/ mission control│
     │ server (Python)     │       │ CLI + web console   │
     └──────────┬─────────┘       └────────────────────┘
                │ reads
     ┌──────────▼──────────────────────────────┐
     │ scenarios/powershell_c2_beaconing/      │
     │ sandbox/analyzers (static, no execute)  │
     │ state/ (incident JSON + audit + mock    │
     │         endpoint registry)              │
     └─────────────────────────────────────────┘
```

## Request lifecycle

1. `serve-ui.mjs` creates a TrueForge session with the inline
   SOC Commander AgentSpec (`agent/schemas/agentspec.sentinelforge.json`).
2. Kickoff turn: "load the alert for scenario X and investigate". The prompt
   contains no answers - discovery happens via tools.
3. Commander spawns subagent threads per specialist. Each specialist's task
   text restricts it to its own toolset.
4. Tool calls hit the MCP server; responses carry stable evidence refs
   (`windows_events:evt_0193`, `flows:flow_0101`, ...).
5. Findings are persisted with `record_finding`; IOCs with `add_iocs_to_incident`.
6. Fusion: `correlate_evidence` groups by category, counts contributing agents;
   `calculate_risk_score` applies fixed weights (section R of the blueprint).
7. If score >= 70 -> recommendation = isolate_endpoint ->
   `request_response_authorization` sets PENDING ->
   Commander calls `isolate_endpoint`.
8. **TrueForge checkpoint** - harness emits `tool.approval_required` and ends
   the turn. The console renders the decision panel.
9. Operator decision resumes a new turn with `user.tool_approval`
   allow/deny. On allow, the tool verifies incident authorization, mutates the
   MOCK registry, records CONTAINED; on deny the call never executes and
   `record_human_decision("DENY")` closes the loop.
10. `finalize_incident_report` freezes findings/evidence/risk/response into
    the final report.

## State model

Incident phases follow the blueprint state machine:

```text
NEW → INVESTIGATING → EVIDENCE_READY → ASSESSMENT_READY
    → WAITING_FOR_APPROVAL → CONTAINED | DENIED → CLOSED
```

Illegal transitions raise errors that surface to the agent as tool failures,
so the model cannot skip the approval phase even if prompted to.

## Evidence traceability

Every conclusion chains: Conclusion → Finding(s) → Evidence refs → Original
records. The audit timeline (`state/audit/<id>.jsonl`) is appended by every
tool call - nothing is fabricated after the fact.
