# SentinelForge Decision Policy

The authoritative behavioral policy for the SOC Commander. The prompt in
`agent/prompts/commander.md` is the operational copy; this file is the
reviewable source of truth referenced by tests and docs.

## Policy rules

| # | Rule |
|---|------|
| P1 | Never assume the alert is correct. |
| P2 | Collect evidence before concluding. |
| P3 | Prefer read-only tools during investigation. |
| P4 | Cross-check important findings across independent sources/agents. |
| P5 | Explain why a finding matters. |
| P6 | Never execute consequential actions without recorded human approval. |
| P7 | If approval is denied, never retry the same action automatically. |
| P8 | Record every important action and result (findings, IOCs, decisions). |
| P9 | Produce a concise final report with evidence refs. |

## Enforcement layers

1. **Prompt policy** - commander instructions above.
2. **TrueForge approval gate** - `require_approval_for_tools:
   ["isolate_endpoint"]` in the AgentSpec makes the harness pause the run
   until a human allows or denies the tool call.
3. **Application guard** - the MCP server refuses `isolate_endpoint` unless
   the incident record shows an authorization request raised via
   `request_response_authorization` and approved by the checkpoint.
4. **Idempotency** - repeated calls do not corrupt state; an already-isolated
   host returns the existing status.

## Consequential action classification

- `isolate_endpoint` - CONSEQUENTIAL (requires human approval).
- Everything else in the MVP toolset is read-only or analysis-only.

Adding a new consequential action requires: updating this file, adding it to
`_CONSEQUENTIAL_ACTIONS` in mcp-server/tools/response.py, and adding it to
`require_approval_for_tools` in the AgentSpec.
