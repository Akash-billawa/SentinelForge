# Sample Run - real end-to-end investigation record

Artifacts captured from a live, unattended investigation
(auto-launched via the incident console on a TrueForge + OpenRouter
stealth/ox-alpha stack):

- `incident.json` - the final IncidentSession: 21 findings, 20+ evidence
  refs, 5 IOCs, transparent risk 100/100 CRITICAL, human-approved
  isolation (mock registry), and the frozen final report with an
  evidence-chained conclusion and honest residual-uncertainty notes.
- `audit-trail.jsonl` - chronological tool-level audit trail appended
  by the MCP server during the run (nothing is written after the fact).
- `endpoint-registry.json` - the mock endpoint state showing WKS-042
  ISOLATED (the entire blast radius of the consequential action).

The agent never received the scenario answers: every conclusion cites
evidence refs discovered through MCP tool calls, and the only
consequential action paused at TrueForge's human approval checkpoint.
