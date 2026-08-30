# SentinelForge

**AI SOC Incident Commander for safe, evidence-driven response.**
*Investigate autonomously. Act only with permission.*

SentinelForge receives a security alert, opens an incident session, and
delegates the investigation to specialist subagents (Log, Network, Malware).
They collect evidence through real MCP tool calls against a deterministic
synthetic dataset, a sandboxed static analyzer decodes the suspicious
artifact, the Commander fuses and cross-checks findings, produces transparent
risk scoring — and then **stops**. Endpoint isolation is consequential, so the
agent pauses at a human approval checkpoint. Only APPROVE lets the controlled
containment execute; DENY closes the loop with no action taken.

```text
Security Alert → SentinelForge Agent → Autonomous Investigation
      ↓ Subagents + MCP Tools + Sandbox
Evidence Correlation → Risk / Confidence
      ↓
Human Approval Checkpoint  ──DENY──▶ No Action (recorded)
      │ APPROVE
      ▼
Containment (mock endpoint) → Incident Report
```

## What problem does it solve?

SOC analysts receive alerts faster than they can investigate them. An alert is
only a starting signal: someone still has to pull logs, reconstruct the
process tree, inspect DNS/flow behavior, decode artifacts, correlate evidence,
and choose a response. Fully automating that last step is dangerous — an agent
that can act on endpoints without control can make an incident worse.
SentinelForge demonstrates the two-sided answer:

> Investigation can be autonomous. Irreversible response remains human-controlled.

## Architecture

See [docs/architecture.md](docs/architecture.md). Short version:

```text
sentinelforge/
├── mcp-server/    Python MCP server (streamable-http): logs, DNS, flows,
│                  process tree, IOCs, analysis tools + mock response registry
├── sandbox/       Static PowerShell analyzer (never executes samples)
├── scenarios/     Deterministic synthetic incident package
├── agent/         Commander prompt, specialist prompts, policy, JSON schemas
├── app/           Mission control: agent driver + web console
└── tests/         Unit / integration (real MCP over HTTP) / scenario replay
```

## How do I run it?

Prerequisites: Python 3.11+, Node.js 22+, any OpenAI-compatible API key.

```bash
# 1. Python deps
python -m venv .venv
.\.venv\Scripts\pip install "mcp>=1.2.0" pytest httpx   # Windows
# pip install "mcp>=1.2.0" pytest httpx                  # Linux/macOS

# 2. SentinelForge MCP server (terminal 1)
.\.venv\Scripts\python mcp-server\server.py
#   -> http://127.0.0.1:8765/mcp

# 3. Start the agent runtime (terminal 2) - works on Windows, macOS and Linux
node scripts\run-trueforge.mjs        # node scripts/run-trueforge.mjs on *nix
#   -> http://localhost:8790
# In Settings -> Models add your provider/API key.

# 4a. CLI demo (terminal 3)
cd app && npm i @truefoundry/trueforge-sdk && node run-demo.mjs --approve

# 4b. Web console instead
cd app && node serve-ui.mjs   # open http://localhost:8090, click START INVESTIGATION
```

## How do I reproduce the demo?

1. Start the three processes above.
2. Web console: click **START INVESTIGATION**. Watch subagents spawn, MCP tool
   calls stream, evidence refs accumulate.
3. At `Risk >= 70` the Commander recommends isolation; the runtime pauses and
   the console shows the checkpoint. Click **APPROVE** (mock endpoint becomes
   ISOLATED, report finalizes) or **DENY** (no action, decision recorded).
4. Reset & replay anytime: `reset_demo` tool or restart the console.

CLI equivalent: `node run-demo.mjs` prompts at the checkpoint;
`--approve` / `--deny` automate it for CI.

## What safety controls exist?

Four independent layers (details: [docs/security-model.md](docs/security-model.md)):

1. Prompt-level decision policy (`agent/policies/decision_policy.md`).
2. Runtime-enforced human checkpoint on the single consequential tool.
3. Application guard: the MCP tool refuses isolation unless the incident shows
   a raised authorization request approved by the checkpoint.
4. Demo-safety: all data synthetic (RFC-2606 `.example` domains, TEST-NET IPs),
   the analyzer never executes artifacts, and `isolate_endpoint` mutates only a
   mock endpoint registry. Idempotent by design.

## Tests

```bash
.\.venv\Scripts\python -m pytest tests   # unit + integration + scenario replay
.\.venv\Scripts\python scripts\smoke_test.py   # tool registration + dataset spot-checks
node scripts\test-preflight.mjs          # model preflight guidance
node scripts\test-mcp-client.mjs         # MCP transport (202/SSE/tool errors)
```

The Python suite covers the data layer, state machine and MCP server over real
HTTP; the Node scripts cover the console's transport and preflight logic, which
pytest never exercises.

## Limitations

- One incident scenario (`powershell_c2_beaconing`) by design: depth over breadth.
- Containment targets a mock registry, deliberately - this is a control-loop demo.
- Risk weights are fixed public policy, tuned for the demo scenario only.
- The sandbox analyzer is static; dynamic execution is intentionally out of scope.
- On Windows, TrueForge's local sandbox fallback is unavailable (upstream
  supports macOS/Linux only). This does not affect the demo: artifact analysis
  is static and runs inside our MCP server, not in a harness sandbox.

## Troubleshooting (Windows)

`npx @truefoundry/trueforge` fails on native Windows with
`ERR_UNSUPPORTED_ESM_URL_SCHEME ... Received protocol 'c:'`. This is an upstream
bug: kysely 0.29.5's `FileMigrationProvider` calls `await import("C:\\...")`,
and Node's ESM loader requires `file://` URLs for absolute paths.

`scripts/run-trueforge.mjs` works around it automatically - it installs
TrueForge locally, applies the one-line `pathToFileURL()` fix to the bundled
kysely copy (idempotent, correct on all platforms), and starts the server.
Alternatives: WSL or Docker Compose from the upstream repository.

## Troubleshooting (model provider)

The console runs a preflight check before every investigation and fails fast
with actionable guidance if the provider/model is misconfigured.

- **Gemini free tier**: pro models have ZERO quota (`limit: 0`) - use
  `google-gemini/gemini-3-6-flash`. Note TrueForge exposes Google models under
  the `google-gemini/` prefix with dash-form names; copy the exact id from the
  preflight error message into `.env`:
  `SENTINELFORGE_MODEL=google-gemini/gemini-3-6-flash`
- **No providers configured**: open `http://localhost:8790` -> Settings ->
  Models and add a provider key first.
- A 429 mid-run is surfaced in the timeline with a targeted hint instead of a
  raw stack trace.

## Disclosure

Built during The Agent Harness Hackathon. AI coding assistants were
used for implementation speed; the participant reviewed, understands, and can
explain all submitted code.

**Synthetic data authorship:** every file under `scenarios/powershell_c2_beaconing/`
- the alert, Windows event log, DNS log, network flow log, process tree, IOC feed,
threat-intel verdicts, expected-findings ground truth, and the suspicious
`win_update.ps1` script - was written by the participant as a realistic-but-fake
incident package. Destinations use RFC-2606 `.example` domains and TEST-NET IP
ranges, and the script's decoded payload is a literal `SYNTHETIC-DEMO-PAYLOAD`
marker, so no real host, network, or code is touched. The unit test
`test_no_real_internet_hosts_in_dataset` enforces this; the scenario-replay
test `tests/scenario/test_replay.py` re-derives the findings from the dataset
and asserts they match `expected_findings.json` (the demo is deterministic and
tamper-evident). The agent itself still runs every step for real against this
controlled data.

## License

MIT
