# SentinelForge

SentinelForge is an AI SOC Incident Commander for evidence-driven security
incident response. It investigates alerts across logs, process trees, DNS,
network flows, threat intelligence, and suspicious PowerShell artifacts, then
produces a traceable risk assessment and incident report.

> Investigate autonomously. Act only with permission.

This project was built for [The Agent Harness Hackathon](https://www.wemakedevs.org/hackathons/trueforge).
The domain is cybersecurity, but the central problem is broadly useful:
agents need real tools, safe execution, and a human stop before an irreversible
action.

## The problem

SOC analysts receive more alerts than they can investigate manually. An alert
is only a starting point: analysts still need to reconstruct the process chain,
inspect DNS and flow behavior, analyze artifacts, correlate evidence, and
decide how to respond.

SentinelForge automates the investigation while keeping containment under
human control. It is intended for SOC analysts, incident responders, and
security engineering teams.

## How it works

```text
Security alert
      |
      v
Commander agent --> Log investigator
                --> Network investigator
                --> Malware investigator
      |
      v
Evidence correlation --> Transparent risk score
      |
      v
Human approval checkpoint
      | APPROVE                 | DENY
      v                         v
Mock endpoint isolation     No action; decision recorded
      |
      v
Final incident report
```

The Commander discovers the answer through MCP tool calls; the scenario
answers are not placed in its prompt. Each conclusion links to findings and
stable evidence references. A persisted state machine prevents the agent from
skipping investigation, authorization, or reporting steps.

## Hackathon requirements demonstrated

- **Real tools:** a Python MCP server exposes logs, DNS, network flows, process
  trees, IOCs, static artifact analysis, and a response registry.
- **Subagents:** Log, Network, and Malware investigators work on bounded parts
  of the investigation.
- **Safe execution:** PowerShell samples are statically inspected and never
  executed. The response target is a mock endpoint registry.
- **Human control:** the agent pauses before `isolate_endpoint`; only an
  explicit approval can continue containment.
- **Session continuity:** one incident maps to one persisted session, including
  findings, risk, response decisions, and an append-only audit trail.
- **Open source and reproducible:** the included dataset is deterministic and
  uses synthetic `.example` domains and TEST-NET IP ranges.

## Example result

The included `powershell_c2_beaconing` scenario contains an unsigned,
obfuscated PowerShell artifact with persistence and machine-precision HTTPS
beaconing. SentinelForge correlates the independent evidence sources,
calculates a transparent `100/100 CRITICAL` risk score, requests approval, and
isolates only the mock endpoint after approval.

See the [sample incident report](docs/sample-run/incident.json) and
[audit trail](docs/sample-run/audit-trail.jsonl).

## Project structure

```text
sentinelforge/
├── mcp-server/    Python MCP server and security data tools
├── sandbox/       Static PowerShell analyzer; never executes samples
├── scenarios/     Deterministic synthetic incident package
├── agent/         Commander and specialist prompts, policy, and schemas
├── app/           Mission control CLI and web console
└── tests/         Unit, integration, and scenario-replay tests
```

## Run locally

Requirements: Python 3.11+, Node.js 22+, and an OpenAI-compatible model API
key.

```bash
# Install Python dependencies
python -m venv .venv
.\\.venv\\Scripts\\pip install "mcp>=1.2.0" pytest httpx

# Terminal 1: start the SentinelForge MCP server
.\\.venv\\Scripts\\python mcp-server\\server.py

# Terminal 2: start the TrueForge agent runtime
node scripts\\run-trueforge.mjs

# Terminal 3: run the CLI demo
cd app
npm install
npm install @truefoundry/trueforge-sdk
node run-demo.mjs --approve
```

For the web console, run `node serve-ui.mjs` from `app` and open
`http://localhost:8090`. At the approval checkpoint, choose **APPROVE** to
contain the mock endpoint or **DENY** to close the incident without action.

## Tests

```bash
.\\.venv\\Scripts\\python -m pytest tests
.\\.venv\\Scripts\\python scripts\\smoke_test.py
node scripts\\test-preflight.mjs
node scripts\\test-mcp-client.mjs
```

The Python tests cover the state machine, data layer, MCP server over HTTP, and
scenario replay. The Node tests cover the console transport and model
preflight behavior.

## Qodo Code Review Evidence

Qodo was used to review substantive implementation changes for edge cases in
the incident state machine, authorization flow, MCP boundaries, error
handling, and test coverage. Findings were used to improve validation,
idempotency, and scenario tests.

The hackathon requires a representative merged pull request with the Qodo
review, decisions, remediation, and follow-up review. The repository's review
history is available at [GitHub Pull Requests](https://github.com/Akash-billawa/SentinelForge/pulls).
Add the final representative merged PR link here before submission.

## Demo

The recommended three-minute flow is documented in
[docs/demo-script.md](docs/demo-script.md).

## Safety and limitations

- All incident data is synthetic and safe to replay.
- The analyzer is static; dynamic malware execution is intentionally out of
  scope.
- Containment changes only a mock endpoint registry.
- Risk weights are fixed, transparent, and tuned to the included scenario.
- The project currently focuses on one deep scenario:
  `powershell_c2_beaconing`.

## Disclosure

AI coding assistants were used for implementation speed. The participant
reviewed the project, understands the architecture and technical decisions,
and can explain all submitted code.

## License

MIT
