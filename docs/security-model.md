# Security Model

## Threat model for this project

SentinelForge itself must not become a risk. The application enforces an agent control
loop; it must never touch real systems, real data, or execute untrusted code.

## Data guarantees

- **Synthetic only.** All logs, DNS, flows and artifacts are generated files
  under `scenarios/`. Destinations use RFC-2606 reserved `.example` domains;
  IPs come from TEST-NET ranges (203.0.113.0/24, 198.51.100.0/24). A unit test
  enforces this (`test_no_real_internet_hosts_in_dataset`).
- **No secrets in the repo.** Provider keys live in TrueForge's own settings
  store or a git-ignored `.env`. `.env.example` documents shape, not values.
- **Deterministic.** The same scenario replays identically - enforced by tests.

## The four approval layers

| Layer | Mechanism | Failure behaviour |
|---|---|---|
| 1. Prompt policy | commander.md rules P1-P9 | advisory |
| 2. TrueForge checkpoint | `require_approval_for_tools: ["isolate_endpoint"]` | turn pauses until human decides |
| 3. Application guard | MCP tool verifies incident shows PENDING/APPROVE authorization | refuses with REFUSED error |
| 4. Idempotency + mock target | repeated calls no-op; registry is a local JSON file | state cannot contradict |

Layer 2 is the human control. Layer 3 exists so that even a misconfigured
harness (approval requirement accidentally removed) cannot execute isolation
without the incident-level workflow having been followed.

## Artifact analysis safety

`sandbox/analyzers/powershell_analyzer.py` performs **static text analysis
only**: regex indicator rules, base64 literal decoding (ASCII-text validated),
domain/IP extraction. It never invokes PowerShell, never touches the network,
and reports `"executed": false` explicitly.

## Response simulation

`isolate_endpoint` writes `{"status": "ISOLATED"}` to `state/endpoints.json`.
That is the entire blast radius. No network calls, no system commands, no
driver interaction. The audit trail records who approved and when.

## Denial handling

A DENY at the checkpoint means the tool call never executes (TrueForge blocks
it). The Commander records the decision with `record_human_decision("DENY")`
and policy P7 forbids automatic retries. Tests cover both paths.

## Data authorship

**Every file under `scenarios/powershell_c2_beaconing/` was authored by the participant**
for this submission (alert, Windows event log, DNS log, network flow log, process
tree, IOC feed, threat-intel verdicts, expected-findings ground truth, and the
suspicious `win_update.ps1` sample). The threat-intel feed (synthetic-threat-feed)
is part of the scenario data. A test (`test_no_real_internet_hosts_in_dataset`)
guards that no real-internet host accidentally leaks into the dataset; the
scenario-replay test (`tests/scenario/test_replay.py`) re-derives the findings
from the dataset and asserts they match `expected_findings.json`, making the
demo deterministic and tamper-evident.

## What is explicitly out of scope

Real EDR/SOAR integrations, offensive tooling, dynamic malware execution,
production containment actions, multi-tenancy, authentication (local demo).
