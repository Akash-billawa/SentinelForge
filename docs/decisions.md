# Decision Log

| # | Decision | Rationale | Alternatives rejected |
|---|---|---|---|
| 1 | MCP server in Python (mcp SDK, streamable-http) | Security tooling + JSONL parsing is natural in Python; TrueForge attaches remote servers by URL | Node MCP server (duplicates harness stack); stdio transport (TrueForge connects remote) |
| 2 | Approval via TrueForge `require_approval_for_tools`, plus an application-level PENDING guard | Harness gate is the real human control; app guard keeps the demo safe even if misconfigured, and makes tests possible without an LLM | Only prompt-based restraint ("please ask first") - unenforceable |
| 3 | Mock endpoint registry instead of real isolation | Blueprint section O.3: prove the control loop without creating risk | Real firewall/EDR integration - out of scope, unsafe, unverifiable by judges |
| 4 | Static analyzer, never executes artifacts | Deterministic, safe, reproducible in CI | Dynamic detonation sandbox - heavy infra, non-deterministic, risk |
| 5 | Fixed transparent risk weights (sum, capped at 100) | Judges must be able to verify the number; model inventing a score is a trust failure | ML scoring / model-authored severity |
| 6 | Incident state persisted as JSON files under state/ | Zero infra, replayable, inspectable during the demo | SQLite/Postgres - unnecessary for one-incident demo |
| 7 | Evidence refs as stable IDs (`windows_events:evt_0192`) baked into tool outputs | Traceability without trusting model memory; enables scenario replay validation | Free-text citations only |
| 8 | Specialists as subagents with restricted toolsets per prompt | Mirrors real SOC roles; shows off harness delegation visibly on stream | Single agent doing everything sequentially |
| 9 | One scenario only | Winning principle: do one job extremely well | Multiple incident types before P0 chain is flawless |
| 10 | UI reads SDK event stream via SSE from one Node process | No build step, no framework lock-in; judges run two commands | React/Vite bundle for a three-minute demo |
| 11 | `scripts/run-trueforge.mjs` installs + patches the harness locally instead of `npx` | TrueForge 0.1.4 cannot start on native Windows: kysely 0.29.5's `FileMigrationProvider.getMigrations()` runs `await import("C:\\...\\migration.js")`, which Node rejects with `ERR_UNSUPPORTED_ESM_URL_SCHEME`. The script applies a one-line, idempotent `pathToFileURL()` fix to the bundled kysely copy - correct on every OS - and keeps the pinned version in the repo's own `node_modules`. Warm start is ~3s. | WSL/Docker as primary path (heavier judge setup); waiting on upstream fix (hackathon deadline) |

## Compatibility shims kept deliberately

- `mcp-server/compat.py` supports both new (`MCPServer`) and legacy
  (`FastMCP`) import paths of the MCP Python SDK.
- Integration tests tolerate both `is_error` and `isError` result fields.

Both exist so judges can `pip install` latest dependencies and still run the
demo unchanged.
