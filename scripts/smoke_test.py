"""Smoke test: verify all MCP tools register and core logic runs."""

import asyncio
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for _p in (ROOT / "mcp-server", ROOT / "sandbox", ROOT):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

# Importing the tool modules is what REGISTERS the handlers - without them the
# smoke test reported "TOTAL: 0" while claiming every tool was verified.
import tools.alerts
import tools.analysis
import tools.intelligence
import tools.logs
import tools.network
import tools.response  # noqa: F401
from mcp_app import mcp


async def main() -> None:
    tools = await mcp.list_tools()
    for t in tools:
        print(f"{t.name:38s} {len(t.description or ''):4d} chars")
    print("TOTAL:", len(tools))
    assert tools, "no MCP tools registered"
    assert all(t.description for t in tools), "every tool needs a description for the agent"

    # functional spot-checks against the synthetic dataset
    from store import ScenarioStore, calculate_risk

    store = ScenarioStore()
    alert = store.alert()
    assert alert["incident_id"] == "INC-2026-0042", alert
    events = store.windows_events(query="powershell")
    assert events and events[0]["evidence_ref"].startswith("windows_events:")

    risk = calculate_risk(
        [
            "powershell_anomaly",
            "encoded_command",
            "suspicious_dns",
            "beacon_pattern",
            "threat_intel_match",
            "suspicious_artifact",
        ]
    )
    assert risk["score"] == 100, risk
    print("risk:", json.dumps({"score": risk["score"], "severity": risk["severity"]}))

    from analyzers.powershell_analyzer import analyze_powershell_file

    result = analyze_powershell_file(ROOT / "scenarios/powershell_c2_beaconing/suspicious_artifact.ps1")
    assert result["verdict"] in ("suspicious", "malicious"), result["verdict"]
    assert result["decoded_payloads"], "base64 payload should decode"
    print("analyzer verdict:", result["verdict"], "| indicators:", len(result["indicators"]))
    print("SMOKE OK")


if __name__ == "__main__":
    asyncio.run(main())
