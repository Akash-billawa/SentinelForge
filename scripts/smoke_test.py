"""Smoke test: verify all MCP tools register and core logic runs."""

import asyncio
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "mcp-server"))
sys.path.insert(0, str(ROOT))

from mcp_app import mcp


async def main() -> None:
    tools = await mcp.list_tools()
    for t in tools:
        print(f"{t.name:38s} {len(t.description or ''):4d} chars")
    print("TOTAL:", len(tools))

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
