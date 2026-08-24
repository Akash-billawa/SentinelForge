"""Alert tools (read-only)."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from mcp_app import mcp
from store import ScenarioStore, list_scenarios


@mcp.tool()
def get_alert(scenario: str = "powershell_c2_beaconing") -> dict:
    """Load the security alert that starts an incident.

    Returns the alert payload (incident_id, hostname, alert_type, severity,
    timestamp, summary). This is only the STARTING SIGNAL - the agent must
    investigate and discover evidence through the other tools.
    """
    return ScenarioStore(scenario).alert()


@mcp.tool()
def list_scenarios_tool() -> dict:
    """List available synthetic incident scenarios."""
    return {"scenarios": list_scenarios()}
