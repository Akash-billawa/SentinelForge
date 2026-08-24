"""Threat-intelligence lookup tools (read-only, synthetic feed)."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from mcp_app import mcp
from store import ScenarioStore


@mcp.tool()
def lookup_ioc(indicator: str, scenario: str = "powershell_c2_beaconing") -> dict:
    """Check an indicator (domain, IP, or sha256 hash) against the synthetic threat feed.

    Returns verdict, category and confidence when known. A ``not_found`` result
    is still meaningful - report it as-is instead of assuming malice.
    """
    return ScenarioStore(scenario).lookup_ioc(indicator)


@mcp.tool()
def list_attack_techniques(scenario: str = "powershell_c2_beaconing") -> dict:
    """List MITRE ATT&CK techniques associated with this scenario's threat intel package."""
    iocs = ScenarioStore(scenario).iocs()
    return {"mitre_attack": iocs.get("mitre_attack", [])}
