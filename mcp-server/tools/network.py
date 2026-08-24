"""Network investigation tools (read-only)."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from mcp_app import mcp
from store import ScenarioStore


@mcp.tool()
def search_dns_logs(
    host: str = "WKS-042",
    time_start: str | None = None,
    time_end: str | None = None,
    scenario: str = "powershell_c2_beaconing",
) -> dict:
    """Search synthetic DNS query logs for a host within a time window.

    Look for unusual domains, low-TTL repeats, and queries issued by the
    suspicious process pid. Each record carries ``dns:<query_id>`` evidence refs.
    """
    store = ScenarioStore(scenario)
    records = store.dns_logs(
        host=host, time_range=(time_start, time_end) if time_start or time_end else None
    )
    domains = sorted({r["query"] for r in records})
    return {"host": host, "count": len(records), "domains": domains, "queries": records}


@mcp.tool()
def search_network_flows(
    host: str = "WKS-042",
    dst_ip: str | None = None,
    time_start: str | None = None,
    time_end: str | None = None,
    scenario: str = "powershell_c2_beaconing",
) -> dict:
    """Search synthetic network flow records for a host (optionally filtered by destination IP).

    Examine cadence, payload-size consistency and destination concentration to
    spot C2 beaconing. Each record carries ``flows:<flow_id>`` evidence refs.
    """
    store = ScenarioStore(scenario)
    records = store.network_flows(
        host=host, time_range=(time_start, time_end) if time_start or time_end else None
    )
    if dst_ip:
        records = [r for r in records if r.get("dst_ip") == dst_ip]
    return {"host": host, "dst_ip": dst_ip, "count": len(records), "flows": records}
