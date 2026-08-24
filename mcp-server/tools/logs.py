"""Endpoint/log investigation tools (read-only)."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from mcp_app import mcp
from store import ScenarioStore, SentinelForgeError


@mcp.tool()
def search_windows_logs(
    query: str = "",
    host: str = "WKS-042",
    time_start: str | None = None,
    time_end: str | None = None,
    scenario: str = "powershell_c2_beaconing",
) -> dict:
    """Search synthetic Windows event logs (process creation, script block, file, registry, EDR events).

    Args:
        query: space-separated keywords matched against the full event record
            (e.g. "powershell", "encoded", "registry").
        host: hostname to filter on.
        time_start / time_end: inclusive ISO-8601 timestamps bounding the search.
        scenario: synthetic dataset name.

    Each returned event carries an ``evidence_ref`` such as
    ``windows_events:evt_0192`` - cite these in findings.
    """
    store = ScenarioStore(scenario)
    events = store.windows_events(
        query=query or None,
        host=host,
        time_range=(time_start, time_end) if time_start or time_end else None,
    )
    return {"host": host, "count": len(events), "events": events}


@mcp.tool()
def get_process_tree(
    host: str = "WKS-042", process_id: str | None = None, scenario: str = "powershell_c2_beaconing"
) -> dict:
    """Return the process ancestry tree for a host.

    With ``process_id`` set, returns only that node's lineage context.
    Nodes reference originating events via ``evidence_event`` - cite them.
    """
    tree = ScenarioStore(scenario).process_tree(host=host)
    if not process_id:
        return tree
    node = ScenarioStore(scenario).find_process(process_id)
    if not node:
        raise SentinelForgeError(f"process_id {process_id!r} not found in tree for {host}")
    return {"host": host, "requested_process": node}


@mcp.tool()
def get_file_metadata(path: str, scenario: str = "powershell_c2_beaconing") -> dict:
    """Get filesystem metadata for a suspicious file artifact (hashes, signer, timestamps).

    The path is typically discovered from logs or the process tree. The result
    includes a sha256 usable with lookup_ioc and an ``artifact:<id>`` evidence ref.
    """
    return ScenarioStore(scenario).file_metadata(path=path)
