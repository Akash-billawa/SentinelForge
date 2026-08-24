"""Standalone repro: walk the full flow over HTTP, printing each step."""

import os
import socket
import subprocess
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SERVER = REPO_ROOT / "mcp-server" / "server.py"


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def main():
    port = free_port()
    env = {**os.environ, "SENTINELFORGE_MCP_PORT": str(port), "SENTINELFORGE_REPO_ROOT": str(REPO_ROOT)}
    proc = subprocess.Popen([sys.executable, str(SERVER)], env=env)
    url = f"http://127.0.0.1:{port}/mcp"
    time.sleep(3)

    import asyncio

    from mcp import ClientSession
    from mcp.client.streamable_http import streamable_http_client

    async def flow():
        async with streamable_http_client(url) as streams, ClientSession(
            streams[0], streams[1]
        ) as s:
            await s.initialize()
            steps = [
                ("reset_demo", {"incident_id": "INC-2026-0042", "host": "WKS-042"}),
                ("create_incident_session", {}),
                ("record_finding", {"incident_id": "INC-2026-0042", "finding": "ps ran", "evidence_refs": ["windows_events:evt_0192"], "confidence": 0.9, "category": "powershell_execution"}),
                ("mark_investigation_complete", {"incident_id": "INC-2026-0042"}),
                ("correlate_evidence", {"incident_id": "INC-2026-0042"}),
                ("calculate_risk_score", {"incident_id": "INC-2026-0042"}),
                ("request_response_authorization", {"incident_id": "INC-2026-0042", "action": "isolate_endpoint", "justification": "confirmed beaconing"}),
                ("isolate_endpoint", {"incident_id": "INC-2026-0042", "host": "WKS-042"}),
            ]
            for name, args in steps:
                print(f"-> {name}", flush=True)
                res = await asyncio.wait_for(s.call_tool(name, args), timeout=15)
                texts = [c.text for c in res.content if getattr(c, "type", "") == "text"]
                print(f"   is_error={res.is_error} out={texts[0][:160] if texts else None}", flush=True)

    try:
        asyncio.run(flow())
    finally:
        proc.terminate()

    print("FLOW DONE")


if __name__ == "__main__":
    main()
