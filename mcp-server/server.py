"""SentinelForge security MCP server - entrypoint.

Serves the SOC investigation tools over streamable HTTP so a remote harness
(TrueForge) can connect by URL:

    http://127.0.0.1:8765/mcp

Run:
    python server.py            # streamable-http on 127.0.0.1:8765
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

# Importing these modules registers their @mcp.tool() handlers.
import tools.alerts
import tools.analysis
import tools.intelligence
import tools.logs
import tools.network
import tools.response  # noqa: F401
from compat import ServerClass  # noqa: F401  (validates SDK availability)
from mcp_app import mcp


def main() -> None:
    host = os.environ.get("SENTINELFORGE_MCP_HOST", "127.0.0.1")
    port = int(os.environ.get("SENTINELFORGE_MCP_PORT", "8765"))
    print(f"SentinelForge MCP server -> http://{host}:{port}/mcp", file=sys.stderr)
    mcp.run(
        transport="streamable-http",
        host=host,
        port=port,
        stateless_http=True,
    )


if __name__ == "__main__":
    main()
