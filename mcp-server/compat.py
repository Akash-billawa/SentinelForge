"""Compatibility import for the MCP Python SDK.

Newer SDK versions expose ``MCPServer``; older ones expose ``FastMCP`` under
``mcp.server.fastmcp``. Both share the same ``@server.tool()`` decorator API.
"""

from __future__ import annotations

try:  # modern SDK
    from mcp.server import MCPServer  # type: ignore[attr-defined]

    ServerClass = MCPServer
except ImportError:  # pragma: no cover - legacy SDKs
    from mcp.server.fastmcp import FastMCP as ServerClass  # type: ignore[no-redef]

__all__ = ["ServerClass"]
