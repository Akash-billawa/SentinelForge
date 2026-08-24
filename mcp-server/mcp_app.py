"""Shared MCP server instance for SentinelForge security tooling."""

from __future__ import annotations

from compat import ServerClass

mcp = ServerClass(
    "sentinelforge-security",
    instructions=(
        "SentinelForge SOC investigation tools. All data is synthetic and "
        "authorized. Read-only investigation tools never mutate state. "
        "isolate_endpoint is CONSEQUENTIAL: it is gated by a human approval "
        "checkpoint and refuses to run without recorded authorization."
    ),
)
