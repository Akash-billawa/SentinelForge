"""Shared pytest configuration: import paths for mcp-server and sandbox."""

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
for p in (
    REPO_ROOT,
    REPO_ROOT / "mcp-server",
    REPO_ROOT / "sandbox",
):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))
