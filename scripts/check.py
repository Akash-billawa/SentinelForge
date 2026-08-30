#!/usr/bin/env python
"""SentinelForge one-command quality gate.

Runs every test/static layer we have and prints a clean pass/fail report.

  python scripts/check.py
"""

import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

# ANSI colors (skipped on non-TTY).
def _supports_color() -> bool:
    return sys.stdout.isatty()

C_GREEN = "\x1b[32m" if _supports_color() else ""
C_RED = "\x1b[31m" if _supports_color() else ""
C_YELLOW = "\x1b[33m" if _supports_color() else ""
C_DIM = "\x1b[2m" if _supports_color() else ""
C_BOLD = "\x1b[1m" if _supports_color() else ""
C_RESET = "\x1b[0m" if _supports_color() else ""


def run(label: str, cmd: list[str], cwd: Path | None = None) -> tuple[bool, str]:
    print(f"\n{C_BOLD}=== {label} ==={C_RESET}")
    print(f"{C_DIM}$ {' '.join(cmd)}{C_RESET}")
    try:
        result = subprocess.run(
            cmd, cwd=cwd or REPO_ROOT, capture_output=True, text=True, timeout=180, check=False,
        )
    except FileNotFoundError as exc:
        print(f"{C_RED}  tool not found: {exc}{C_RESET}")
        return False, f"{label}: tool not found"
    except subprocess.TimeoutExpired:
        print(f"{C_RED}  timeout after 180s{C_RESET}")
        return False, f"{label}: timeout"
    out = (result.stdout or "") + (result.stderr or "")
    print(out.rstrip())
    if result.returncode == 0:
        print(f"{C_GREEN}  PASS{C_RESET}  {label}")
        return True, label
    print(f"{C_RED}  FAIL{C_RESET}  {label} (exit {result.returncode})")
    return False, f"{label}: exit {result.returncode}"


def main() -> int:
    venv_python = REPO_ROOT / ".venv" / "Scripts" / "python.exe"
    if not venv_python.exists():
        venv_python = REPO_ROOT / ".venv" / "bin" / "python"
    py = str(venv_python if venv_python.exists() else Path(sys.executable))
    node = "node"

    results: list[tuple[bool, str]] = []
    results.append(run(
        "unit + integration + scenario tests",
        [py, "-m", "pytest", "tests", "-q", "--tb=line", "--color=no"],
    ))

    results.append(run(
        "ruff lint (mcp-server + sandbox + tests + scripts)",
        [py, "-m", "ruff", "check", "mcp-server", "sandbox", "tests", "scripts"],
    ))

    js_targets = sorted(
        str(p.relative_to(REPO_ROOT))
        for p in [
            *REPO_ROOT.glob("app/*.mjs"),
            *REPO_ROOT.glob("app/lib/*.mjs"),
            *REPO_ROOT.glob("scripts/*.mjs"),
        ]
    )
    if not js_targets:
        results.append(("no JS files", "JS syntax check", True))
    else:
        # Run all --check invocations in one process for speed.
        all_ok = True
        print(f"\n{C_BOLD}=== JS syntax (node --check) ==={C_RESET}")
        for t in js_targets:
            r = subprocess.run([node, "--check", t], capture_output=True, text=True, check=False)
            if r.returncode != 0:
                all_ok = False
                print(f"{C_RED}  FAIL{C_RESET} {t}: {r.stderr.strip() or r.stdout.strip()}")
        if all_ok:
            print(f"{C_GREEN}  PASS{C_RESET}  {len(js_targets)} JS files clean")
        results.append((all_ok, f"JS syntax ({'all ' if all_ok else ''}{len(js_targets)} files)"))

    print(f"\n{C_BOLD}========== SUMMARY =========={C_RESET}")
    width = max(len(label) for _, label in results)
    for ok, label in results:
        if ok is True or ok == "no JS files":
            mark = f"{C_GREEN}PASS{C_RESET}"
        else:
            mark = f"{C_RED}FAIL{C_RESET}"
        print(f"  {mark}  {label:<{width}}")
    failed = [label for ok, label in results if ok is False]
    if failed:
        print(f"\n{C_RED}{len(failed)} layer(s) failed.{C_RESET} Fix and re-run:  python scripts/check.py")
        return 1
    print(f"\n{C_GREEN}All clean.{C_RESET}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
