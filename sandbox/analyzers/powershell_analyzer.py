"""Static PowerShell artifact analyzer.

Deterministic, explainable, execution-free. Produces the same result for the
same input every time - required by the demo reproducibility principle.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import ipaddress
import re
from pathlib import Path
from typing import Any

# --- detection rules -------------------------------------------------------
# Each rule: (id, regex, description, severity points)
_RULES: list[tuple[str, re.Pattern[str], str, int]] = [
    (
        "obfuscation.base64",
        re.compile(r"FromBase64String\s*\("),
        "Decodes a base64-encoded payload at runtime",
        25,
    ),
    (
        "execution.invoke_expression",
        re.compile(r"\bInvoke-Expression\b|\biex\b", re.IGNORECASE),
        "Dynamically executes constructed code",
        20,
    ),
    (
        "stealth.hidden_window",
        re.compile(r"-WindowStyle\s+Hidden", re.IGNORECASE),
        "Requests a hidden window to avoid user visibility",
        10,
    ),
    (
        "policy.bypass",
        re.compile(r"-ExecutionPolicy\s+Bypass", re.IGNORECASE),
        "Bypasses script execution policy",
        15,
    ),
    (
        "network.web_request",
        re.compile(r"\bInvoke-WebRequest\b|\bInvoke-RestMethod\b|\bNet\.WebClient\b", re.IGNORECASE),
        "Performs outbound HTTP requests",
        15,
    ),
    (
        "persistence.sleep_loop",
        re.compile(r"while\s*\(\$true\)", re.IGNORECASE),
        "Contains an infinite loop (typical of beaconing)",
        10,
    ),
    (
        "discovery.error_suppress",
        re.compile(r"\$ErrorActionPreference\s*=\s*'SilentlyContinue'", re.IGNORECASE),
        "Suppresses all errors to evade logging",
        5,
    ),
]

_DOMAIN_RE = re.compile(r"\b([a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+)\b")
_IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")

RESERVED_SUFFIX = ".example"


def _extract_strings(text: str) -> dict[str, list[str]]:
    domains: set[str] = set()
    for match in _DOMAIN_RE.finditer(text):
        candidate = match.group(1).lower()
        if (candidate.endswith(RESERVED_SUFFIX) or "." in candidate) and not candidate.replace(
            ".", ""
        ).isdigit():
            domains.add(candidate)
    ips: list[str] = []
    for match in _IP_RE.finditer(text):
        try:
            ipaddress.ip_address(match.group(1))
            ips.append(match.group(1))
        except ValueError:
            continue
    return {"domains": sorted(domains), "ips": sorted(set(ips))}


def _decode_base64_blobs(text: str) -> list[dict[str, str]]:
    """Decode every base64-shaped string literal (inline or via a variable)."""
    decoded: list[dict[str, str]] = []
    seen: set[str] = set()
    for match in re.finditer(r"['\"]([A-Za-z0-9+/=]{16,})['\"]", text):
        blob = match.group(1)
        if blob in seen or not re.fullmatch(r"(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?", blob):
            continue
        seen.add(blob)
        try:
            plain_bytes = base64.b64decode(blob, validate=True)
            plain = plain_bytes.decode("ascii")  # rejects non-text payloads
            if not all(c.isprintable() or c in "\r\n\t" for c in plain):
                raise ValueError
            decoded.append(
                {
                    "encoded_preview": blob[:32] + ("..." if len(blob) > 32 else ""),
                    "decoded": plain,
                }
            )
        except (binascii.Error, ValueError, UnicodeDecodeError):
            continue
    return decoded


def analyze_powershell_text(text: str, source_path: str | None = None) -> dict[str, Any]:
    """Analyze PowerShell source text and return a structured verdict."""
    sha256 = hashlib.sha256(text.encode("utf-8")).hexdigest()
    indicators = [
        {"rule_id": rid, "description": desc, "points": pts}
        for rid, rx, desc, pts in _RULES
        if rx.search(text)
    ]
    score = min(sum(i["points"] for i in indicators), 100)
    if score >= 60:
        verdict = "malicious"
    elif score >= 30:
        verdict = "suspicious"
    elif score > 0:
        verdict = "notable"
    else:
        verdict = "benign"
    return {
        "analyzer": "static-powershell-v1",
        "source_path": source_path,
        "sha256": sha256,
        "verdict": verdict,
        "score": score,
        "indicators": indicators,
        "decoded_payloads": _decode_base64_blobs(text),
        "referenced_destinations": _extract_strings(text),
        "executed": False,
        "method": "static analysis only - artifact was never executed",
    }


def analyze_powershell_file(path: str | Path) -> dict[str, Any]:
    file_path = Path(path)
    if not file_path.is_file():
        raise FileNotFoundError(f"artifact not found: {path}")
    if file_path.suffix.lower() not in (".ps1", ".txt"):
        raise ValueError("only .ps1 artifacts are accepted by this analyzer")
    return analyze_powershell_text(file_path.read_text(encoding="utf-8"), str(file_path))
