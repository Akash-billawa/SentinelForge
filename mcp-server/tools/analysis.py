"""Analysis tools: sandbox artifact analysis, network pattern analysis,
evidence fusion and transparent risk scoring."""

from __future__ import annotations

import sys
from datetime import datetime
from itertools import pairwise
from pathlib import Path
from statistics import mean, pstdev

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

REPO_ROOT = Path(__file__).resolve().parents[2]
for candidate in (REPO_ROOT, REPO_ROOT / "sandbox"):
    if str(candidate) not in sys.path:
        sys.path.insert(0, str(candidate))

from mcp_app import mcp
from store import (
    RISK_WEIGHTS,
    STORE,
    ScenarioStore,
    SentinelForgeError,
    calculate_risk,
)

# category -> risk signal (Section R weights)
CATEGORY_SIGNAL = {
    "powershell_execution": "powershell_anomaly",
    "encoded_command": "encoded_command",
    "suspicious_dns": "suspicious_dns",
    "beacon_pattern": "beacon_pattern",
    "threat_intel_match": "threat_intel_match",
    "suspicious_artifact": "suspicious_artifact",
}

VALID_CATEGORIES = sorted(CATEGORY_SIGNAL)


def parse_timestamp(ts: str) -> datetime:
    """Parse an ISO-8601 timestamp (Python 3.11+ accepts the trailing 'Z')."""
    return datetime.fromisoformat(ts)


def gap_seconds(flows: list[dict]) -> list[int]:
    """Whole-second gaps between consecutive flows, which must be time-sorted.

    Uses real datetime arithmetic. Slicing minutes/seconds out of the string
    discarded the hour and date, so a 15s gap spanning 10:59:50 -> 11:00:05
    measured as 0s and a periodic beacon looked irregular (or vice versa).
    """
    return [
        int((parse_timestamp(b["timestamp"]) - parse_timestamp(a["timestamp"])).total_seconds())
        for a, b in pairwise(flows)
    ]


@mcp.tool()
def analyze_powershell(
    path: str | None = None,
    artifact_id: str | None = None,
    scenario: str = "powershell_c2_beaconing",
) -> dict:
    """Run static analysis on a suspicious PowerShell artifact inside the analyzer sandbox.

    The artifact is parsed as text and NEVER executed. Returns a verdict,
    indicator list with severity points, decoded base64 payloads, referenced
    domains/IPs and an ``artifact:<id>`` evidence ref.
    """
    store = ScenarioStore(scenario)
    meta = store.file_metadata(path=path)
    if artifact_id and meta["artifact_id"] != artifact_id:
        raise SentinelForgeError(f"artifact_id {artifact_id!r} does not match {meta['artifact_id']!r}")

    sample_path = (
        REPO_ROOT / "scenarios" / scenario / "suspicious_artifact.ps1"
    )
    if not sample_path.is_file():
        raise SentinelForgeError(f"sandbox sample missing for scenario {scenario!r}")

    from analyzers.powershell_analyzer import analyze_powershell_file

    result = analyze_powershell_file(sample_path)
    result["file_metadata"] = meta
    result["evidence_ref"] = meta["evidence_ref"]
    return result


@mcp.tool()
def analyze_network_pattern(dst_ip: str, host: str = "WKS-042", scenario: str = "powershell_c2_beaconing") -> dict:
    """Analyze flows toward one destination IP for beaconing behaviour.

    Reports cadence regularity and payload-size consistency with plain-language
    reasons plus the flow evidence refs used - no opaque scoring.
    """
    flows = [
        f for f in ScenarioStore(scenario).network_flows(host=host) if f.get("dst_ip") == dst_ip
    ]
    if len(flows) < 3:
        return {
            "dst_ip": dst_ip,
            "flows_analyzed": len(flows),
            "verdict": "insufficient_data",
            "reason": "fewer than three flows; cannot assess cadence",
            "evidence_refs": [f["evidence_ref"] for f in flows],
        }
    flows = sorted(flows, key=lambda f: f["timestamp"])
    gaps = gap_seconds(flows)
    sent_sizes = [f["bytes_sent"] for f in flows]
    gap_cv = (pstdev(gaps) / mean(gaps)) if gaps and mean(gaps) else 0.0
    size_spread = max(sent_sizes) - min(sent_sizes)
    size_tolerance = max(mean(sent_sizes) * 0.05, 10)
    periodic = gap_cv <= 0.25
    consistent_size = size_spread <= size_tolerance
    verdict = "beacon-like" if periodic and consistent_size else ("periodic" if periodic else "irregular")

    return {
        "dst_ip": dst_ip,
        "host": host,
        "flows_analyzed": len(flows),
        "interval_seconds": {"observed_gaps": gaps, "mean": round(mean(gaps), 1), "cv": round(gap_cv, 3)},
        "payload_bytes_sent": {"min": min(sent_sizes), "max": max(sent_sizes), "spread": size_spread},
        "periodic": periodic,
        "consistent_payload_size": consistent_size,
        "verdict": verdict,
        "reasons": [
            f"inter-flow intervals vary by only {round(gap_cv * 100, 1)}% (regular cadence)" if periodic
            else f"inter-flow intervals vary by {round(gap_cv * 100, 1)}% (irregular)",
            f"payload sizes within {size_spread} bytes across all flows" if consistent_size
            else f"payload sizes vary widely ({size_spread} bytes spread)",
        ],
        "evidence_refs": [f["evidence_ref"] for f in flows],
    }


# ---------------------------------------------------------------------------
# Incident session tools (stateful)
# ---------------------------------------------------------------------------


@mcp.tool()
def create_incident_session(scenario: str = "powershell_c2_beaconing") -> dict:
    """Create (or resume) the persistent incident session for an alert.

    Returns the full IncidentSession record: phase, findings, evidence refs,
    IOCs, risk, approval and response state. Call this first. Safe to call
    twice: an existing session is RESUMED rather than rejected, so a retried
    turn does not dead-end the investigation.
    """
    incident_id = ScenarioStore(scenario).alert()["incident_id"]
    try:
        return STORE.get(incident_id)
    except SentinelForgeError:
        return STORE.create(scenario)


@mcp.tool()
def get_incident_context(incident_id: str) -> dict:
    """Fetch the current incident session state: findings so far, evidence refs, IOCs, phase."""
    return STORE.get(incident_id)


@mcp.tool()
def record_finding(
    incident_id: str,
    finding: str,
    evidence_refs: list[str],
    confidence: float,
    source_agent: str = "commander",
    category: str | None = None,
) -> dict:
    """Record one evidence-backed conclusion in the incident session.

    Every claim MUST cite at least one evidence_ref returned by another tool
    (e.g. ``windows_events:evt_0192``, ``dns:dns_0001``, ``flows:flow_0101``,
    ``process_tree:proc_0051``, ``artifact:art_0001``). Use ``category`` from:
    powershell_execution, encoded_command, suspicious_dns, beacon_pattern,
    threat_intel_match, suspicious_artifact, iocs.
    """
    updated = STORE.add_finding(incident_id, finding, evidence_refs, confidence, source_agent, category)
    return {
        "recorded": True,
        "findings_count": len(updated["findings"]),
        "current_phase": updated["current_phase"],
    }


@mcp.tool()
def mark_investigation_complete(incident_id: str) -> dict:
    """Transition NEW/INVESTIGATING -> EVIDENCE_READY once specialists have reported."""
    record = STORE.get(incident_id)
    target = "EVIDENCE_READY"
    if record["current_phase"] == "NEW":
        STORE.transition(incident_id, "INVESTIGATING")
    return STORE.transition(incident_id, target)


@mcp.tool()
def correlate_evidence(incident_id: str) -> dict:
    """Fuse recorded findings into a correlation summary.

    Groups findings by category, counts independent agent sources per category,
    lists every cited evidence ref and derives the transparent risk-signal set.

    Phase transition: this is the canonical EVIDENCE_READY -> ASSESSMENT_READY
    transition. The incident must be in EVIDENCE_READY (or already
    ASSESSMENT_READY, in which case this is a no-op re-correlation). If the
    incident is still in INVESTIGATING or NEW, refuse: investigation has not
    been marked complete yet. The user-facing error names the exact tool they
    need to call next so the agent can self-correct.
    """
    record = STORE.get(incident_id)
    findings = record["findings"]
    if not findings:
        raise SentinelForgeError("no findings recorded yet; investigate before correlating")
    current = record["current_phase"]
    if current not in ("EVIDENCE_READY", "ASSESSMENT_READY"):
        if current in ("NEW", "INVESTIGATING"):
            raise SentinelForgeError(
                f"phase is {current}; call mark_investigation_complete first to "
                "transition to EVIDENCE_READY, then call correlate_evidence to "
                "transition to ASSESSMENT_READY"
            )
        raise SentinelForgeError(
            f"phase is {current}; correlate_evidence only operates on "
            "EVIDENCE_READY or ASSESSMENT_READY incidents"
        )
    by_category: dict[str, list[dict]] = {}
    signals: list[str] = []
    for f in findings:
        cat = f.get("category") or "uncategorized"
        by_category.setdefault(cat, []).append(f)
        signal = CATEGORY_SIGNAL.get(cat)
        if signal and signal not in signals:
            signals.append(signal)
    agents = sorted({f["source_agent"] for f in findings})
    all_evidence = record["evidence_refs"]
    corroborated = {
        cat: sorted({f["source_agent"] for f in fs_list})
        for cat, fs_list in by_category.items()
    }
    summary = {
        "incident_id": incident_id,
        "findings_total": len(findings),
        "categories": {cat: len(fs) for cat, fs in sorted(by_category.items())},
        "contributing_agents": agents,
        "agent_corroboration": {cat: src for cat, src in sorted(corroborated.items())},
        "evidence_refs_total": len(all_evidence),
        "risk_signals": signals,
        "risk_signal_catalog": RISK_WEIGHTS,
        "current_phase": "ASSESSMENT_READY",
        "phase_transition": f"{current} -> ASSESSMENT_READY" if current != "ASSESSMENT_READY" else "no change",
    }

    def mutate(rec):
        if rec["current_phase"] == "EVIDENCE_READY":
            rec["current_phase"] = "ASSESSMENT_READY"
        # ASSESSMENT_READY is idempotent; re-correlation does not regress.

    STORE.update(incident_id, mutate)
    STORE.audit(incident_id, "EVIDENCE_CORRELATED", {"signals": signals, "previous_phase": current})
    return summary


@mcp.tool()
def calculate_risk_score(incident_id: str, extra_signals: list[str] | None = None) -> dict:
    """Compute the transparent risk score from correlated evidence (fixed public weights).

    Signals come from correlate_evidence; each carries its fixed point value.
    Returns score, severity, average finding confidence and the full breakdown.
    """
    record = STORE.get(incident_id)
    signals: list[str] = []
    for f in record["findings"]:
        sig = CATEGORY_SIGNAL.get(f.get("category") or "")
        if sig:
            signals.append(sig)
    signals += [s for s in (extra_signals or []) if s not in signals]
    if not signals:
        raise SentinelForgeError("no risk signals available; run correlate_evidence first")
    risk = calculate_risk(signals)
    confidences = [f["confidence"] for f in record["findings"]]
    assessment = {
        **risk,
        "confidence": round(sum(confidences) / len(confidences), 3) if confidences else None,
        "recommended_action": "isolate_endpoint" if risk["score"] >= 70 else "monitor",
        # Must reflect the ACTUAL branch: the old text always claimed the
        # threshold was reached, even for a LOW score recommending monitoring.
        "rationale": (
            f"score {risk['score']} reaches the containment threshold (>=70); "
            "recommend isolating the endpoint pending human approval"
            if risk["score"] >= 70
            else f"score {risk['score']} is below the containment threshold (>=70); "
            "continue monitoring - no consequential action is justified"
        ),
    }

    def mutate(rec):
        rec["risk"] = {k: v for k, v in assessment.items() if k != "rationale"}
        rec["confidence"] = assessment["confidence"]
        rec["recommended_action"] = assessment["recommended_action"]

    STORE.update(incident_id, mutate)
    STORE.audit(incident_id, "RISK_CALCULATED", {"score": risk["score"], "severity": risk["severity"]})
    return assessment


@mcp.tool()
def add_iocs_to_incident(incident_id: str, indicators: list[str], scenario: str = "powershell_c2_beaconing") -> dict:
    """Attach discovered IOC values to the incident session (looked up via lookup_ioc)."""
    store = ScenarioStore(scenario)
    resolved = [store.lookup_ioc(i) for i in indicators]
    STORE.add_iocs(incident_id, resolved)
    STORE.audit(incident_id, "IOCS_RECORDED", {"count": len(resolved)})
    return {"added": [r["value"] for r in resolved]}
