"""SentinelForge data and incident-state layer.

Pure stdlib. All tools read the deterministic synthetic dataset under
``scenarios/<name>/`` and persist incident state under ``state/incidents/``.

Every record returned to an agent carries a stable evidence reference
(``<source>:<id>``) so conclusions stay traceable end-to-end.
"""

from __future__ import annotations

import json
import os
import re
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

# --------------------------------------------------------------------------
# Layout / configuration
# --------------------------------------------------------------------------

_REPO_ROOT = Path(
    os.environ.get("SENTINELFORGE_REPO_ROOT") or Path(__file__).resolve().parents[1]
)
# Tests isolate via SENTINELFORGE_STATE_DIR so they never touch demo state.
STATE_DIR = Path(os.environ.get("SENTINELFORGE_STATE_DIR") or (_REPO_ROOT / "state"))
SCENARIOS_DIR = _REPO_ROOT / "scenarios"

_INCIDENT_ID_RE = re.compile(r"^INC-\d{4}-\d{4,6}$")


def repo_root() -> Path:
    return _REPO_ROOT


def utc_now() -> str:
    # Single clock read: sampling now() twice could straddle a second boundary
    # and emit a timestamp whose milliseconds belong to a different second.
    now = datetime.now(UTC)
    return now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"


class SentinelForgeError(Exception):
    """Domain error surfaced to agents with a clear message."""


# --------------------------------------------------------------------------
# Scenario data access (read-only)
# --------------------------------------------------------------------------


def list_scenarios() -> list[str]:
    if not SCENARIOS_DIR.is_dir():
        return []
    return sorted(p.name for p in SCENARIOS_DIR.iterdir() if p.is_dir())


def _jsonl(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


def _in_range(ts: str, time_range: tuple[str | None, str | None] | None) -> bool:
    """Inclusive bounds check where either end may be None (unbounded).

    The log/DNS/flow tools build the range from optional time_start/time_end
    arguments, so a half-open range is a normal request - comparing against
    None used to raise TypeError and fail the tool call.
    """
    if not time_range:
        return True
    start, end = time_range
    return (not start or ts >= start) and (not end or ts <= end)


class ScenarioStore:
    """Read-only access to one synthetic incident package."""

    def __init__(self, scenario: str = "powershell_c2_beaconing") -> None:
        self.name = scenario
        self.dir = SCENARIOS_DIR / scenario
        if not self.dir.is_dir():
            raise SentinelForgeError(
                f"unknown scenario {scenario!r}; available: {list_scenarios()}"
            )

    def alert(self) -> dict[str, Any]:
        return json.loads((self.dir / "alert.json").read_text(encoding="utf-8"))

    def iocs(self) -> dict[str, Any]:
        return json.loads((self.dir / "iocs.json").read_text(encoding="utf-8"))

    def expected_findings(self) -> dict[str, Any]:
        return json.loads((self.dir / "expected_findings.json").read_text(encoding="utf-8"))

    def windows_events(
        self,
        query: str | None = None,
        host: str | None = None,
        time_range: tuple[str | None, str | None] | None = None,
    ) -> list[dict[str, Any]]:
        out = []
        for rec in _jsonl(self.dir / "windows_events.jsonl"):
            if host and rec.get("host") != host:
                continue
            if not _in_range(rec["timestamp"], time_range):
                continue
            if query:
                haystack = json.dumps(rec).lower()
                terms = [t.strip().lower() for t in query.split() if t.strip()]
                if terms and not all(t in haystack for t in terms):
                    continue
            out.append({**rec, "evidence_ref": f"windows_events:{rec['event_id']}"})
        return out

    def dns_logs(
        self, host: str | None = None, time_range: tuple[str | None, str | None] | None = None
    ) -> list[dict[str, Any]]:
        out = []
        for rec in _jsonl(self.dir / "dns.jsonl"):
            if host and rec.get("host") != host:
                continue
            if not _in_range(rec["timestamp"], time_range):
                continue
            out.append({**rec, "evidence_ref": f"dns:{rec['query_id']}"})
        return out

    def network_flows(
        self, host: str | None = None, time_range: tuple[str | None, str | None] | None = None
    ) -> list[dict[str, Any]]:
        out = []
        for rec in _jsonl(self.dir / "network_flows.jsonl"):
            if host and rec.get("host") != host:
                continue
            if not _in_range(rec["timestamp"], time_range):
                continue
            out.append({**rec, "evidence_ref": f"flows:{rec['flow_id']}"})
        return out

    def process_tree(self, host: str | None = None) -> dict[str, Any]:
        tree = json.loads((self.dir / "process_tree.json").read_text(encoding="utf-8"))
        if host and tree.get("host") != host:
            raise SentinelForgeError(f"no process tree for host {host!r} in {self.name!r}")
        return tree

    def find_process(self, process_id: str) -> dict[str, Any] | None:
        def walk(node: dict[str, Any]) -> dict[str, Any] | None:
            if node.get("process_id") == process_id:
                return node
            for child in node.get("children", []):
                found = walk(child)
                if found:
                    return found
            return None

        tree = self.process_tree()
        root = tree.get("root", {})
        return walk(root)

    def file_metadata(self, path: str | None = None) -> dict[str, Any]:
        meta = json.loads((self.dir / "file_metadata.json").read_text(encoding="utf-8"))
        meta["evidence_ref"] = f"artifact:{meta['artifact_id']}"
        if path and meta["path"].lower() != path.lower():
            raise SentinelForgeError(f"unknown artifact path {path!r}")
        return meta

    def lookup_ioc(self, indicator: str) -> dict[str, Any]:
        norm = indicator.strip().lower()
        for ioc in self.iocs().get("iocs", []):
            if ioc["value"].lower() == norm:
                return {
                    **ioc,
                    "evidence_ref": f"ioc:{ioc['type']}:{ioc['value']}",
                }
        return {
            "type": "unknown",
            "value": indicator,
            "verdict": "not_found",
            "category": None,
            "confidence": 0.0,
            "source": "synthetic-threat-feed",
            "note": "indicator absent from synthetic threat feed",
        }


def get_alert(scenario: str = "powershell_c2_beaconing") -> dict[str, Any]:
    return ScenarioStore(scenario).alert()


# --------------------------------------------------------------------------
# Incident state machine (Section S of the blueprint)
# --------------------------------------------------------------------------

PHASES = [
    "NEW",
    "INVESTIGATING",
    "EVIDENCE_READY",
    "ASSESSMENT_READY",
    "WAITING_FOR_APPROVAL",
    "CONTAINED",
    "DENIED",
    "CLOSED",
]

_TRANSITIONS: dict[str, set[str]] = {
    "NEW": {"INVESTIGATING", "CLOSED"},
    "INVESTIGATING": {"EVIDENCE_READY", "CLOSED"},
    "EVIDENCE_READY": {"ASSESSMENT_READY", "CLOSED"},
    "ASSESSMENT_READY": {"WAITING_FOR_APPROVAL", "CONTAINED", "DENIED", "CLOSED"},
    "WAITING_FOR_APPROVAL": {"CONTAINED", "DENIED", "ASSESSMENT_READY", "CLOSED"},
    "CONTAINED": {"CLOSED"},
    "DENIED": {"CLOSED"},
    "CLOSED": set(),
}


def can_transition(current: str, target: str) -> bool:
    return target in _TRANSITIONS.get(current, set())


class InvalidTransition(SentinelForgeError):
    pass


# --------------------------------------------------------------------------
# Transparent risk scoring (Section R of the blueprint)
# --------------------------------------------------------------------------

RISK_WEIGHTS = {
    "powershell_anomaly": 20,
    "encoded_command": 20,
    "suspicious_dns": 15,
    "beacon_pattern": 20,
    "threat_intel_match": 10,
    "suspicious_artifact": 15,
}


def calculate_risk(signals: list[str]) -> dict[str, Any]:
    """Deterministic, explainable score. Never invented by the model.

    Each distinct signal scores ONCE. Several findings in the same category are
    corroboration, not additional risk: counting them repeatedly let a single
    category (e.g. five PowerShell findings) reach 100/CRITICAL on its own and
    silently cross the containment threshold.
    """
    matched: list[str] = []
    unknown: list[str] = []
    for signal in signals:
        bucket = matched if signal in RISK_WEIGHTS else unknown
        if signal not in bucket:
            bucket.append(signal)
    score = min(sum(RISK_WEIGHTS[s] for s in matched), 100)
    if score >= 85:
        severity = "CRITICAL"
    elif score >= 60:
        severity = "HIGH"
    elif score >= 35:
        severity = "MEDIUM"
    else:
        severity = "LOW"
    breakdown = [{"signal": s, "points": RISK_WEIGHTS[s]} for s in matched]
    return {
        "score": score,
        "max_score": 100,
        "severity": severity,
        "signals": breakdown,
        "ignored_signals": unknown,
        "formula": "sum of DISTINCT signal weights, capped at 100; weights are fixed policy",
    }


# --------------------------------------------------------------------------
# Incident persistence + audit trail
# --------------------------------------------------------------------------


class IncidentStore:
    """Persistent incident sessions (survives within and across app runs)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        (STATE_DIR / "incidents").mkdir(parents=True, exist_ok=True)

    # NOTE: paths resolve STATE_DIR at call time so tests can isolate via
    # monkeypatch.setattr(store, "STATE_DIR", tmp).

    # -- paths ------------------------------------------------------------
    @staticmethod
    def _path(incident_id: str) -> Path:
        if not _INCIDENT_ID_RE.match(incident_id or ""):
            raise SentinelForgeError(
                f"invalid incident id {incident_id!r}; expected INC-YYYY-NNNN"
            )
        path = STATE_DIR / "incidents" / f"{incident_id}.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        return path

    @staticmethod
    def _audit_path(incident_id: str) -> Path:
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        return STATE_DIR / "audit" / f"{incident_id}.jsonl"

    # -- CRUD -------------------------------------------------------------
    def create(self, scenario: str, incident_id: str | None = None) -> dict[str, Any]:
        alert = get_alert(scenario)
        incident_id = incident_id or alert["incident_id"]
        with self._lock:
            path = self._path(incident_id)
            if path.exists():
                raise SentinelForgeError(f"incident {incident_id} already exists")
            record = {
                "incident_id": incident_id,
                "scenario": scenario,
                "created_at": utc_now(),
                "updated_at": utc_now(),
                "alert": alert,
                "current_phase": "NEW",
                "findings": [],
                "evidence_refs": [],
                "iocs": [],
                "risk": None,
                "confidence": None,
                "recommended_action": None,
                "approval_state": "NOT_REQUESTED",
                "response_state": "NONE",
                "final_report": None,
            }
            path.write_text(json.dumps(record, indent=2), encoding="utf-8")
            self.audit(incident_id, "INCIDENT_CREATED", {"scenario": scenario})
            return record

    def reset(self, incident_id: str) -> dict[str, Any]:
        """Delete stored incident so the demo can be replayed deterministically.

        Idempotent: resetting a scenario that was never run is a no-op. The
        console resets before every START, so raising here broke the very first
        investigation on a clean checkout.
        """
        with self._lock:
            path = self._path(incident_id)
            existed = path.exists()
            self._audit_path(incident_id).unlink(missing_ok=True)
            path.unlink(missing_ok=True)
        return {"reset": True, "incident_id": incident_id, "existed": existed}

    def get(self, incident_id: str) -> dict[str, Any]:
        path = self._path(incident_id)
        if not path.exists():
            raise SentinelForgeError(f"incident {incident_id} does not exist")
        return json.loads(path.read_text(encoding="utf-8"))

    def update(self, incident_id: str, mutate) -> dict[str, Any]:
        with self._lock:
            record = self.get(incident_id)
            mutate(record)
            record["updated_at"] = utc_now()
            self._path(incident_id).write_text(
                json.dumps(record, indent=2), encoding="utf-8"
            )
            return record

    def transition(self, incident_id: str, target_phase: str) -> dict[str, Any]:
        def mutate(rec: dict[str, Any]) -> None:
            current = rec["current_phase"]
            if not can_transition(current, target_phase):
                raise InvalidTransition(
                    f"illegal phase transition {current} -> {target_phase}"
                )
            rec["current_phase"] = target_phase

        updated = self.update(incident_id, mutate)
        self.audit(incident_id, "PHASE_TRANSITION", {"to": target_phase})
        return updated

    # -- findings ---------------------------------------------------------
    def add_finding(
        self,
        incident_id: str,
        finding: str,
        evidence_refs: list[str],
        confidence: float,
        source_agent: str = "commander",
        category: str | None = None,
    ) -> dict[str, Any]:
        if not 0.0 <= confidence <= 1.0:
            raise SentinelForgeError("confidence must be within [0,1]")
        if not evidence_refs:
            raise SentinelForgeError("a finding requires at least one evidence_ref")

        def mutate(rec: dict[str, Any]) -> None:
            rec["findings"].append(
                {
                    "finding": finding,
                    "evidence": evidence_refs,
                    "confidence": round(confidence, 3),
                    "source_agent": source_agent,
                    "category": category,
                    "recorded_at": utc_now(),
                }
            )
            known = set(rec["evidence_refs"])
            rec["evidence_refs"] = sorted(known | set(evidence_refs))

        updated = self.update(incident_id, mutate)
        self.audit(
            incident_id,
            "FINDING_RECORDED",
            {
                "finding": finding,
                "evidence": evidence_refs,
                "confidence": confidence,
                "source_agent": source_agent,
            },
        )
        return updated

    def add_iocs(self, incident_id: str, indicators: list[dict[str, Any]]) -> dict[str, Any]:
        def mutate(rec: dict[str, Any]) -> None:
            seen = {(i.get("type"), i.get("value")) for i in rec["iocs"]}
            for ind in indicators:
                key = (ind.get("type"), ind.get("value"))
                if key not in seen:
                    rec["iocs"].append(ind)
                    seen.add(key)

        return self.update(incident_id, mutate)

    def set_assessment(
        self,
        incident_id: str,
        risk_signals: list[str],
        recommended_action: str | None,
    ) -> dict[str, Any]:
        risk = calculate_risk(risk_signals)

        def mutate(rec: dict[str, Any]) -> None:
            rec["risk"] = risk
            confidences = [f["confidence"] for f in rec["findings"]] or [0.0]
            rec["confidence"] = round(sum(confidences) / len(confidences), 3)
            rec["recommended_action"] = recommended_action
            # set_assessment only operates on fully-correlated incidents.
            # The workflow that reaches this point is:
            #   mark_investigation_complete -> correlate_evidence -> set_assessment
            # correlate_evidence advances EVIDENCE_READY -> ASSESSMENT_READY, so
            # the precondition is ASSESSMENT_READY. Earlier states mean the
            # agent skipped correlate_evidence.
            if rec["current_phase"] in ("NEW", "INVESTIGATING"):
                raise InvalidTransition(
                    f"cannot assess while phase={rec['current_phase']}; "
                    "call mark_investigation_complete and correlate_evidence first"
                )
            if rec["current_phase"] == "EVIDENCE_READY":
                raise InvalidTransition(
                    f"phase is EVIDENCE_READY; call correlate_evidence first to "
                    "transition to ASSESSMENT_READY"
                )
            # ASSESSMENT_READY is the expected state; re-setting is idempotent.

        updated = self.update(incident_id, mutate)
        self.audit(
            incident_id,
            "RISK_CALCULATED",
            {
                "score": risk["score"],
                "severity": risk["severity"],
                "recommended_action": recommended_action,
            },
        )
        return updated

    # -- approval + response ----------------------------------------------
    def request_approval(self, incident_id: str, action: str) -> dict[str, Any]:
        def mutate(rec: dict[str, Any]) -> None:
            if rec["current_phase"] != "ASSESSMENT_READY":
                raise InvalidTransition(
                    "approval can only be requested from ASSESSMENT_READY "
                    f"(current={rec['current_phase']})"
                )
            if rec["approval_state"] == "PENDING":
                raise SentinelForgeError("approval already pending")
            if action != rec["recommended_action"]:
                raise SentinelForgeError(
                    f"action {action!r} does not match recommendation "
                    f"{rec['recommended_action']!r}"
                )
            rec["approval_state"] = "PENDING"
            rec["current_phase"] = "WAITING_FOR_APPROVAL"

        updated = self.update(incident_id, mutate)
        self.audit(incident_id, "APPROVAL_REQUESTED", {"action": action})
        return updated

    def resolve_approval(self, incident_id: str, decision: str, decided_by: str = "human") -> dict[str, Any]:
        if decision not in ("APPROVE", "DENY"):
            raise SentinelForgeError("decision must be APPROVE or DENY")

        def mutate(rec: dict[str, Any]) -> None:
            if rec["approval_state"] != "PENDING":
                raise SentinelForgeError(
                    f"no approval pending (state={rec['approval_state']})"
                )
            rec["approval_state"] = decision

        updated = self.update(incident_id, mutate)
        self.audit(incident_id, f"APPROVAL_{decision}", {"decided_by": decided_by})
        return updated

    def apply_response(self, incident_id: str, action: str, result: dict[str, Any]) -> dict[str, Any]:
        def mutate(rec: dict[str, Any]) -> None:
            if rec["approval_state"] != "APPROVE":
                raise SentinelForgeError(
                    "refusing response execution: no recorded human approval"
                )
            rec["response_state"] = result.get("status", "UNKNOWN")
            if rec["current_phase"] == "WAITING_FOR_APPROVAL":
                rec["current_phase"] = "CONTAINED" if result.get("status") == "ISOLATED" else "DENIED"

        updated = self.update(incident_id, mutate)
        self.audit(incident_id, "RESPONSE_EXECUTED", {"action": action, **result})
        return updated

    # -- report -----------------------------------------------------------
    def finalize_report(self, incident_id: str, report: dict[str, Any]) -> dict[str, Any]:
        def mutate(rec: dict[str, Any]) -> None:
            rec["final_report"] = report
            rec["current_phase"] = "CLOSED"

        updated = self.update(incident_id, mutate)
        self.audit(incident_id, "REPORT_FINALIZED", {})
        return updated

    # -- audit ------------------------------------------------------------
    def audit(self, incident_id: str, event: str, detail: dict[str, Any]) -> None:
        path = self._audit_path(incident_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        entry = {"ts": utc_now(), "event": event, **detail}
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry) + "\n")

    def timeline(self, incident_id: str) -> list[dict[str, Any]]:
        path = self._audit_path(incident_id)
        if not path.exists():
            return []
        with path.open("r", encoding="utf-8") as fh:
            return [json.loads(line) for line in fh if line.strip()]


STORE = IncidentStore()
