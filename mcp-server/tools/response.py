"""Consequential response tools.

``isolate_endpoint`` is the single consequential tool in the MVP. It is
guarded by TWO independent gates:

1. TrueForge's human approval checkpoint (``require_approval_for_tools`` in
   the agent spec) - the harness pauses the run until a person approves.
2. SentinelForge's own authorization check - the incident record must show an
   authorization request was raised and approved; otherwise the tool refuses,
   even if it is somehow invoked directly.

The response target is a MOCK endpoint registry (state/endpoints.json) - no
real machine is ever touched. The operation is idempotent.
"""

from __future__ import annotations

import json
import sys
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from mcp_app import mcp
from store import STATE_DIR, STORE, InvalidTransition, SentinelForgeError, utc_now

_ENDPOINTS_PATH = STATE_DIR / "endpoints.json"
_ENDPOINT_LOCK = threading.Lock()
_CONSEQUENTIAL_ACTIONS = ("isolate_endpoint",)


def _load_endpoints() -> dict:
    if _ENDPOINTS_PATH.exists():
        return json.loads(_ENDPOINTS_PATH.read_text(encoding="utf-8"))
    return {}


def _save_endpoints(data: dict) -> None:
    _ENDPOINTS_PATH.parent.mkdir(parents=True, exist_ok=True)
    _ENDPOINTS_PATH.write_text(json.dumps(data, indent=2), encoding="utf-8")


@mcp.tool()
def get_endpoint_status(host: str) -> dict:
    """Read-only check of the mock endpoint registry (status: ONLINE or ISOLATED)."""
    endpoints = _load_endpoints()
    entry = endpoints.get(host)
    if not entry:
        return {"host": host, "status": "ONLINE", "note": "not previously registered"}
    return {"host": host, **entry}


@mcp.tool()
def request_response_authorization(incident_id: str, action: str, justification: str) -> dict:
    """Formally request HUMAN AUTHORIZATION for a consequential action.

    This transitions the incident to WAITING_FOR_APPROVAL. The actual action
    must then be attempted through its tool call so TrueForge's approval
    checkpoint can pause the run for a human decision. Provide a clear
    ``justification`` - it is shown to the approver and kept in the audit trail.
    """
    if action not in _CONSEQUENTIAL_ACTIONS:
        raise SentinelForgeError(
            f"unknown consequential action {action!r}; allowed: {list(_CONSEQUENTIAL_ACTIONS)}"
        )
    if not justification or len(justification.strip()) < 10:
        raise SentinelForgeError("a meaningful justification (>=10 chars) is required")
    try:
        updated = STORE.request_approval(incident_id, action)
    except InvalidTransition as exc:
        raise SentinelForgeError(str(exc)) from exc
    STORE.audit(incident_id, "AUTHORIZATION_REQUESTED", {"action": action, "justification": justification})
    return {
        "requested": True,
        "action": action,
        "approval_state": updated["approval_state"],
        "current_phase": updated["current_phase"],
        "note": (
            "Now attempt the action itself; TrueForge will pause for a human "
            "decision before the tool executes."
        ),
    }


@mcp.tool()
def isolate_endpoint(incident_id: str, host: str) -> dict:
    """CONSEQUENTIAL: isolate a host by cutting its network access.

    REQUIRES HUMAN APPROVAL via the TrueForge approval checkpoint - without a
    configured approval requirement this tool refuses to run unless the
    incident shows recorded authorization. Updates only the MOCK endpoint
    registry; no real system is modified. Safe to retry (idempotent).
    """
    record = STORE.get(incident_id)
    if record["alert"]["hostname"] != host:
        raise SentinelForgeError(
            f"host {host!r} does not belong to incident {incident_id} "
            f"(expected {record['alert']['hostname']!r})"
        )
    if record["response_state"] == "ISOLATED":
        endpoints = _load_endpoints()
        isolated_at = endpoints.get(host, {}).get("isolated_at")
        return {
            "status": "ISOLATED",
            "already_isolated": True,
            "host": host,
            "isolated_at": isolated_at,
            "note": "endpoint was already isolated; no state changed (idempotent)",
        }
    if record["approval_state"] not in ("PENDING", "APPROVE"):
        raise SentinelForgeError(
            "REFUSED: no pending/approved authorization on this incident "
            f"(approval_state={record['approval_state']}). Raise it with "
            "request_response_authorization and obtain human approval."
        )

    # Record the harness-level approval, then mutate mock state atomically.
    STORE.resolve_approval(incident_id, "APPROVE", decided_by="trueforge-checkpoint")
    with _ENDPOINT_LOCK:
        endpoints = _load_endpoints()
        previous = endpoints.get(host, {})
        isolated_at = utc_now()
        endpoints[host] = {"status": "ISOLATED", "isolated_at": isolated_at}
        _save_endpoints(endpoints)

    result = {
        "status": "ISOLATED",
        "already_isolated": False,
        "host": host,
        "isolated_at": isolated_at,
        "previous_status": previous.get("status", "ONLINE"),
        "target": "mock endpoint registry (no real machine touched)",
    }
    STORE.apply_response(incident_id, "isolate_endpoint", result)
    return result


@mcp.tool()
def record_human_decision(incident_id: str, decision: str, decided_by: str = "human") -> dict:
    """Record the human's APPROVE or DENY decision for a pending authorization.

    Use this when the harness blocked the consequential tool call because the
    human DENIED the checkpoint - it closes the loop in the incident record.
    """
    updated = STORE.resolve_approval(incident_id, decision.upper(), decided_by=decided_by)

    def mutate(rec):
        if decision.upper() == "DENY":
            rec["current_phase"] = "DENIED"
            rec["response_state"] = "NOT_EXECUTED"

    updated = STORE.update(incident_id, mutate)
    return {
        "recorded": True,
        "decision": decision.upper(),
        "approval_state": updated["approval_state"],
        "current_phase": updated["current_phase"],
        "note": (
            "Per policy: do not retry the denied action automatically."
            if decision.upper() == "DENY"
            else ""
        ),
    }


@mcp.tool()
def finalize_incident_report(
    incident_id: str,
    executive_summary: str,
    conclusion: str,
) -> dict:
    """Close out the incident: freeze findings, evidence, risk and response into the final report."""
    record = STORE.get(incident_id)
    report = {
        "incident_id": incident_id,
        "generated_at": utc_now(),
        "executive_summary": executive_summary,
        "conclusion": conclusion,
        "alert": record["alert"],
        "findings": record["findings"],
        "evidence_refs": record["evidence_refs"],
        "iocs": record["iocs"],
        "risk": record["risk"],
        "confidence": record["confidence"],
        "recommended_action": record["recommended_action"],
        "approval_state": record["approval_state"],
        "response_state": record["response_state"],
    }
    STORE.finalize_report(incident_id, report)
    return report


@mcp.tool()
def get_audit_timeline(incident_id: str) -> dict:
    """Return the full chronological audit timeline for the incident."""
    events = STORE.timeline(incident_id)
    return {"incident_id": incident_id, "events_count": len(events), "timeline": events}


@mcp.tool()
def reset_demo(incident_id: str, host: str | None = None) -> dict:
    """Reset demo state for replay: deletes the stored incident and clears mock isolation."""
    result = STORE.reset(incident_id)
    if host:
        with _ENDPOINT_LOCK:
            endpoints = _load_endpoints()
            if host in endpoints and endpoints[host].get("status") == "ISOLATED":
                endpoints[host] = {"status": "ONLINE", "restored_at": utc_now()}
                _save_endpoints(endpoints)
    return {**result, "note": "scenario data unchanged; safe to replay from create_incident_session"}
