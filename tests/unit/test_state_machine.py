"""Unit tests: incident state machine and store behaviour (blueprint section S)."""

import pytest
from store import (
    PHASES,
    InvalidTransition,
    SentinelForgeError,
    can_transition,
)


@pytest.fixture()
def incident(tmp_path, monkeypatch):
    import store as store_mod

    monkeypatch.setattr(store_mod, "STATE_DIR", tmp_path / "state")
    record = store_mod.STORE.create("powershell_c2_beaconing")
    return record, store_mod.STORE


def test_happy_lifecycle(incident):
    _, store = incident
    inc = "INC-2026-0042"
    assert store.get(inc)["current_phase"] == "NEW"
    store.transition(inc, "INVESTIGATING")
    store.transition(inc, "EVIDENCE_READY")
    store.add_finding(
        inc,
        "PowerShell executed an encoded command",
        ["windows_events:evt_0193"],
        0.96,
        source_agent="log_investigator",
        category="encoded_command",
    )
    store.transition(inc, "ASSESSMENT_READY")
    rec = store.set_assessment(inc, ["encoded_command"], "isolate_endpoint")
    assert rec["risk"]["score"] == 20

    store.request_approval(inc, "isolate_endpoint")
    assert store.get(inc)["approval_state"] == "PENDING"

    store.resolve_approval(inc, "APPROVE")
    store.apply_response(inc, "isolate_endpoint", {"status": "ISOLATED"})
    final = store.finalize_report(inc, {"summary": "contained"})
    assert final["current_phase"] == "CLOSED"
    assert final["final_report"]["summary"] == "contained"


def test_illegal_transition_rejected(incident):
    _, store = incident
    inc = "INC-2026-0042"
    with pytest.raises(InvalidTransition):
        store.transition(inc, "CONTAINED")  # NEW -> CONTAINED not allowed


def test_finding_requires_evidence(incident):
    _, store = incident
    inc = "INC-2026-0042"
    with pytest.raises(SentinelForgeError):
        store.add_finding(inc, "unsupported claim", [], 0.9)


def test_confidence_bounds_enforced(incident):
    _, store = incident
    inc = "INC-2026-0042"
    with pytest.raises(SentinelForgeError):
        store.add_finding(inc, "overconfident", ["windows_events:evt_0192"], 1.5)


def test_duplicate_incident_refused(incident):
    _, store = incident
    with pytest.raises(SentinelForgeError):
        store.create("powershell_c2_beaconing")


def test_invalid_incident_id_shape():
    from store import IncidentStore

    with pytest.raises(SentinelForgeError):
        IncidentStore._path("not-an-id")


def test_approval_flow_guards(incident):
    _, store = incident
    inc = "INC-2026-0042"
    # approval before assessment is illegal
    with pytest.raises(SentinelForgeError):
        store.request_approval(inc, "isolate_endpoint")

    store.transition(inc, "INVESTIGATING")
    store.transition(inc, "EVIDENCE_READY")
    store.transition(inc, "ASSESSMENT_READY")
    store.set_assessment(inc, ["beacon_pattern"], "isolate_endpoint")

    # mismatched action refused
    with pytest.raises(SentinelForgeError):
        store.request_approval(inc, "some_other_action")

    store.request_approval(inc, "isolate_endpoint")
    # response without recorded approve refused
    with pytest.raises(SentinelForgeError):
        store.apply_response(inc, "isolate_endpoint", {"status": "ISOLATED"})

    store.resolve_approval(inc, "DENY")
    rec = store.get(inc)
    assert rec["approval_state"] == "DENY"
    # second resolve on a non-pending state refused
    with pytest.raises(SentinelForgeError):
        store.resolve_approval(inc, "APPROVE")


def test_reset_allows_replay(incident):
    _, store = incident
    inc = "INC-2026-0042"
    store.reset(inc)
    fresh = store.create("powershell_c2_beaconing")
    assert fresh["current_phase"] == "NEW"
    assert fresh["findings"] == []


def test_phase_graph_is_connected_to_closed():
    for phase in PHASES[:-1]:
        assert can_transition(phase, "CLOSED"), f"{phase} must reach CLOSED"
