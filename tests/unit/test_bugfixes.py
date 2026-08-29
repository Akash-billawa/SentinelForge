"""Regression tests for bugs found while verifying the project end-to-end.

Each test below failed before its corresponding fix. They guard behaviour that
the original suite passed over: it exercised only the happy path with unique
signals, whole-minute timestamps and pre-existing state.
"""

import pytest
import store as store_mod
from store import RISK_WEIGHTS, ScenarioStore, calculate_risk
from tools.analysis import _gap_seconds, _parse_timestamp

INCIDENT = "INC-2026-0042"


@pytest.fixture()
def isolated_state(tmp_path, monkeypatch):
    """Point every state write at a temp dir (incidents, audit AND endpoints)."""
    monkeypatch.setattr(store_mod, "STATE_DIR", tmp_path / "state")
    return tmp_path / "state"


# --- transparent risk scoring ------------------------------------------------


def test_repeated_signals_score_once():
    """Corroboration is not extra risk.

    Five PowerShell findings plus one DNS finding used to total 100/CRITICAL
    and auto-cross the >=70 containment threshold on a single real signal.
    """
    risk = calculate_risk(["powershell_anomaly"] * 5 + ["suspicious_dns"])
    assert risk["score"] == RISK_WEIGHTS["powershell_anomaly"] + RISK_WEIGHTS["suspicious_dns"]
    assert risk["severity"] == "MEDIUM"
    assert [s["signal"] for s in risk["signals"]] == ["powershell_anomaly", "suspicious_dns"]
    assert risk["score"] < 70, "must not reach the containment threshold"


def test_repeated_unknown_signals_reported_once():
    risk = calculate_risk(["invented_signal", "invented_signal"])
    assert risk["ignored_signals"] == ["invented_signal"]
    assert risk["score"] == 0


def test_breakdown_still_sums_to_score():
    risk = calculate_risk(["beacon_pattern", "beacon_pattern", "encoded_command"])
    assert sum(s["points"] for s in risk["signals"]) == risk["score"]


# --- dataset queries ---------------------------------------------------------


def test_half_open_time_ranges_do_not_crash():
    """Only one of time_start/time_end is a valid, documented tool call."""
    store = ScenarioStore()
    later = store.windows_events(time_range=("2026-08-24T10:42:12Z", None))
    earlier = store.windows_events(time_range=(None, "2026-08-24T10:42:11Z"))
    assert later and earlier
    assert {e["event_id"] for e in later}.isdisjoint({e["event_id"] for e in earlier})


def test_half_open_ranges_apply_to_dns_and_flows():
    store = ScenarioStore()
    assert store.dns_logs(time_range=(None, "2099-01-01T00:00:00Z"))
    assert store.network_flows(time_range=("2000-01-01T00:00:00Z", None))


# --- beacon cadence arithmetic ----------------------------------------------


def test_flow_gaps_respect_hours_and_days():
    """Old code sliced minutes/seconds only, so it discarded hour and date."""
    flows = [
        {"timestamp": "2026-08-24T10:59:50Z"},
        {"timestamp": "2026-08-24T11:00:05Z"},
        {"timestamp": "2026-08-25T11:00:05Z"},
    ]
    assert _gap_seconds(flows) == [15, 86400]


def test_scenario_beacon_cadence_is_fifteen_seconds():
    flows = sorted(
        (f for f in ScenarioStore().network_flows(host="WKS-042") if f["dst_ip"] == "203.0.113.66"),
        key=lambda f: f["timestamp"],
    )
    assert _gap_seconds(flows) == [15, 15, 15]


def test_timestamp_parser_accepts_zulu():
    assert _parse_timestamp("2026-08-24T10:42:17Z").hour == 10


# --- replay / state hygiene --------------------------------------------------


def test_reset_is_idempotent(isolated_state):
    """The console resets before every START, including the very first run."""
    first = store_mod.STORE.reset(INCIDENT)
    assert first["existed"] is False

    store_mod.STORE.create("powershell_c2_beaconing")
    second = store_mod.STORE.reset(INCIDENT)
    assert second["existed"] is True
    assert store_mod.STORE.reset(INCIDENT)["existed"] is False


def test_endpoint_registry_honors_patched_state_dir(isolated_state):
    """Mock isolation must never leak into the real demo state directory."""
    from tools import response

    response._save_endpoints({"WKS-042": {"status": "ISOLATED"}})
    assert (isolated_state / "endpoints.json").is_file()
    assert response._load_endpoints()["WKS-042"]["status"] == "ISOLATED"
    assert response._endpoints_path().parent == isolated_state


def test_create_incident_session_resumes(isolated_state):
    """A retried turn must resume the session, not dead-end the investigation."""
    from tools.analysis import create_incident_session

    first = create_incident_session()
    store_mod.STORE.add_finding(
        INCIDENT, "powershell ran", ["windows_events:evt_0192"], 0.9, category="powershell_execution"
    )
    resumed = create_incident_session()
    assert resumed["incident_id"] == first["incident_id"]
    assert len(resumed["findings"]) == 1, "resume must preserve recorded findings"


def test_low_risk_rationale_does_not_claim_threshold(isolated_state):
    from tools.analysis import calculate_risk_score, create_incident_session

    create_incident_session()
    store_mod.STORE.add_finding(
        INCIDENT, "powershell ran", ["windows_events:evt_0192"], 0.9, category="powershell_execution"
    )
    assessment = calculate_risk_score(INCIDENT)
    assert assessment["recommended_action"] == "monitor"
    assert "below the containment threshold" in assessment["rationale"]
