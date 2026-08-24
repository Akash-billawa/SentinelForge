"""Unit tests: transparent risk scoring (blueprint section R)."""


from store import RISK_WEIGHTS, calculate_risk


def test_full_signal_set_caps_at_100():
    risk = calculate_risk(list(RISK_WEIGHTS.keys()))
    assert risk["score"] == 100
    assert risk["severity"] == "CRITICAL"
    assert len(risk["signals"]) == len(RISK_WEIGHTS)


def test_scores_are_sum_of_fixed_weights():
    signals = ["powershell_anomaly", "encoded_command", "suspicious_dns"]
    expected = sum(RISK_WEIGHTS[s] for s in signals)
    risk = calculate_risk(signals)
    assert risk["score"] == expected
    assert {s["signal"] for s in risk["signals"]} == set(signals)


def test_severity_bands():
    assert calculate_risk([])["severity"] == "LOW"
    assert calculate_risk(["powershell_anomaly", "suspicious_dns"])["severity"] == "MEDIUM"
    assert calculate_risk(["powershell_anomaly", "encoded_command", "beacon_pattern"])[
        "severity"
    ] == "HIGH"


def test_unknown_signals_are_reported_not_scored():
    risk = calculate_risk(["powershell_anomaly", "made_up_signal"])
    assert risk["ignored_signals"] == ["made_up_signal"]
    assert risk["score"] == RISK_WEIGHTS["powershell_anomaly"]


def test_deterministic_for_same_input():
    a = calculate_risk(["beacon_pattern", "threat_intel_match"])
    b = calculate_risk(["threat_intel_match", "beacon_pattern"])
    assert a["score"] == b["score"]
    assert a["severity"] == b["severity"]


def test_no_opaque_numbers():
    risk = calculate_risk(["encoded_command"])
    assert risk["formula"]
    assert all(s["points"] == RISK_WEIGHTS[s["signal"]] for s in risk["signals"])
