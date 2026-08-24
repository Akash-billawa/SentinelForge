"""Scenario replay test: full deterministic investigation against ground truth.

Simulates exactly what the SOC Commander must discover via MCP tools and
validates the outcome against scenarios/.../expected_findings.json.
No LLM involved - this proves the dataset + tools + scoring are coherent and
replayable (blueprint section V: "Demo can be reset and replayed").
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "mcp-server"))

import store as store_mod
from store import ScenarioStore

INCIDENT = "INC-2026-0042"


@pytest.fixture()
def fresh_store(tmp_path, monkeypatch):
    monkeypatch.setattr(store_mod, "STATE_DIR", tmp_path / "state")
    return store_mod.STORE


def _investigate(store: store_mod.IncidentStore) -> dict:
    """Deterministic commander flow using ONLY tool-visible data."""
    scenario = ScenarioStore()

    # --- Log specialist -----------------------------------------------------
    events = scenario.windows_events(host="WKS-042", query="powershell")
    ps_events = [e for e in events if "powershell.exe" in (e.get("image") or e.get("script_block_text") or "")]
    assert ps_events
    suspicious = scenario.find_process("proc_0051")
    assert suspicious and suspicious["name"] == "powershell.exe"
    meta = scenario.file_metadata(path="C:\\Users\\svc_backup\\AppData\\Roaming\\win_update.ps1")

    store.create("powershell_c2_beaconing")
    store.add_finding(
        INCIDENT,
        "PowerShell executed with bypass flags from suspicious lineage",
        [e["evidence_ref"] for e in ps_events[:1]] + ["process_tree:proc_0051"],
        0.97,
        source_agent="log_investigator",
        category="powershell_execution",
    )
    script_blocks = [e for e in events if e.get("action") == "script_block_logged"]
    assert script_blocks, "encoded command event must exist in data"
    store.add_finding(
        INCIDENT,
        "PowerShell executed an encoded command",
        [script_blocks[0]["evidence_ref"], meta["evidence_ref"]],
        0.96,
        source_agent="log_investigator",
        category="encoded_command",
    )

    # --- Network specialist ---------------------------------------------------
    dns = scenario.dns_logs(host="WKS-042")
    flows = scenario.network_flows(host="WKS-042")
    by_dst: dict[str, list] = {}
    for f in flows:
        by_dst.setdefault(f["dst_ip"], []).append(f)
    beacon_dst, beacon_flows = max(by_dst.items(), key=lambda kv: len(kv[1]))
    assert len(beacon_flows) >= 3
    store.add_finding(
        INCIDENT,
        f"Periodic outbound connections to single external endpoint {beacon_dst}",
        [f["evidence_ref"] for f in beacon_flows],
        0.95,
        source_agent="network_investigator",
        category="beacon_pattern",
    )
    noncorp = [d for d in dns if not d["query"].endswith("corp.example")]
    assert noncorp, "expected at least one non-corporate DNS query"
    store.add_finding(
        INCIDENT,
        "Suspicious DNS resolution of non-corporate domain",
        [noncorp[0]["evidence_ref"]],
        0.92,
        source_agent="network_investigator",
        category="suspicious_dns",
    )

    # --- Intel + artifact -------------------------------------------------------
    ioc_hash = scenario.lookup_ioc(meta["sha256"])
    assert ioc_hash["verdict"] == "malicious"
    store.add_finding(
        INCIDENT,
        "Artifact hash matches known-malicious indicator",
        [ioc_hash["evidence_ref"], meta["evidence_ref"]],
        0.94,
        source_agent="malware_investigator",
        category="threat_intel_match",
    )

    # --- IOC capture (commander records every indicator discovered) -----------
    indicators = [noncorp[0]["query"], beacon_dst, meta["sha256"]]
    store.add_iocs(INCIDENT, [scenario.lookup_ioc(i) for i in indicators])

    from analyzers.powershell_analyzer import analyze_powershell_text

    sample = (
        Path(__file__).resolve().parents[2]
        / "scenarios/powershell_c2_beaconing/suspicious_artifact.ps1"
    ).read_text(encoding="utf-8")
    analysis = analyze_powershell_text(sample)
    store.add_finding(
        INCIDENT,
        f"Sandbox static analysis verdict: {analysis['verdict']}",
        [meta["evidence_ref"]],
        0.9,
        source_agent="malware_investigator",
        category="suspicious_artifact",
    )

    # --- Fusion ------------------------------------------------------------------
    store.transition(INCIDENT, "INVESTIGATING")
    store.transition(INCIDENT, "EVIDENCE_READY")
    store.transition(INCIDENT, "ASSESSMENT_READY")
    signals = ["powershell_anomaly", "encoded_command", "suspicious_dns", "beacon_pattern", "threat_intel_match", "suspicious_artifact"]
    rec = store.set_assessment(INCIDENT, signals, "isolate_endpoint")
    return rec


def test_replay_matches_expected_findings(fresh_store):
    expected = ScenarioStore().expected_findings()
    rec = _investigate(fresh_store)

    exp_risk = expected["expected_risk"]
    assert exp_risk["score_min"] <= rec["risk"]["score"] <= exp_risk["score_max"]
    assert rec["risk"]["severity"] == exp_risk["severity"]
    assert rec["recommended_action"] == expected["expected_recommended_action"]

    cited = set(rec["evidence_refs"])
    missing_evidence = []
    for exp in expected["findings"]:
        if not set(exp["evidence"]) & cited:
            missing_evidence.append(exp["finding"])
    assert missing_evidence == [], f"findings with no cited evidence: {missing_evidence}"

    ioc_values = {ioc["value"] for ioc in rec["iocs"]} | {
        ref.split(":", 2)[-1] for ref in cited if ref.startswith("ioc:")
    }
    for want in expected["expected_iocs"]:
        assert any(want in v or v in want for v in ioc_values), f"missing IOC {want}"


def test_replay_is_deterministic_across_resets(fresh_store):
    first = _investigate(fresh_store)
    risk_one = first["risk"]

    fresh_store.reset(INCIDENT)
    second = _investigate(fresh_store)

    assert second["risk"]["score"] == risk_one["score"]
    assert [f["finding"] for f in second["findings"]] == [f["finding"] for f in first["findings"]]
