"""Integration tests: SentinelForge MCP server over real streamable HTTP.

Covers blueprint section Q: Commander->MCP->synthetic data flows, the
authorization gate, DENY path, idempotency, invalid ids, and replay/reset.
"""

import asyncio
import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import httpx
import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SERVER = REPO_ROOT / "mcp-server" / "server.py"


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def mcp_url():
    port = _free_port()
    env = {
        **os.environ,
        "SENTINELFORGE_MCP_PORT": str(port),
        "SENTINELFORGE_MCP_HOST": "127.0.0.1",
        "SENTINELFORGE_REPO_ROOT": str(REPO_ROOT),
    }
    proc = subprocess.Popen(
        [sys.executable, str(SERVER)],
        env=env,
        # Never PIPE without draining: uvicorn's request logs fill the OS
        # buffer (~64KB) and deadlock the server mid-suite on Windows.
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    url = f"http://127.0.0.1:{port}/mcp"
    deadline = time.time() + 20
    while time.time() < deadline:
        try:
            httpx.post(url, timeout=1)
            break  # any HTTP response means the listener is up
        except (httpx.HTTPError, OSError, ConnectionError):
            if proc.poll() is not None:
                _, err = proc.communicate()
                raise RuntimeError(f"server died: {err.decode()[:2000]}")
            time.sleep(0.25)
    yield url
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()


def call(url, name, arguments=None):
    """Sync helper: initialize an MCP session, call one tool, return parsed JSON."""
    return asyncio.run(_call_once(url, name, arguments or {}))


async def _call_once(url, name, arguments):
    from mcp import ClientSession
    from mcp.client.streamable_http import streamable_http_client

    try:
        client_ctx = streamable_http_client(url)
    except ImportError:  # older SDKs
        from mcp.client.streamable_http import streamablehttp_client as fn

        client_ctx = fn(url)

    async with client_ctx as streams:
        read, write = streams[0], streams[1]
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool(name, arguments)
            is_err = getattr(result, "is_error", None)
            if is_err is None:  # older SDK field name
                is_err = result.isError
            texts = [c.text for c in result.content if getattr(c, "type", "") == "text"]
            payload = None
            if texts:
                try:
                    payload = json.loads(texts[0])
                except json.JSONDecodeError:
                    payload = {"message": texts[0]}
            return {"isError": bool(is_err), "payload": payload}


def test_list_and_call_read_tools(mcp_url):
    alert = call(mcp_url, "get_alert")
    assert alert["isError"] is False
    assert alert["payload"]["incident_id"] == "INC-2026-0042"

    logs = call(
        mcp_url,
        "search_windows_logs",
        {"query": "powershell", "host": "WKS-042"},
    )
    assert logs["payload"]["count"] >= 1
    assert logs["payload"]["events"][0]["evidence_ref"].startswith("windows_events:")


def test_full_investigation_to_approval_to_containment(mcp_url):
    inc_id = "INC-2026-0042"
    # fresh session for deterministic replay inside this test
    call(mcp_url, "reset_demo", {"incident_id": inc_id, "host": "WKS-042"})
    created = call(mcp_url, "create_incident_session")
    assert created["payload"]["current_phase"] == "NEW"

    findings = [
        ("PowerShell ran with bypass flags", ["windows_events:evt_0192"], 0.97, "powershell_execution"),
        ("Encoded command executed", ["windows_events:evt_0193"], 0.96, "encoded_command"),
        ("Suspicious DNS resolution", ["dns:dns_0001"], 0.92, "suspicious_dns"),
        ("Periodic beaconing observed", ["flows:flow_0101", "flows:flow_0102"], 0.95, "beacon_pattern"),
        ("Known-malicious hash matched", ["ioc:sha256:b1946ac92492d2347c6235b4d2611184e0f3a1d2f4a5b6c7d8e9f00112233445"], 0.94, "threat_intel_match"),
    ]
    for finding, refs, conf, cat in findings:
        res = call(
            mcp_url,
            "record_finding",
            {
                "incident_id": inc_id,
                "finding": finding,
                "evidence_refs": refs,
                "confidence": conf,
                "source_agent": "specialist",
                "category": cat,
            },
        )
        assert res["isError"] is False

    call(mcp_url, "mark_investigation_complete", {"incident_id": inc_id})
    corr = call(mcp_url, "correlate_evidence", {"incident_id": inc_id})
    assert corr["payload"]["risk_signals"]
    risk = call(mcp_url, "calculate_risk_score", {"incident_id": inc_id})
    assert risk["payload"]["score"] >= 70
    assert risk["payload"]["recommended_action"] == "isolate_endpoint"

    auth = call(
        mcp_url,
        "request_response_authorization",
        {
            "incident_id": inc_id,
            "action": "isolate_endpoint",
            "justification": "Confirmed C2 beaconing from WKS-042; containment required.",
        },
    )
    assert auth["payload"]["approval_state"] == "PENDING"

    iso = call(mcp_url, "isolate_endpoint", {"incident_id": inc_id, "host": "WKS-042"})
    assert iso["payload"]["status"] == "ISOLATED"

    status = call(mcp_url, "get_endpoint_status", {"host": "WKS-042"})
    assert status["payload"]["status"] == "ISOLATED"

    report = call(
        mcp_url,
        "finalize_incident_report",
        {
            "incident_id": inc_id,
            "executive_summary": "Synthetic C2 incident contained.",
            "conclusion": "Beaconing confirmed across log, network and artifact evidence.",
        },
    )
    assert report["payload"]["response_state"] == "ISOLATED"

    timeline = call(mcp_url, "get_audit_timeline", {"incident_id": inc_id})
    events = [e["event"] for e in timeline["payload"]["timeline"]]
    assert "APPROVAL_REQUESTED" in events
    assert "RESPONSE_EXECUTED" in events


def test_isolate_refused_without_authorization(mcp_url):
    call(mcp_url, "reset_demo", {"incident_id": "INC-2026-0042"})
    call(mcp_url, "create_incident_session")
    res = call(mcp_url, "isolate_endpoint", {"incident_id": "INC-2026-0042", "host": "WKS-042"})
    assert res["isError"] is True
    assert "REFUSED" in json.dumps(res["payload"])


def test_isolate_is_idempotent(mcp_url):
    inc_id = "INC-2026-0042"
    call(mcp_url, "reset_demo", {"incident_id": inc_id, "host": "WKS-042"})
    call(mcp_url, "create_incident_session")
    for finding, refs, conf, cat in [
        ("powershell anomaly", ["windows_events:evt_0192"], 0.9, "powershell_execution"),
        ("encoded command", ["windows_events:evt_0193"], 0.9, "encoded_command"),
        ("beacon pattern", ["flows:flow_0101"], 0.9, "beacon_pattern"),
        ("dns anomaly", ["dns:dns_0001"], 0.8, "suspicious_dns"),
    ]:
        call(mcp_url, "record_finding", {
            "incident_id": inc_id, "finding": finding,
            "evidence_refs": refs, "confidence": conf, "category": cat,
        })
    call(mcp_url, "mark_investigation_complete", {"incident_id": inc_id})
    call(mcp_url, "correlate_evidence", {"incident_id": inc_id})
    risk = call(mcp_url, "calculate_risk_score", {"incident_id": inc_id})["payload"]
    assert risk["recommended_action"] == "isolate_endpoint", risk
    call(mcp_url, "request_response_authorization", {
        "incident_id": inc_id, "action": "isolate_endpoint",
        "justification": "test idempotency of containment",
    })
    first = call(mcp_url, "isolate_endpoint", {"incident_id": inc_id, "host": "WKS-042"})
    second = call(mcp_url, "isolate_endpoint", {"incident_id": inc_id, "host": "WKS-042"})
    assert first["payload"]["status"] == "ISOLATED"
    assert second["payload"]["status"] == "ISOLATED"
    assert second["payload"]["already_isolated"] is True


def test_deny_path_records_decision_and_blocks_retry(mcp_url):
    inc_id = "INC-2026-0042"
    call(mcp_url, "reset_demo", {"incident_id": inc_id, "host": "WKS-042"})
    call(mcp_url, "create_incident_session")
    for finding, refs, conf, cat in [
        ("powershell anomaly", ["windows_events:evt_0192"], 0.9, "powershell_execution"),
        ("beacon pattern", ["flows:flow_0101"], 0.9, "beacon_pattern"),
        ("threat-intel hash match", ["ioc:sha256:b1946ac92492d2347c6235b4d2611184e0f3a1d2f4a5b6c7d8e9f00112233445"], 0.9, "threat_intel_match"),
        ("suspicious dns", ["dns:dns_0001"], 0.8, "suspicious_dns"),
        ("encoded command", ["windows_events:evt_0193"], 0.9, "encoded_command"),
    ]:
        call(mcp_url, "record_finding", {
            "incident_id": inc_id, "finding": finding,
            "evidence_refs": refs, "confidence": conf, "category": cat,
        })
    call(mcp_url, "mark_investigation_complete", {"incident_id": inc_id})
    call(mcp_url, "correlate_evidence", {"incident_id": inc_id})
    call(mcp_url, "calculate_risk_score", {"incident_id": inc_id})
    call(mcp_url, "request_response_authorization", {
        "incident_id": inc_id, "action": "isolate_endpoint",
        "justification": "operator will deny this one",
    })
    denied = call(mcp_url, "record_human_decision", {
        "incident_id": inc_id, "decision": "DENY", "decided_by": "tester",
    })
    assert denied["payload"]["approval_state"] == "DENY"
    assert denied["payload"]["current_phase"] == "DENIED"

    # after DENY the consequential tool must refuse (no pending approval left)
    res = call(mcp_url, "isolate_endpoint", {"incident_id": inc_id, "host": "WKS-042"})
    assert res["isError"] is True


def test_invalid_incident_id_clean_error(mcp_url):
    res = call(mcp_url, "get_incident_context", {"incident_id": "BOGUS"})
    assert res["isError"] is True
