from __future__ import annotations

from pathlib import Path

from ihadrs.integrations.secureops import (
    SecureOpsQueue,
    build_secureops_payload,
    normalize_api_base_url,
)


def test_build_secureops_payload_uses_stable_alert_id(sample_threat_event):
    payload = build_secureops_payload(
        sample_threat_event,
        device_id="device-1",
        endpoint_id="endpoint-1",
    )

    assert payload["alert_id"] == f"win-edr-TEST-PC-{sample_threat_event.threat_id}"
    assert payload["severity"] == "high"
    assert payload["event_type"] == "suspicious_powershell"
    assert payload["device_id"] == "device-1"
    assert payload["endpoint_id"] == "endpoint-1"
    assert payload["hostname"] == "TEST-PC"
    assert payload["process_name"] == "powershell.exe"
    assert payload["raw_event"]["rule_id"] == "R001"


def test_payload_contains_expected_iocs(sample_threat_event):
    payload = build_secureops_payload(
        sample_threat_event,
        device_id="device-1",
        endpoint_id="endpoint-1",
    )

    iocs = {(ioc["type"], ioc["value"]) for ioc in payload["iocs"]}
    assert ("process", "powershell.exe") in iocs
    assert ("hostname", "TEST-PC") in iocs


def test_normalize_api_base_url_accepts_host_without_api_suffix():
    assert normalize_api_base_url("http://127.0.0.1:8000") == "http://127.0.0.1:8000/api/v1"
    assert normalize_api_base_url("http://127.0.0.1:8000/api") == "http://127.0.0.1:8000/api/v1"
    assert normalize_api_base_url("http://127.0.0.1:8000/api/v1/") == "http://127.0.0.1:8000/api/v1"


def test_queue_success_removes_alert(tmp_path: Path):
    queue = SecureOpsQueue(tmp_path / "secureops_queue.db")
    queue.initialize()
    try:
        queue.enqueue({"alert_id": "win-edr-test-1", "title": "Test", "severity": "high"})
        assert queue.get_status()["queue_depth"] == 1

        queue.mark_success(["win-edr-test-1"])

        assert queue.get_status()["queue_depth"] == 0
        assert queue.get_due(10) == []
    finally:
        queue.close()


def test_queue_retry_uses_backoff_and_keeps_alert(tmp_path: Path):
    queue = SecureOpsQueue(tmp_path / "secureops_queue.db", backoff_seconds=[10])
    queue.initialize()
    try:
        queue.enqueue({"alert_id": "win-edr-test-1", "title": "Test", "severity": "critical"})
        due = queue.get_due(10)
        assert len(due) == 1

        queue.mark_retry(["win-edr-test-1"], 503, "SOC unavailable")

        status = queue.get_status()
        assert status["queue_depth"] == 1
        assert status["critical_high_queued"] == 1
        assert status["last_error"] == "SOC unavailable"
        assert queue.get_due(10) == []
    finally:
        queue.close()
