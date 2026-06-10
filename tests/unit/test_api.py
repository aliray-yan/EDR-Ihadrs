"""
Unit tests for Phase 6 — REST API.

Tests cover:
    APIServer:      build, auth guard, rate limiting, all endpoints
    Rate Limiter:   token bucket logic
    Health probe:   /healthz no-auth endpoint
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest


# =============================================================================
# HELPERS
# =============================================================================

def _make_config(tmp_path: Path, api_enabled: bool = True) -> Any:
    from ihadrs.core.config import IHADRSConfig
    return IHADRSConfig.model_validate({
        "app": {"require_admin": False},
        "logging": {"console_output": False, "level": "WARNING"},
        "api": {
            "enabled": api_enabled,
            "host": "127.0.0.1",
            "port": 18765,
            "token": "test-token-for-unit-tests",
            "cors_origins": ["http://localhost:18765"],
            "rate_limit_requests": 100,
            "rate_limit_window_seconds": 60,
        },
        "detection": {"rules_file": "config/rules.yaml"},
        "response": {"mode": "manual"},
        "monitors": {"file_watch_paths": [str(tmp_path)], "ip_whitelist": []},
    })


def _make_test_client(config: Any) -> Any:
    """Build a FastAPI TestClient without starting uvicorn."""
    from fastapi.testclient import TestClient
    from ihadrs.api.server import APIServer

    server = APIServer(config)
    app = server._build_app()
    return TestClient(app, raise_server_exceptions=True), server


AUTH_HEADERS = {"X-IHADRS-Token": "test-token-for-unit-tests"}
BAD_HEADERS = {"X-IHADRS-Token": "wrong-token"}


# =============================================================================
# RATE LIMITER TESTS
# =============================================================================

class TestRateLimiter:

    def test_passes_under_limit(self):
        from ihadrs.api.server import _RateLimiter
        rl = _RateLimiter(requests_per_window=10, window_seconds=60)
        for _ in range(10):
            rl.check("client1")  # Should not raise

    def test_raises_at_limit(self):
        from ihadrs.api.server import _RateLimiter
        from ihadrs.exceptions import RateLimitError
        rl = _RateLimiter(requests_per_window=3, window_seconds=60)
        for _ in range(3):
            rl.check("client1")
        with pytest.raises(RateLimitError):
            rl.check("client1")

    def test_different_clients_tracked_separately(self):
        from ihadrs.api.server import _RateLimiter
        rl = _RateLimiter(requests_per_window=2, window_seconds=60)
        rl.check("client1")
        rl.check("client1")
        # client2 is unaffected
        rl.check("client2")
        rl.check("client2")

    def test_limit_resets_after_window(self):
        from ihadrs.api.server import _RateLimiter
        from ihadrs.exceptions import RateLimitError
        rl = _RateLimiter(requests_per_window=2, window_seconds=1)
        rl.check("c")
        rl.check("c")
        with pytest.raises(RateLimitError):
            rl.check("c")

        time.sleep(1.1)
        # Window expired — should pass again
        rl.check("c")  # Should not raise


# =============================================================================
# HEALTH PROBE (no auth)
# =============================================================================

class TestHealthProbe:

    def test_healthz_returns_ok(self, tmp_path):
        config = _make_config(tmp_path)
        client, _ = _make_test_client(config)
        response = client.get("/healthz")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert "version" in data

    def test_healthz_no_auth_required(self, tmp_path):
        """Health probe works without any authentication token."""
        config = _make_config(tmp_path)
        client, _ = _make_test_client(config)
        # No headers at all
        response = client.get("/healthz")
        assert response.status_code == 200


# =============================================================================
# AUTHENTICATION TESTS
# =============================================================================

class TestAuthentication:

    def test_missing_token_returns_401(self, tmp_path):
        config = _make_config(tmp_path)
        client, _ = _make_test_client(config)
        response = client.get("/api/v1/status")
        assert response.status_code == 401

    def test_wrong_token_returns_401(self, tmp_path):
        config = _make_config(tmp_path)
        client, _ = _make_test_client(config)
        response = client.get("/api/v1/status", headers=BAD_HEADERS)
        assert response.status_code == 401

    def test_correct_token_returns_200(self, tmp_path):
        config = _make_config(tmp_path)
        client, _ = _make_test_client(config)
        response = client.get("/api/v1/status", headers=AUTH_HEADERS)
        assert response.status_code == 200

    def test_bearer_token_format_accepted(self, tmp_path):
        """Authorization: Bearer {token} format is also accepted."""
        config = _make_config(tmp_path)
        client, _ = _make_test_client(config)
        response = client.get(
            "/api/v1/status",
            headers={"Authorization": "Bearer test-token-for-unit-tests"},
        )
        assert response.status_code == 200


# =============================================================================
# STATUS ENDPOINT
# =============================================================================

class TestStatusEndpoint:

    def test_returns_version(self, tmp_path):
        config = _make_config(tmp_path)
        client, _ = _make_test_client(config)
        response = client.get("/api/v1/status", headers=AUTH_HEADERS)
        assert response.status_code == 200
        data = response.json()
        assert "version" in data
        assert data["version"]

    def test_returns_status_field(self, tmp_path):
        config = _make_config(tmp_path)
        client, _ = _make_test_client(config)
        response = client.get("/api/v1/status", headers=AUTH_HEADERS)
        data = response.json()
        assert "status" in data
        assert data["status"] == "running"

    def test_returns_monitors_list(self, tmp_path):
        config = _make_config(tmp_path)
        client, server = _make_test_client(config)
        server.monitors = []
        response = client.get("/api/v1/status", headers=AUTH_HEADERS)
        data = response.json()
        assert "monitors" in data
        assert isinstance(data["monitors"], list)


# =============================================================================
# EVENTS ENDPOINT
# =============================================================================

class TestEventsEndpoint:

    def test_returns_events_structure_no_store(self, tmp_path):
        """Without event store returns empty list."""
        config = _make_config(tmp_path)
        client, _ = _make_test_client(config)
        response = client.get("/api/v1/events", headers=AUTH_HEADERS)
        assert response.status_code == 200
        data = response.json()
        assert "events" in data
        assert isinstance(data["events"], list)

    def test_with_mock_event_store(self, tmp_path):
        config = _make_config(tmp_path)
        client, server = _make_test_client(config)

        mock_store = AsyncMock()
        mock_store.get_events = AsyncMock(return_value=[
            {"event_id": "evt-001", "event_type": "process.created"}
        ])
        server.event_store = mock_store

        response = client.get("/api/v1/events", headers=AUTH_HEADERS)
        assert response.status_code == 200
        data = response.json()
        assert len(data["events"]) == 1
        assert data["events"][0]["event_id"] == "evt-001"

    def test_pagination_params_passed_to_store(self, tmp_path):
        config = _make_config(tmp_path)
        client, server = _make_test_client(config)

        mock_store = AsyncMock()
        mock_store.get_events = AsyncMock(return_value=[])
        server.event_store = mock_store

        client.get("/api/v1/events?limit=25&offset=100", headers=AUTH_HEADERS)
        mock_store.get_events.assert_called_once_with(
            limit=25, offset=100, event_type=None, severity=None
        )

    def test_limit_capped_at_500(self, tmp_path):
        """Limit > 500 is rejected by validation."""
        config = _make_config(tmp_path)
        client, _ = _make_test_client(config)
        response = client.get("/api/v1/events?limit=999", headers=AUTH_HEADERS)
        assert response.status_code == 422  # Unprocessable Entity


# =============================================================================
# THREATS ENDPOINT
# =============================================================================

class TestThreatsEndpoint:

    def test_returns_threats_structure_no_store(self, tmp_path):
        config = _make_config(tmp_path)
        client, _ = _make_test_client(config)
        response = client.get("/api/v1/threats", headers=AUTH_HEADERS)
        assert response.status_code == 200
        data = response.json()
        assert "threats" in data

    def test_get_threat_by_id_not_found(self, tmp_path):
        config = _make_config(tmp_path)
        client, server = _make_test_client(config)

        mock_store = AsyncMock()
        mock_store.get_threat_by_id = AsyncMock(return_value=None)
        server.event_store = mock_store

        response = client.get("/api/v1/threats/nonexistent-id", headers=AUTH_HEADERS)
        assert response.status_code == 404

    def test_get_threat_by_id_found(self, tmp_path):
        config = _make_config(tmp_path)
        client, server = _make_test_client(config)

        threat_data = {
            "threat_id": "threat-001",
            "severity": "HIGH",
            "attack_category": "Ransomware",
        }
        mock_store = AsyncMock()
        mock_store.get_threat_by_id = AsyncMock(return_value=threat_data)
        server.event_store = mock_store

        response = client.get("/api/v1/threats/threat-001", headers=AUTH_HEADERS)
        assert response.status_code == 200
        data = response.json()
        assert data["threat_id"] == "threat-001"

    def test_mark_false_positive(self, tmp_path):
        config = _make_config(tmp_path)
        client, server = _make_test_client(config)

        mock_store = AsyncMock()
        mock_store.mark_false_positive = AsyncMock(return_value=None)
        server.event_store = mock_store

        response = client.post(
            "/api/v1/threats/threat-001/fp",
            headers=AUTH_HEADERS,
            json={"reason": "Legitimate software update", "marked_by": "analyst"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        mock_store.mark_false_positive.assert_called_once()


# =============================================================================
# STATS ENDPOINT
# =============================================================================

class TestStatsEndpoint:

    def test_returns_error_without_store(self, tmp_path):
        config = _make_config(tmp_path)
        client, _ = _make_test_client(config)
        response = client.get("/api/v1/stats", headers=AUTH_HEADERS)
        assert response.status_code == 200
        data = response.json()
        # Should return some response even without store
        assert isinstance(data, dict)

    def test_with_mock_store(self, tmp_path):
        config = _make_config(tmp_path)
        client, server = _make_test_client(config)

        stats = {
            "total_threats": 42,
            "by_severity": {"CRITICAL": 5, "HIGH": 15, "MEDIUM": 22},
            "window_hours": 24,
        }
        mock_store = AsyncMock()
        mock_store.get_threat_stats = AsyncMock(return_value=stats)
        server.event_store = mock_store

        response = client.get("/api/v1/stats?hours=24", headers=AUTH_HEADERS)
        assert response.status_code == 200
        data = response.json()
        assert data["total_threats"] == 42


# =============================================================================
# RULES ENDPOINT
# =============================================================================

class TestRulesEndpoint:

    def test_returns_empty_without_engine(self, tmp_path):
        config = _make_config(tmp_path)
        client, _ = _make_test_client(config)
        response = client.get("/api/v1/rules", headers=AUTH_HEADERS)
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 0

    def test_returns_rules_from_engine(self, tmp_path):
        from pathlib import Path as Pth
        if not Pth("config/rules.yaml").exists():
            pytest.skip("config/rules.yaml not found")

        config = _make_config(tmp_path)
        client, server = _make_test_client(config)

        # Inject a mock detection engine with real rules
        from ihadrs.detection.rule_engine import RuleLoader, RuleEvaluator
        rules = RuleLoader.load_rules(Pth("config/rules.yaml"))
        evaluator = RuleEvaluator(rules)

        mock_engine = MagicMock()
        mock_engine._rule_evaluator = evaluator
        mock_engine._rule_evaluator._all_rules = rules
        server.detection_engine = mock_engine

        response = client.get("/api/v1/rules", headers=AUTH_HEADERS)
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 30
        rule_ids = [r["rule_id"] for r in data["rules"]]
        assert "R001" in rule_ids
        assert "R030" in rule_ids


# =============================================================================
# RESPONSE EXECUTE ENDPOINT
# =============================================================================

class TestResponseEndpoint:

    def test_execute_returns_success(self, tmp_path):
        config = _make_config(tmp_path)
        client, _ = _make_test_client(config)

        response = client.post(
            "/api/v1/response/execute",
            headers=AUTH_HEADERS,
            json={
                "action_type": "kill_process",
                "target": "malware.exe:4444",
                "threat_id": "threat-001",
            },
        )
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert data["action_type"] == "kill_process"

    def test_execute_missing_fields_returns_422(self, tmp_path):
        config = _make_config(tmp_path)
        client, _ = _make_test_client(config)

        response = client.post(
            "/api/v1/response/execute",
            headers=AUTH_HEADERS,
            json={"action_type": "kill_process"},  # Missing "target"
        )
        assert response.status_code == 422


# =============================================================================
# OPENAPI / DOCS
# =============================================================================

class TestAPIDocumentation:

    def test_openapi_schema_available(self, tmp_path):
        config = _make_config(tmp_path)
        client, _ = _make_test_client(config)
        response = client.get("/api/openapi.json")
        assert response.status_code == 200
        schema = response.json()
        assert "info" in schema
        assert schema["info"]["title"] == "IHADRS API"

    def test_swagger_docs_available(self, tmp_path):
        config = _make_config(tmp_path)
        client, _ = _make_test_client(config)
        response = client.get("/api/docs")
        assert response.status_code == 200