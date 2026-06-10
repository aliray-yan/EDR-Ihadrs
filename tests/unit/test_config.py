"""
Unit tests for core.config — configuration loading and validation.

Tests verify:
- Settings.yaml loads and parses correctly
- JSON Schema validation catches invalid values
- Pydantic model validation catches type errors
- Environment variable overrides work
- ConfigFileNotFoundError for missing file
- ConfigValidationError for invalid values
- Default values are applied correctly
- IHADRSConfig is frozen (immutable after load)
"""

from __future__ import annotations

import os
import textwrap
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest
import yaml

from ihadrs.core.config import ConfigLoader, IHADRSConfig
from ihadrs.exceptions import (
    ConfigFileNotFoundError,
    ConfigSchemaError,
    ConfigValidationError,
    IHADRSError,
)


# =============================================================================
# HELPERS
# =============================================================================

def _write_yaml(path: Path, data: dict[str, Any]) -> None:
    """Write a dict as YAML to the given path."""
    with path.open("w") as f:
        yaml.dump(data, f)


def _minimal_config() -> dict[str, Any]:
    """Return a minimal valid configuration dict."""
    return {
        "app": {"require_admin": False},
        "logging": {"level": "DEBUG", "console_output": False},
        "detection": {"rules_file": "config/rules.yaml"},
        "response": {"mode": "manual"},
        "api": {"enabled": False, "token": "test-token"},
        "monitors": {"enabled_monitors": ["process"]},
    }


# =============================================================================
# FILE LOADING
# =============================================================================

class TestConfigFileLoading:
    """Config file read operations."""

    def test_load_valid_yaml_returns_config(self, tmp_path: Path) -> None:
        config_path = tmp_path / "settings.yaml"
        _write_yaml(config_path, _minimal_config())
        config = ConfigLoader.load(config_path)
        assert isinstance(config, IHADRSConfig)

    def test_missing_file_raises_config_file_not_found(self, tmp_path: Path) -> None:
        missing = tmp_path / "does_not_exist.yaml"
        with pytest.raises(ConfigFileNotFoundError) as exc_info:
            ConfigLoader.load(missing)
        assert str(missing) in str(exc_info.value)

    def test_invalid_yaml_syntax_raises_config_validation_error(
        self, tmp_path: Path
    ) -> None:
        config_path = tmp_path / "bad.yaml"
        config_path.write_text("key: [unclosed bracket\n  nested: bad")
        with pytest.raises(ConfigValidationError):
            ConfigLoader.load(config_path)

    def test_non_dict_yaml_root_raises_error(self, tmp_path: Path) -> None:
        config_path = tmp_path / "list.yaml"
        config_path.write_text("- item1\n- item2\n")
        with pytest.raises(ConfigValidationError):
            ConfigLoader.load(config_path)

    def test_empty_yaml_uses_all_defaults(self, tmp_path: Path) -> None:
        config_path = tmp_path / "empty.yaml"
        config_path.write_text("{}\n")
        # Empty config should load with all defaults
        config = ConfigLoader.load(config_path)
        assert config.app.name == "IHADRS"
        assert config.logging.level == "INFO"

    def test_load_full_settings_yaml(self) -> None:
        """Load the actual project settings.yaml file."""
        import warnings
        settings_path = Path("config/settings.yaml")
        if not settings_path.exists():
            pytest.skip("config/settings.yaml not found — run from project root")
        with warnings.catch_warnings(record=True):
            warnings.simplefilter("always")
            config = ConfigLoader.load(settings_path)
        assert config.app.name == "IHADRS"


# =============================================================================
# DEFAULT VALUES
# =============================================================================

class TestDefaultValues:
    """Unspecified fields should receive correct defaults."""

    @pytest.fixture
    def config(self, tmp_path: Path) -> IHADRSConfig:
        config_path = tmp_path / "settings.yaml"
        _write_yaml(config_path, {})
        return ConfigLoader.load(config_path)

    def test_app_defaults(self, config: IHADRSConfig) -> None:
        assert config.app.name == "IHADRS"
        assert config.app.require_admin is True

    def test_logging_defaults(self, config: IHADRSConfig) -> None:
        assert config.logging.level == "INFO"
        assert config.logging.json_format is True
        assert config.logging.retention_days == 30

    def test_response_mode_default(self, config: IHADRSConfig) -> None:
        assert config.response.mode == "semi_auto"

    def test_ml_defaults(self, config: IHADRSConfig) -> None:
        assert config.ml.enabled is True
        assert config.ml.anomaly_threshold == -0.5
        assert config.ml.contamination == 0.05

    def test_performance_defaults(self, config: IHADRSConfig) -> None:
        assert config.performance.cpu_budget_average_pct == 3.0
        assert config.performance.ram_budget_max_mb == 200

    def test_alerting_defaults(self, config: IHADRSConfig) -> None:
        assert config.alerting.desktop_notifications is True
        assert config.alerting.email.enabled is False
        assert config.alerting.webhook.enabled is False


# =============================================================================
# VALIDATION
# =============================================================================

class TestValidation:
    """Invalid config values should raise ConfigValidationError."""

    def _load_with(self, tmp_path: Path, overrides: dict[str, Any]) -> IHADRSConfig:
        data = _minimal_config()
        data.update(overrides)
        path = tmp_path / "settings.yaml"
        _write_yaml(path, data)
        return ConfigLoader.load(path)

    def test_invalid_log_level_raises(self, tmp_path: Path) -> None:
        with pytest.raises((ConfigValidationError, ConfigSchemaError, IHADRSError)):
            self._load_with(tmp_path, {"logging": {"level": "VERBOSE"}})

    def test_invalid_response_mode_raises(self, tmp_path: Path) -> None:
        with pytest.raises((ConfigValidationError, ConfigSchemaError, IHADRSError)):
            self._load_with(tmp_path, {"response": {"mode": "aggressive"}})

    def test_anomaly_threshold_above_zero_raises(self, tmp_path: Path) -> None:
        with pytest.raises((ConfigValidationError, ConfigSchemaError, IHADRSError)):
            self._load_with(tmp_path, {"ml": {"anomaly_threshold": 0.5}})

    def test_anomaly_threshold_below_minus_one_raises(self, tmp_path: Path) -> None:
        with pytest.raises((ConfigValidationError, ConfigSchemaError, IHADRSError)):
            self._load_with(tmp_path, {"ml": {"anomaly_threshold": -2.0}})

    def test_api_enabled_without_token_warns(self, tmp_path: Path) -> None:
        """API enabled without token emits a UserWarning (not a hard error)."""
        import warnings
        config_path = tmp_path / "settings.yaml"
        _write_yaml(config_path, {"api": {"enabled": True}})
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            config = ConfigLoader.load(config_path)
            # Should load successfully
            assert config.api.enabled is True
            # But should have warned
            warning_messages = [str(x.message) for x in w]
            assert any("token" in msg.lower() for msg in warning_messages)

    def test_negative_retention_days_raises(self, tmp_path: Path) -> None:
        with pytest.raises((ConfigValidationError, ConfigSchemaError, IHADRSError)):
            self._load_with(tmp_path, {"logging": {"retention_days": -1}})

    def test_retention_days_zero_raises(self, tmp_path: Path) -> None:
        with pytest.raises((ConfigValidationError, ConfigSchemaError, IHADRSError)):
            self._load_with(tmp_path, {"logging": {"retention_days": 0}})


# =============================================================================
# ENVIRONMENT VARIABLE OVERRIDES
# =============================================================================

class TestEnvironmentVariableOverrides:
    """Env vars should override YAML values."""

    def test_log_level_env_override(self, tmp_path: Path) -> None:
        config_path = tmp_path / "settings.yaml"
        _write_yaml(config_path, {"logging": {"level": "INFO"}})

        with patch.dict(os.environ, {"IHADRS_LOG_LEVEL": "DEBUG"}):
            config = ConfigLoader.load(config_path)

        assert config.logging.level == "DEBUG"

    def test_api_host_env_override(self, tmp_path: Path) -> None:
        config_path = tmp_path / "settings.yaml"
        _write_yaml(config_path, {
            "api": {"enabled": False, "host": "127.0.0.1", "token": "tok"}
        })

        with patch.dict(os.environ, {"IHADRS_API_HOST": "0.0.0.0"}):
            config = ConfigLoader.load(config_path)

        assert config.api.host == "0.0.0.0"

    def test_api_port_env_override_coerced_to_int(self, tmp_path: Path) -> None:
        config_path = tmp_path / "settings.yaml"
        _write_yaml(config_path, {
            "api": {"enabled": False, "port": 8765, "token": "tok"}
        })

        with patch.dict(os.environ, {"IHADRS_API_PORT": "9999"}):
            config = ConfigLoader.load(config_path)

        assert config.api.port == 9999

    def test_boolean_env_override_true(self, tmp_path: Path) -> None:
        config_path = tmp_path / "settings.yaml"
        _write_yaml(config_path, {"api": {"enabled": True, "token": "tok"}})

        with patch.dict(os.environ, {"IHADRS_API_ENABLED": "false"}):
            config = ConfigLoader.load(config_path)

        assert config.api.enabled is False

    def test_float_env_override(self, tmp_path: Path) -> None:
        config_path = tmp_path / "settings.yaml"
        _write_yaml(config_path, {})

        with patch.dict(os.environ, {"IHADRS_ANOMALY_THRESHOLD": "-0.3"}):
            config = ConfigLoader.load(config_path)

        assert config.ml.anomaly_threshold == pytest.approx(-0.3)

    def test_env_var_takes_precedence_over_yaml(self, tmp_path: Path) -> None:
        config_path = tmp_path / "settings.yaml"
        _write_yaml(config_path, {"logging": {"level": "ERROR"}})

        with patch.dict(os.environ, {"IHADRS_LOG_LEVEL": "DEBUG"}):
            config = ConfigLoader.load(config_path)

        # ENV should win over YAML
        assert config.logging.level == "DEBUG"


# =============================================================================
# IMMUTABILITY
# =============================================================================

class TestConfigImmutability:
    """IHADRSConfig must be frozen after loading."""

    def test_config_is_frozen(self, tmp_path: Path) -> None:
        """IHADRSConfig declares frozen=True in model_config."""
        from ihadrs.core.config import IHADRSConfig
        assert IHADRSConfig.model_config.get("frozen") is True


# =============================================================================
# CORRECT CONFIG VALUES ROUNDTRIP
# =============================================================================

class TestConfigValueRoundtrip:
    """Verify specific values survive YAML → ConfigLoader → IHADRSConfig."""

    def test_custom_data_dir_preserved(self, tmp_path: Path) -> None:
        config_path = tmp_path / "settings.yaml"
        custom_dir = str(tmp_path / "custom_data")
        _write_yaml(config_path, {"app": {"data_dir": custom_dir}})
        config = ConfigLoader.load(config_path)
        assert str(config.app.data_dir) == custom_dir

    def test_disabled_rules_list_preserved(self, tmp_path: Path) -> None:
        config_path = tmp_path / "settings.yaml"
        _write_yaml(config_path, {
            "detection": {"disabled_rules": ["R001", "R029"]}
        })
        config = ConfigLoader.load(config_path)
        assert "R001" in config.detection.disabled_rules
        assert "R029" in config.detection.disabled_rules

    def test_email_recipients_list_preserved(self, tmp_path: Path) -> None:
        config_path = tmp_path / "settings.yaml"
        emails = ["a@example.com", "b@example.com"]
        _write_yaml(config_path, {
            "alerting": {"email": {"enabled": False, "to_addresses": emails}}
        })
        config = ConfigLoader.load(config_path)
        assert config.alerting.email.to_addresses == emails

    def test_full_auto_response_mode(self, tmp_path: Path) -> None:
        config_path = tmp_path / "settings.yaml"
        _write_yaml(config_path, {"response": {"mode": "full_auto"}})
        config = ConfigLoader.load(config_path)
        assert config.response.mode == "full_auto"

    def test_multiple_monitor_types(self, tmp_path: Path) -> None:
        config_path = tmp_path / "settings.yaml"
        monitors = ["process", "network", "file", "registry"]
        _write_yaml(config_path, {"monitors": {"enabled_monitors": monitors}})
        config = ConfigLoader.load(config_path)
        assert set(config.monitors.enabled_monitors) == set(monitors)