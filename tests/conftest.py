from __future__ import annotations
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

"""
conftest.py — Pytest configuration and shared fixtures for IHADRS tests.

Fixtures:
    config          — In-memory IHADRSConfig with test defaults
    event_bus       — Started EventBus instance (auto-stopped)
    resource_manager — Started ResourceManager (auto-stopped)
    scheduler       — Started TaskScheduler (auto-stopped)
    tmp_log_dir     — Temporary directory for log files
    sample_process_event — Factory for ProcessEvent test data
    sample_network_event — Factory for NetworkEvent test data
    sample_file_event    — Factory for FileEvent test data
    sample_threat_event  — Factory for ThreatEvent test data
"""


import asyncio
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Generator
from unittest.mock import MagicMock

import pytest

from ihadrs.constants import (
    AttackCategory,
    EventType,
    MonitorType,
    ResponseStatus,
    Severity,
)
from ihadrs.core.config import IHADRSConfig
from ihadrs.core.event_bus import EventBus
from ihadrs.core.resource_manager import ResourceManager
from ihadrs.core.scheduler import TaskScheduler
from ihadrs.models.events import (
    FileEvent,
    NetworkEvent,
    ProcessEvent,
    make_file_event,
    make_network_connection_event,
    make_process_created_event,
)
from ihadrs.models.threats import (
    ProcessContext,
    RemediationStep,
    ThreatEvent,
    ThreatEvidence,
)


# =============================================================================
# ASYNCIO CONFIGURATION
# =============================================================================

@pytest.fixture(scope="session")
def event_loop_policy():
    """Use default asyncio event loop policy."""
    return asyncio.DefaultEventLoopPolicy()


# =============================================================================
# CONFIGURATION FIXTURE
# =============================================================================

@pytest.fixture
def config(tmp_path: Path) -> IHADRSConfig:
    """
    Return a minimal IHADRSConfig with test-safe defaults.

    All file paths point to tmp_path to avoid cluttering the repository
    and to ensure tests are isolated from production config.
    """
    from pydantic import SecretStr

    # Build config with overridden paths
    raw_config: dict = {
        "app": {
            "data_dir": str(tmp_path / "data"),
            "require_admin": False,  # Tests don't run as admin
        },
        "logging": {
            "level": "DEBUG",
            "log_dir": str(tmp_path / "logs"),
            "json_format": True,
            "console_output": False,  # Suppress console output in tests
        },
        "monitors": {
            "enabled_monitors": ["process", "network", "file"],
            "file_watch_paths": [str(tmp_path / "watch")],
        },
        "detection": {
            "rules_file": "config/rules.yaml",
            "disabled_rules": [],
        },
        "ml": {
            "enabled": False,  # Disable ML by default in tests
            "model_path": str(tmp_path / "model.pkl"),
        },
        "response": {
            "mode": "manual",  # Never execute automated actions in tests
        },
        "alerting": {
            "desktop_notifications": False,
            "console_output": False,
        },
        "storage": {
            "db_path": str(tmp_path / "data" / "test.db"),
        },
        "api": {
            "enabled": False,  # Don't start API server in unit tests
            "token": "test-token-not-for-production",
        },
        "performance": {
            "event_queue_size": 1000,
            "max_events_per_second": 10000,
        },
    }

    return IHADRSConfig.model_validate(raw_config)


# =============================================================================
# EVENT BUS FIXTURE
# =============================================================================

@pytest.fixture
def event_bus() -> Generator[EventBus, None, None]:
    """
    Provide a started EventBus instance.

    Automatically stopped after each test.
    """
    bus = EventBus(max_queue_size=1000, max_events_per_second=10000)
    bus.start()
    yield bus
    bus.stop(drain_timeout_seconds=2.0)


# =============================================================================
# RESOURCE MANAGER FIXTURE
# =============================================================================

@pytest.fixture
def resource_manager() -> Generator[ResourceManager, None, None]:
    """
    Provide a started ResourceManager.

    Uses loose budget limits to avoid throttling in tests.
    """
    rm = ResourceManager(
        cpu_budget_average=99.0,    # Don't throttle tests
        cpu_budget_peak=100.0,
        ram_budget_max_mb=4096,
    )
    rm.start()
    yield rm
    rm.stop()


# =============================================================================
# SCHEDULER FIXTURE
# =============================================================================

@pytest.fixture
def scheduler() -> Generator[TaskScheduler, None, None]:
    """Provide a started TaskScheduler."""
    sched = TaskScheduler()
    sched.start()
    yield sched
    sched.stop()


# =============================================================================
# TEMPORARY LOG DIRECTORY
# =============================================================================

@pytest.fixture
def tmp_log_dir(tmp_path: Path) -> Path:
    """Return a temporary directory for log files."""
    log_dir = tmp_path / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    return log_dir


# =============================================================================
# EVENT FACTORIES
# =============================================================================

@pytest.fixture
def sample_process_event() -> ProcessEvent:
    """Return a sample ProcessEvent for testing."""
    return make_process_created_event(
        pid=4444,
        name="powershell.exe",
        image_path="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        command_line='powershell.exe -enc SQBFAFgA',
        parent_pid=3333,
        parent_name="cmd.exe",
        username="testuser",
        hostname="TEST-PC",
        is_elevated=False,
    )


@pytest.fixture
def sample_malicious_process_event() -> ProcessEvent:
    """Return a ProcessEvent that should trigger detection rules."""
    return make_process_created_event(
        pid=9999,
        name="mimikatz.exe",
        image_path="C:\\Users\\testuser\\AppData\\Local\\Temp\\mimikatz.exe",
        command_line="mimikatz.exe sekurlsa::logonpasswords",
        parent_pid=1234,
        parent_name="cmd.exe",
        username="testuser",
        hostname="TEST-PC",
        is_elevated=True,
    )


@pytest.fixture
def sample_network_event() -> NetworkEvent:
    """Return a sample NetworkEvent for testing."""
    return make_network_connection_event(
        pid=4444,
        process_name="powershell.exe",
        local_ip="192.168.1.100",
        local_port=54321,
        remote_ip="1.2.3.4",
        remote_port=4444,
        protocol="tcp",
        direction="outbound",
        state="ESTABLISHED",
        remote_hostname="evil.example.com",
    )


@pytest.fixture
def sample_file_event() -> FileEvent:
    """Return a sample FileEvent for testing."""
    return make_file_event(
        file_path="C:\\Users\\testuser\\Documents\\report.docx.encrypted",
        change_type="renamed",
        pid=4444,
        process_name="malware.exe",
        old_path="C:\\Users\\testuser\\Documents\\report.docx",
        new_path="C:\\Users\\testuser\\Documents\\report.docx.encrypted",
    )


@pytest.fixture
def sample_threat_event() -> ThreatEvent:
    """Return a minimal ThreatEvent for testing alerting and response."""
    evidence = ThreatEvidence(
        triggered_rule_ids=["R001"],
        triggered_rule_names=["Encoded PowerShell Execution"],
        raw_events=[{
            "pid": 4444,
            "process_name": "powershell.exe",
            "command_line": "powershell.exe -enc SQBFAFgA",
        }],
        iocs=["4444", "powershell.exe", "-enc"],
    )

    return ThreatEvent(
        hostname="TEST-PC",
        username="testuser",
        source_monitor=MonitorType.PROCESS.value,
        attack_category=AttackCategory.MALWARE_EXECUTION,
        severity=Severity.HIGH,
        confidence=0.85,
        mitre_tactics=["TA0002"],
        mitre_techniques=["T1059.001"],
        mitre_tactic_names=["Execution"],
        mitre_technique_names=["PowerShell"],
        affected_resource="process:powershell.exe:4444",
        summary="Encoded PowerShell execution detected",
        user_explanation=(
            "PowerShell was run with an encoded command to hide its contents."
        ),
        technical_details=(
            "Process powershell.exe (PID 4444) executed with Base64-encoded "
            "command-line argument."
        ),
        evidence=evidence,
        process_context=ProcessContext(
            pid=4444,
            name="powershell.exe",
            image_path="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            command_line="powershell.exe -enc SQBFAFgA",
            parent_pid=3333,
            parent_name="cmd.exe",
        ),
        remediation_steps=[
            RemediationStep(
                step_number=1,
                category="immediate",
                description="Terminate the suspicious process",
                command="taskkill /PID 4444 /F",
            ),
        ],
        false_positive_hints=[
            "Some software update mechanisms use encoded PowerShell",
        ],
        references=["https://attack.mitre.org/techniques/T1059/001/"],
    )


# =============================================================================
# MOCK FACTORIES
# =============================================================================

@pytest.fixture
def mock_event_bus() -> MagicMock:
    """Return a MagicMock that quacks like an EventBus."""
    mock = MagicMock(spec=EventBus)
    mock.publish.return_value = True
    mock.publish_many.return_value = 1
    return mock


# =============================================================================
# PYTEST MARKERS
# =============================================================================

def pytest_configure(config: pytest.Config) -> None:
    """Register custom pytest markers."""
    config.addinivalue_line("markers", "slow: marks tests as slow (skipped by default)")
    config.addinivalue_line("markers", "windows: marks tests as Windows-only")
    config.addinivalue_line("markers", "linux: marks tests as Linux-only")
    config.addinivalue_line("markers", "integration: marks integration tests")
    config.addinivalue_line("markers", "simulation: marks attack simulation tests")
    config.addinivalue_line("markers", "unit: marks unit tests")
    config.addinivalue_line("markers", "requires_admin: requires admin/root privileges")
    config.addinivalue_line("markers", "ml: marks ML-related tests")


def pytest_collection_modifyitems(
    config: pytest.Config,
    items: list[pytest.Item],
) -> None:
    """
    Automatically skip platform-specific tests.

    - @pytest.mark.windows: Skip on non-Windows
    - @pytest.mark.linux: Skip on non-Linux
    - @pytest.mark.requires_admin: Skip if not running as admin
    """
    import sys

    for item in items:
        if "windows" in item.keywords and sys.platform != "win32":
            item.add_marker(pytest.mark.skip(reason="Windows-only test"))

        if "linux" in item.keywords and not sys.platform.startswith("linux"):
            item.add_marker(pytest.mark.skip(reason="Linux-only test"))

        if "requires_admin" in item.keywords:
            import os
            is_admin = (
                os.geteuid() == 0
                if hasattr(os, "geteuid")
                else False
            )
            if not is_admin:
                item.add_marker(
                    pytest.mark.skip(reason="Requires administrator/root privileges")
                )