"""
Unit tests for Phase 2 monitors — BaseMonitor, ProcessMonitor, NetworkMonitor,
FileMonitor, RegistryMonitor (Windows-only), AuthMonitor.
"""
from __future__ import annotations

import asyncio
import socket
import subprocess as sp
import time
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import psutil
import pytest

from ihadrs.constants import EventType, MonitorType, RANSOMWARE_FILE_RENAME_THRESHOLD
from ihadrs.core.event_bus import BusEvent, EventBus, EventPriority
from ihadrs.exceptions import MonitorAlreadyRunningError, MonitorInitializationError, EventBusFullError
from ihadrs.models.events import ProcessEvent


# =============================================================================
# HELPERS
# =============================================================================

def _make_config(tmp_path: Path) -> Any:
    from ihadrs.core.config import IHADRSConfig
    return IHADRSConfig.model_validate({
        "app": {"require_admin": False},
        "logging": {"console_output": False, "level": "DEBUG"},
        "monitors": {
            "enabled_monitors": ["process","network","file"],
            "process_poll_interval": 0.1,
            "network_poll_interval": 0.5,
            "file_watch_paths": [str(tmp_path)],
            "file_watch_recursive": False,
            "process_baseline_whitelist": [],
            "ip_whitelist": [],
        },
        "detection": {"rules_file": "config/rules.yaml"},
        "api": {"enabled": False, "token": "test"},
        "response": {"mode": "manual"},
    })

def _make_bus() -> EventBus:
    bus = EventBus(max_queue_size=500, max_events_per_second=10000)
    bus.start()
    return bus


# Concrete minimal monitor for base class testing
from ihadrs.monitors.base import BaseMonitor

class FakeMonitor(BaseMonitor):
    def __init__(self, config, event_bus):
        super().__init__(config, event_bus)
        self._status.name = "FakeMonitor"
        self._status.monitor_type = MonitorType.SYNTHETIC
        self.iterations = 0

    async def initialize(self):
        self._mark_initialized()

    async def _run_monitor_loop(self):
        while not self._stop_event.is_set():
            self.iterations += 1
            await asyncio.sleep(0.05)

    async def stop(self):
        await self._base_stop()


# =============================================================================
# BASE MONITOR TESTS
# =============================================================================

class TestBaseMonitor:

    @pytest.mark.asyncio
    async def test_initialize_marks_flag(self, tmp_path):
        bus = _make_bus()
        m = FakeMonitor(_make_config(tmp_path), bus)
        await m.initialize()
        assert m._status.initialized is True
        bus.stop(drain_timeout_seconds=1.0)

    @pytest.mark.asyncio
    async def test_start_and_stop(self, tmp_path):
        bus = _make_bus()
        m = FakeMonitor(_make_config(tmp_path), bus)
        await m.initialize()
        await m.start()
        assert m.is_running
        time.sleep(0.2)
        await m.stop()
        assert not m.is_running
        assert m.iterations >= 1
        bus.stop(drain_timeout_seconds=1.0)

    @pytest.mark.asyncio
    async def test_double_start_raises(self, tmp_path):
        bus = _make_bus()
        m = FakeMonitor(_make_config(tmp_path), bus)
        await m.initialize()
        await m.start()
        try:
            with pytest.raises(MonitorAlreadyRunningError):
                await m.start()
        finally:
            await m.stop()
            bus.stop(drain_timeout_seconds=1.0)

    @pytest.mark.asyncio
    async def test_publish_increments_counter(self, tmp_path):
        bus = _make_bus()
        m = FakeMonitor(_make_config(tmp_path), bus)
        from ihadrs.models.events import make_process_created_event
        ev = make_process_created_event(1,"a.exe","","",0,"")
        m._publish(ev)
        assert m.events_published == 1
        bus.stop(drain_timeout_seconds=1.0)

    @pytest.mark.asyncio
    async def test_deduplication_suppresses_duplicate(self, tmp_path):
        bus = _make_bus()
        m = FakeMonitor(_make_config(tmp_path), bus)
        m._dedup_ttl_seconds = 5.0
        from ihadrs.models.events import make_process_created_event
        ev = make_process_created_event(1,"a.exe","","",0,"")
        r1 = m._publish(ev, dedup_key="k1")
        r2 = m._publish(ev, dedup_key="k1")
        assert r1 is True
        assert r2 is False
        assert m.events_published == 1
        bus.stop(drain_timeout_seconds=1.0)

    @pytest.mark.asyncio
    async def test_bus_full_increments_dropped(self, tmp_path):
        bus = _make_bus()
        m = FakeMonitor(_make_config(tmp_path), bus)
        m._event_bus.publish = lambda *a, **kw: (_ for _ in ()).throw(
            EventBusFullError(100, 100, "process.created")
        )
        from ihadrs.models.events import make_process_created_event
        ev = make_process_created_event(1,"a.exe","","",0,"")
        result = m._publish(ev)
        assert result is False
        assert m._status.events_dropped == 1
        bus.stop(drain_timeout_seconds=1.0)

    @pytest.mark.asyncio
    async def test_health_check_running(self, tmp_path):
        bus = _make_bus()
        m = FakeMonitor(_make_config(tmp_path), bus)
        await m.initialize()
        await m.start()
        try:
            h = await m.health_check()
            assert h["status"] == "healthy"
            assert h["running"] is True
        finally:
            await m.stop()
            bus.stop(drain_timeout_seconds=1.0)

    @pytest.mark.asyncio
    async def test_health_check_failed_not_running(self, tmp_path):
        bus = _make_bus()
        m = FakeMonitor(_make_config(tmp_path), bus)
        await m.initialize()
        h = await m.health_check()
        assert h["status"] == "failed"
        bus.stop(drain_timeout_seconds=1.0)

    def test_record_error(self, tmp_path):
        bus = _make_bus()
        m = FakeMonitor(_make_config(tmp_path), bus)
        m._record_error(ValueError("oops"), "ctx")
        assert m._status.errors == 1
        assert "oops" in m._status.last_error
        bus.stop(drain_timeout_seconds=1.0)


# =============================================================================
# PROCESS MONITOR TESTS
# =============================================================================

class TestProcessMonitor:

    @pytest.mark.asyncio
    async def test_initialize_baseline(self, tmp_path):
        from ihadrs.monitors.process_monitor import ProcessMonitor
        bus = _make_bus()
        m = ProcessMonitor(_make_config(tmp_path), bus)
        await m.initialize()
        assert len(m._prev_pids) > 0
        assert m._status.initialized
        await m.stop()
        bus.stop(drain_timeout_seconds=1.0)

    @pytest.mark.asyncio
    async def test_terminated_pid_emits_event(self, tmp_path):
        from ihadrs.monitors.process_monitor import ProcessMonitor
        bus = _make_bus()
        m = ProcessMonitor(_make_config(tmp_path), bus)
        await m.initialize()

        received = []
        bus.subscribe("t", received.append, {EventType.PROCESS_TERMINATED})

        # Inject fake cached PID that won't be in next poll
        fake = 77777
        m._prev_pids.add(fake)
        m._process_cache[fake] = {
            "name": "gone.exe", "exe": "C:\\gone.exe", "cmdline": "gone.exe",
            "ppid": 0, "parent_name": "", "username": "user",
            "create_time": None, "create_time_float": time.time() - 30,
            "num_threads": 1, "memory_mb": 1.0, "session_id": 0,
            "is_elevated": False, "integrity_level": "",
        }

        real = set(psutil.pids()) - {fake}
        with patch("psutil.pids", return_value=list(real)):
            await m._poll_once()

        time.sleep(0.1)
        assert any(e.event_type == EventType.PROCESS_TERMINATED for e in received)
        await m.stop()
        bus.stop(drain_timeout_seconds=1.0)

    def test_own_process_info_readable(self, tmp_path):
        from ihadrs.monitors.process_monitor import ProcessMonitor
        bus = _make_bus()
        m = ProcessMonitor(_make_config(tmp_path), bus)
        info = m._get_process_info(psutil.Process().pid)
        assert info is not None
        assert info["memory_mb"] > 0
        bus.stop(drain_timeout_seconds=1.0)

    def test_nonexistent_pid_returns_none(self, tmp_path):
        from ihadrs.monitors.process_monitor import ProcessMonitor
        bus = _make_bus()
        m = ProcessMonitor(_make_config(tmp_path), bus)
        assert m._get_process_info(999999999) is None
        bus.stop(drain_timeout_seconds=1.0)

    def test_high_risk_path_detection(self, tmp_path):
        # Test Windows path matching logic directly
        from ihadrs.monitors.process_monitor import _HIGH_RISK_EXPANDED
        import os
        if os.name == "nt":
            import os
            temp = os.path.expandvars("%TEMP%").lower().replace("\\","/")
            risky = (temp + "/evil.exe")
            assert any(p in risky for p in _HIGH_RISK_EXPANDED)
        else:
            # On Linux, verify the constant contains expected Windows paths
            all_paths = list(_HIGH_RISK_EXPANDED)
            assert len(all_paths) > 0  # At least has entries
            assert any("%" in p or "users" in p for p in all_paths)

    def test_whitelisted_process_returns_none(self, tmp_path):
        from ihadrs.monitors.process_monitor import ProcessMonitor
        from ihadrs.core.config import IHADRSConfig
        bus = _make_bus()
        cfg = IHADRSConfig.model_validate({
            "app":{"require_admin":False},
            "logging":{"console_output":False},
            "monitors":{"process_baseline_whitelist":["legit.exe"],
                        "file_watch_paths":[str(tmp_path)],"ip_whitelist":[]},
            "api":{"enabled":False,"token":"t"},"response":{"mode":"manual"},
        })
        m = ProcessMonitor(cfg, bus)
        fake_info = {
            "name":"legit.exe","exe":"/usr/bin/legit.exe","cmdline":"legit.exe",
            "ppid":1,"parent_name":"init","parent_exe":"","username":"user",
            "create_time":None,"create_time_float":time.time(),
            "num_threads":1,"memory_mb":1.0,"session_id":0,
            "is_elevated":False,"integrity_level":"","cpu_percent":0.0,
        }
        with patch.object(m,"_get_process_info",return_value=fake_info):
            result = m._build_created(1234)
        assert result is None
        bus.stop(drain_timeout_seconds=1.0)


# =============================================================================
# NETWORK MONITOR TESTS
# =============================================================================

class TestNetworkMonitor:

    @pytest.mark.asyncio
    async def test_initialize(self, tmp_path):
        from ihadrs.monitors.network_monitor import NetworkMonitor
        bus = _make_bus()
        m = NetworkMonitor(_make_config(tmp_path), bus)
        await m.initialize()
        assert m._status.initialized
        await m.stop()
        bus.stop(drain_timeout_seconds=1.0)

    def test_is_private_ip(self):
        from ihadrs.monitors.network_monitor import _is_private_ip
        assert _is_private_ip("192.168.1.1") is True
        assert _is_private_ip("10.0.0.1") is True
        assert _is_private_ip("127.0.0.1") is True
        assert _is_private_ip("8.8.8.8") is False

    def test_beacon_detection_regular(self, tmp_path):
        from ihadrs.monitors.network_monitor import NetworkMonitor
        bus = _make_bus()
        m = NetworkMonitor(_make_config(tmp_path), bus)
        key = (1234, "1.2.3.4", 443)
        now = time.time()
        for i in range(8):
            m._beacon_tracker[key].append(now - (7-i)*60.0)
        m._pid_name_cache[1234] = "malware.exe"
        beacons = m._detect_beaconing(now)
        assert len(beacons) == 1
        assert beacons[0].event_type == EventType.NETWORK_C2_BEACON
        bus.stop(drain_timeout_seconds=1.0)

    def test_beacon_detection_irregular_not_flagged(self, tmp_path):
        from ihadrs.monitors.network_monitor import NetworkMonitor
        bus = _make_bus()
        m = NetworkMonitor(_make_config(tmp_path), bus)
        key = (1234, "8.8.8.8", 443)
        now = time.time()
        # Highly irregular
        for offset in [600, 490, 350, 200, 100, 45, 0]:
            m._beacon_tracker[key].append(now - offset)
        beacons = m._detect_beaconing(now)
        assert len(beacons) == 0
        bus.stop(drain_timeout_seconds=1.0)

    def test_beacon_too_few_observations(self, tmp_path):
        from ihadrs.monitors.network_monitor import NetworkMonitor
        bus = _make_bus()
        m = NetworkMonitor(_make_config(tmp_path), bus)
        key = (1234, "1.2.3.4", 4444)
        now = time.time()
        for i in range(3):  # Below minimum of 5
            m._beacon_tracker[key].append(now - i*60.0)
        beacons = m._detect_beaconing(now)
        assert len(beacons) == 0
        bus.stop(drain_timeout_seconds=1.0)


# =============================================================================
# FILE MONITOR TESTS
# =============================================================================

class TestFileMonitor:

    @pytest.mark.asyncio
    async def test_initialize_valid_path(self, tmp_path):
        from ihadrs.monitors.file_monitor import FileMonitor
        bus = _make_bus()
        m = FileMonitor(_make_config(tmp_path), bus)
        await m.initialize()
        assert m._status.initialized
        await m.stop()
        bus.stop(drain_timeout_seconds=1.0)

    @pytest.mark.asyncio
    async def test_no_paths_raises(self, tmp_path):
        from ihadrs.monitors.file_monitor import FileMonitor
        from ihadrs.core.config import IHADRSConfig
        bus = _make_bus()
        cfg = IHADRSConfig.model_validate({
            "app":{"require_admin":False},"logging":{"console_output":False},
            "monitors":{"file_watch_paths":[],"ip_whitelist":[]},
            "api":{"enabled":False,"token":"t"},"response":{"mode":"manual"},
        })
        m = FileMonitor(cfg, bus)
        with pytest.raises(MonitorInitializationError):
            await m.initialize()
        bus.stop(drain_timeout_seconds=1.0)

    def test_crypto_rename_tracked(self, tmp_path):
        from ihadrs.monitors.file_monitor import FileMonitor
        from watchdog.events import FileMovedEvent
        bus = _make_bus()
        m = FileMonitor(_make_config(tmp_path), bus)
        received = []
        m._publish = lambda ev, **kw: received.append(ev)
        old = str(tmp_path / "file.docx")
        new = str(tmp_path / "file.docx.encrypted")
        m._on_file_event(FileMovedEvent(old, new))
        assert len(m._crypto_rename_times) == 1
        bus.stop(drain_timeout_seconds=1.0)

    def test_ransomware_threshold_triggers_mass_event(self, tmp_path):
        from ihadrs.monitors.file_monitor import FileMonitor
        bus = _make_bus()
        received = []
        bus.subscribe("t", received.append, {EventType.FILE_MASS_OPERATION})
        m = FileMonitor(_make_config(tmp_path), bus)
        now = time.time()
        for _ in range(RANSOMWARE_FILE_RENAME_THRESHOLD + 5):
            m._crypto_rename_times.append(now)
        m._check_ransomware_pattern()
        time.sleep(0.15)
        assert any(e.event_type == EventType.FILE_MASS_OPERATION for e in received)
        assert len(m._crypto_rename_times) == 0  # Cleared after alert
        bus.stop(drain_timeout_seconds=1.0)

    def test_file_created_event_emitted(self, tmp_path):
        from ihadrs.monitors.file_monitor import FileMonitor
        from watchdog.events import FileCreatedEvent
        bus = _make_bus()
        received = []
        bus.subscribe("t", received.append, {EventType.FILE_CREATED})
        m = FileMonitor(_make_config(tmp_path), bus)
        m._on_file_event(FileCreatedEvent(str(tmp_path / "new_file.txt")))
        time.sleep(0.1)
        assert any(e.event_type == EventType.FILE_CREATED for e in received)
        bus.stop(drain_timeout_seconds=1.0)


# =============================================================================
# REGISTRY MONITOR TESTS
# =============================================================================

class TestRegistryMonitor:

    @pytest.mark.asyncio
    @pytest.mark.linux
    async def test_linux_raises(self, tmp_path):
        from ihadrs.monitors.registry_monitor import RegistryMonitor
        bus = _make_bus()
        m = RegistryMonitor(_make_config(tmp_path), bus)
        with pytest.raises(MonitorInitializationError):
            await m.initialize()
        bus.stop(drain_timeout_seconds=1.0)


# =============================================================================
# AUTH MONITOR TESTS
# =============================================================================

class TestAuthMonitor:

    @pytest.mark.asyncio
    @pytest.mark.linux
    async def test_linux_failed_login_parsed(self, tmp_path):
        from ihadrs.monitors.auth_monitor import AuthMonitor
        bus = _make_bus()
        m = AuthMonitor(_make_config(tmp_path), bus)
        m._auth_log_path = str(tmp_path / "auth.log")
        log_line = (
            "Apr 22 10:00:01 host sshd[123]: Failed password for "
            "admin from 1.2.3.4 port 22 ssh2\n"
        )
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout=log_line)
            events = await m._poll_linux_events()
        failed = [e for e in events if not e.success]
        assert len(failed) >= 1
        assert failed[0].event_type == EventType.AUTH_LOGON_FAILURE
        bus.stop(drain_timeout_seconds=1.0)

    @pytest.mark.asyncio
    @pytest.mark.linux
    async def test_linux_success_login_parsed(self, tmp_path):
        from ihadrs.monitors.auth_monitor import AuthMonitor
        bus = _make_bus()
        m = AuthMonitor(_make_config(tmp_path), bus)
        m._auth_log_path = str(tmp_path / "auth.log")
        log_line = (
            "Apr 22 10:00:01 host sshd[1]: Accepted publickey for "
            "alice from 10.0.0.1 port 54321 ssh2\n"
        )
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout=log_line)
            events = await m._poll_linux_events()
        success = [e for e in events if e.success]
        assert len(success) >= 1
        assert success[0].target_username == "alice"
        bus.stop(drain_timeout_seconds=1.0)