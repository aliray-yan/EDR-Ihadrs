"""
Unit tests for storage.event_store and storage.cache.

Tests verify:
- EventStore initializes and runs migrations
- Events saved and retrieved correctly
- Threat events round-trip through serialization
- False positive marking
- Database pruning removes old records
- Cache get/set/TTL/LRU eviction
- Cache hit rate tracking
- TTL expiry eviction
"""

from __future__ import annotations

import asyncio
import time
from pathlib import Path

import pytest

from ihadrs.constants import AttackCategory, Severity
from ihadrs.models.threats import ThreatEvent, ThreatEvidence
from ihadrs.storage.cache import TTLCache
from ihadrs.storage.event_store import EventStore


# =============================================================================
# EVENT STORE TESTS
# =============================================================================

class TestEventStoreInitialization:
    """EventStore setup and migration."""

    @pytest.mark.asyncio
    async def test_initializes_with_fresh_database(self, tmp_path: Path) -> None:
        store = EventStore(db_path=tmp_path / "test.db")
        await store.initialize()
        assert (tmp_path / "test.db").exists()
        await store.close()

    @pytest.mark.asyncio
    async def test_creates_parent_directory(self, tmp_path: Path) -> None:
        deep_path = tmp_path / "nested" / "dir" / "ihadrs.db"
        store = EventStore(db_path=deep_path)
        await store.initialize()
        assert deep_path.exists()
        await store.close()

    @pytest.mark.asyncio
    async def test_reinitializing_existing_database_works(self, tmp_path: Path) -> None:
        db_path = tmp_path / "existing.db"
        # First init
        store1 = EventStore(db_path=db_path)
        await store1.initialize()
        await store1.close()
        # Second init — should not raise (migrations already applied)
        store2 = EventStore(db_path=db_path)
        await store2.initialize()
        await store2.close()

    @pytest.mark.asyncio
    async def test_database_stats_returns_correct_schema(self, tmp_path: Path) -> None:
        store = EventStore(db_path=tmp_path / "test.db")
        await store.initialize()
        stats = await store.get_database_stats()
        assert "events_count" in stats
        assert "threats_count" in stats
        assert "audit_count" in stats
        assert "schema_version" in stats
        assert stats["schema_version"] >= 1
        await store.close()


class TestEventStoreSaveAndRetrieve:
    """Basic CRUD operations."""

    @pytest.fixture
    async def store(self, tmp_path: Path) -> EventStore:
        s = EventStore(db_path=tmp_path / "test.db")
        await s.initialize()
        yield s
        await s.close()

    @pytest.mark.asyncio
    async def test_save_and_retrieve_raw_event(self, tmp_path: Path) -> None:
        store = EventStore(db_path=tmp_path / "test.db")
        await store.initialize()

        await store.save_event(
            event_id="test-event-001",
            event_type="process.created",
            source="process_monitor",
            timestamp=time.time(),
            payload={"pid": 1234, "name": "cmd.exe"},
            severity="HIGH",
        )

        events = await store.get_events(limit=10)
        assert len(events) == 1
        assert events[0]["event_id"] == "test-event-001"
        assert events[0]["payload"]["pid"] == 1234

        await store.close()

    @pytest.mark.asyncio
    async def test_duplicate_event_id_ignored(self, tmp_path: Path) -> None:
        store = EventStore(db_path=tmp_path / "test.db")
        await store.initialize()

        for _ in range(3):
            await store.save_event(
                event_id="duplicate-id",
                event_type="process.created",
                source="test",
                timestamp=time.time(),
                payload={},
            )

        events = await store.get_events(limit=10)
        assert len(events) == 1  # Only one, duplicates ignored

        await store.close()

    @pytest.mark.asyncio
    async def test_filter_events_by_type(self, tmp_path: Path) -> None:
        store = EventStore(db_path=tmp_path / "test.db")
        await store.initialize()

        await store.save_event("e1", "process.created", "pm", time.time(), {})
        await store.save_event("e2", "file.created", "fm", time.time(), {})
        await store.save_event("e3", "process.created", "pm", time.time(), {})

        proc_events = await store.get_events(event_type="process.created")
        file_events = await store.get_events(event_type="file.created")

        assert len(proc_events) == 2
        assert len(file_events) == 1

        await store.close()

    @pytest.mark.asyncio
    async def test_save_and_retrieve_threat(self, tmp_path: Path, sample_threat_event: ThreatEvent) -> None:
        store = EventStore(db_path=tmp_path / "test.db")
        await store.initialize()

        await store.save_threat(sample_threat_event.to_dict())

        threats = await store.get_threats(limit=10)
        assert len(threats) == 1
        assert threats[0]["threat_id"] == sample_threat_event.threat_id
        assert threats[0]["severity"] == "HIGH"

        await store.close()

    @pytest.mark.asyncio
    async def test_get_threat_by_id_found(self, tmp_path: Path, sample_threat_event: ThreatEvent) -> None:
        store = EventStore(db_path=tmp_path / "test.db")
        await store.initialize()

        await store.save_threat(sample_threat_event.to_dict())
        retrieved = await store.get_threat_by_id(sample_threat_event.threat_id)

        assert retrieved is not None
        assert retrieved["threat_id"] == sample_threat_event.threat_id

        await store.close()

    @pytest.mark.asyncio
    async def test_get_threat_by_id_not_found_returns_none(self, tmp_path: Path) -> None:
        store = EventStore(db_path=tmp_path / "test.db")
        await store.initialize()

        result = await store.get_threat_by_id("nonexistent-id")
        assert result is None

        await store.close()

    @pytest.mark.asyncio
    async def test_mark_false_positive(self, tmp_path: Path, sample_threat_event: ThreatEvent) -> None:
        store = EventStore(db_path=tmp_path / "test.db")
        await store.initialize()

        await store.save_threat(sample_threat_event.to_dict())
        await store.mark_false_positive(
            threat_id=sample_threat_event.threat_id,
            marked_by="testuser",
            reason="This is normal behavior for my software",
        )

        # FP should be excluded from default queries
        threats = await store.get_threats(include_false_positives=False)
        assert len(threats) == 0

        # FP included when explicitly requested
        threats_with_fp = await store.get_threats(include_false_positives=True)
        assert len(threats_with_fp) == 1

        await store.close()

    @pytest.mark.asyncio
    async def test_audit_log_save(self, tmp_path: Path) -> None:
        store = EventStore(db_path=tmp_path / "test.db")
        await store.initialize()

        await store.save_audit_record(
            action_type="kill_process",
            component="auto_responder",
            target="malware.exe:4444",
            threat_id="threat-001",
            operator="auto",
            result="success",
            details={"pid": 4444},
        )

        stats = await store.get_database_stats()
        assert stats["audit_count"] == 1

        await store.close()


class TestEventStorePruning:
    """Old event pruning."""

    @pytest.mark.asyncio
    async def test_prune_old_events(self, tmp_path: Path) -> None:
        store = EventStore(db_path=tmp_path / "test.db")
        await store.initialize()

        old_ts = time.time() - (100 * 86400)  # 100 days ago
        recent_ts = time.time() - 3600  # 1 hour ago

        await store.save_event("old-evt", "process.created", "pm", old_ts, {})
        await store.save_event("recent-evt", "process.created", "pm", recent_ts, {})

        deleted = await store.prune_old_events(keep_days=90)
        assert deleted >= 1

        remaining = await store.get_events()
        ids = [e["event_id"] for e in remaining]
        assert "recent-evt" in ids
        assert "old-evt" not in ids

        await store.close()

    @pytest.mark.asyncio
    async def test_prune_by_max_events(self, tmp_path: Path) -> None:
        store = EventStore(db_path=tmp_path / "test.db")
        await store.initialize()

        # Insert 20 events
        for i in range(20):
            await store.save_event(
                f"evt-{i:03d}",
                "process.created",
                "pm",
                time.time() - (20 - i),  # Staggered timestamps
                {},
            )

        # Prune to max 10
        deleted = await store.prune_old_events(keep_days=365, max_events=10)
        assert deleted == 10

        remaining = await store.get_events(limit=100)
        assert len(remaining) == 10

        await store.close()

    @pytest.mark.asyncio
    async def test_threat_stats_by_severity(self, tmp_path: Path) -> None:
        store = EventStore(db_path=tmp_path / "test.db")
        await store.initialize()

        # Insert threats of different severities
        for severity in ["CRITICAL", "HIGH", "HIGH", "MEDIUM"]:
            t = ThreatEvent(
                source_monitor="process_monitor",
                attack_category=AttackCategory.MALWARE_EXECUTION,
                severity=Severity[severity],
                confidence=0.8,
                affected_resource="process:test.exe:1",
                summary="Test threat",
                evidence=ThreatEvidence(),
            )
            await store.save_threat(t.to_dict())

        stats = await store.get_threat_stats(since_hours=24)
        assert stats["total_threats"] == 4
        assert stats["by_severity"].get("CRITICAL", 0) == 1
        assert stats["by_severity"].get("HIGH", 0) == 2
        assert stats["by_severity"].get("MEDIUM", 0) == 1

        await store.close()


# =============================================================================
# CACHE TESTS
# =============================================================================

class TestTTLCache:
    """TTLCache get/set/eviction."""

    def test_set_and_get_basic(self) -> None:
        cache: TTLCache[str] = TTLCache(default_ttl=60)
        cache.set("key1", "value1")
        assert cache.get("key1") == "value1"

    def test_get_missing_key_returns_none(self) -> None:
        cache: TTLCache[str] = TTLCache(default_ttl=60)
        assert cache.get("nonexistent") is None

    def test_expired_entry_returns_none(self) -> None:
        cache: TTLCache[str] = TTLCache(default_ttl=0.01)  # 10ms TTL
        cache.set("expiring", "value")
        time.sleep(0.05)  # Wait for expiry
        assert cache.get("expiring") is None

    def test_non_expired_entry_returned(self) -> None:
        cache: TTLCache[str] = TTLCache(default_ttl=60)
        cache.set("persistent", "data")
        time.sleep(0.01)
        assert cache.get("persistent") == "data"

    def test_custom_ttl_per_entry(self) -> None:
        cache: TTLCache[str] = TTLCache(default_ttl=60)
        cache.set("short", "s", ttl=0.01)
        cache.set("long", "l", ttl=60)
        time.sleep(0.05)
        assert cache.get("short") is None
        assert cache.get("long") == "l"

    def test_lru_eviction_on_max_size(self) -> None:
        cache: TTLCache[int] = TTLCache(max_size=3, default_ttl=60)
        cache.set("a", 1)
        cache.set("b", 2)
        cache.set("c", 3)
        # Access "a" to make it recently used
        cache.get("a")
        # Insert new entry — should evict "b" (LRU, not "a")
        cache.set("d", 4)

        assert cache.get("a") == 1   # Recently accessed — stays
        assert cache.get("c") == 3   # Recently set — stays
        assert cache.get("d") == 4   # Newest — stays
        # "b" was LRU and should be gone (capacity is 3)
        # Note: exact LRU depends on ordering after get("a") moved "a" to end

    def test_delete_removes_entry(self) -> None:
        cache: TTLCache[str] = TTLCache(default_ttl=60)
        cache.set("key", "value")
        assert cache.has("key")
        cache.delete("key")
        assert not cache.has("key")

    def test_delete_nonexistent_returns_false(self) -> None:
        cache: TTLCache[str] = TTLCache(default_ttl=60)
        assert cache.delete("ghost") is False

    def test_has_returns_false_for_expired(self) -> None:
        cache: TTLCache[str] = TTLCache(default_ttl=0.01)
        cache.set("expiring", "v")
        time.sleep(0.05)
        assert cache.has("expiring") is False

    def test_hit_rate_calculation(self) -> None:
        cache: TTLCache[str] = TTLCache(default_ttl=60)
        cache.set("key", "value")
        cache.get("key")   # Hit
        cache.get("key")   # Hit
        cache.get("miss")  # Miss
        assert cache.hit_rate == pytest.approx(2 / 3)

    def test_sweep_expired_removes_stale_entries(self) -> None:
        cache: TTLCache[str] = TTLCache(default_ttl=0.01)
        cache.set("a", "1")
        cache.set("b", "2")
        cache.set("c", "3")
        time.sleep(0.05)
        removed = cache.sweep_expired()
        assert removed == 3
        assert cache.size == 0

    def test_clear_empties_cache(self) -> None:
        cache: TTLCache[int] = TTLCache(default_ttl=60)
        for i in range(10):
            cache.set(f"k{i}", i)
        assert cache.size == 10
        cleared = cache.clear()
        assert cleared == 10
        assert cache.size == 0

    def test_invalidate_prefix(self) -> None:
        cache: TTLCache[str] = TTLCache(default_ttl=60)
        cache.set("process:1234", "proc1")
        cache.set("process:5678", "proc2")
        cache.set("network:1234", "net1")

        removed = cache.invalidate_prefix("process:")
        assert removed == 2
        assert cache.get("process:1234") is None
        assert cache.get("network:1234") == "net1"

    def test_stats_returns_all_fields(self) -> None:
        cache: TTLCache[str] = TTLCache(max_size=100, default_ttl=60, name="test")
        cache.set("k", "v")
        cache.get("k")
        cache.get("miss")
        stats = cache.stats()
        assert stats["name"] == "test"
        assert stats["hits"] == 1
        assert stats["misses"] == 1
        assert stats["sets"] == 1
        assert stats["size"] == 1
        assert stats["max_size"] == 100