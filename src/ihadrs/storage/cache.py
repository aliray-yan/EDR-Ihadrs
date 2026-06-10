"""
Module: storage.cache
Purpose: Thread-safe in-memory LRU cache with TTL eviction for hot data.
         Used to cache process info, file hashes, and network state to
         avoid redundant psutil/filesystem calls on every event.
Owner: storage
Dependencies: threading, time, collections
Performance: O(1) get/set via dict + doubly-linked list.
             Background eviction thread runs every 30 seconds.
             Zero external dependencies.
"""

from __future__ import annotations

import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any, Generic, Optional, TypeVar

from loguru import logger

from ihadrs.constants import (
    CACHE_FILE_HASH_TTL_SECONDS,
    CACHE_MAX_SIZE,
    CACHE_NETWORK_TTL_SECONDS,
    CACHE_PROCESS_TTL_SECONDS,
)

T = TypeVar("T")


# =============================================================================
# CACHE ENTRY
# =============================================================================

@dataclass
class CacheEntry(Generic[T]):
    """Single cached item with expiry metadata."""

    value: T
    expires_at: float
    hits: int = 0
    created_at: float = field(default_factory=time.time)

    @property
    def is_expired(self) -> bool:
        return time.time() > self.expires_at

    @property
    def age_seconds(self) -> float:
        return time.time() - self.created_at


# =============================================================================
# LRU CACHE WITH TTL
# =============================================================================

class TTLCache(Generic[T]):
    """
    Thread-safe LRU cache with per-entry TTL eviction.

    Entries are evicted when:
    1. Their TTL expires (lazy eviction on access + background sweep)
    2. The cache reaches max_size (LRU eviction of least-recently-used)

    Usage:
        cache: TTLCache[dict] = TTLCache(max_size=1000, default_ttl=60)
        cache.set("process:1234", proc_info)
        proc_info = cache.get("process:1234")
    """

    def __init__(
        self,
        max_size: int = CACHE_MAX_SIZE,
        default_ttl: float = CACHE_PROCESS_TTL_SECONDS,
        name: str = "cache",
    ) -> None:
        self._max_size = max_size
        self._default_ttl = default_ttl
        self._name = name
        self._store: OrderedDict[str, CacheEntry[T]] = OrderedDict()
        self._lock = threading.RLock()

        # Stats
        self._hits: int = 0
        self._misses: int = 0
        self._evictions: int = 0
        self._sets: int = 0

    # -------------------------------------------------------------------------
    # Core Operations
    # -------------------------------------------------------------------------

    def get(self, key: str) -> Optional[T]:
        """
        Retrieve a value from the cache.

        Returns None if key doesn't exist or has expired.
        Moves the entry to the end (most recently used) on hit.
        """
        with self._lock:
            entry = self._store.get(key)
            if entry is None:
                self._misses += 1
                return None

            if entry.is_expired:
                del self._store[key]
                self._misses += 1
                self._evictions += 1
                return None

            # Move to end (most recently used)
            self._store.move_to_end(key)
            entry.hits += 1
            self._hits += 1
            return entry.value

    def set(
        self,
        key: str,
        value: T,
        ttl: Optional[float] = None,
    ) -> None:
        """
        Store a value in the cache.

        Args:
            key:   Cache key string.
            value: Value to cache.
            ttl:   TTL in seconds. Uses default_ttl if not specified.
        """
        effective_ttl = ttl if ttl is not None else self._default_ttl
        expires_at = time.time() + effective_ttl

        with self._lock:
            if key in self._store:
                # Update existing entry and move to end
                self._store[key].value = value
                self._store[key].expires_at = expires_at
                self._store.move_to_end(key)
            else:
                # Evict LRU entry if at capacity
                if len(self._store) >= self._max_size:
                    oldest_key, _ = self._store.popitem(last=False)
                    self._evictions += 1
                    logger.debug(
                        "Cache '{name}' LRU eviction: '{key}'",
                        name=self._name,
                        key=oldest_key[:40],
                    )

                self._store[key] = CacheEntry(
                    value=value,
                    expires_at=expires_at,
                )

            self._sets += 1

    def delete(self, key: str) -> bool:
        """Remove a specific key. Returns True if it existed."""
        with self._lock:
            if key in self._store:
                del self._store[key]
                return True
            return False

    def has(self, key: str) -> bool:
        """Return True if key exists and has not expired."""
        with self._lock:
            entry = self._store.get(key)
            if entry is None:
                return False
            if entry.is_expired:
                del self._store[key]
                return False
            return True

    def get_or_set(
        self,
        key: str,
        factory: Any,
        ttl: Optional[float] = None,
    ) -> T:
        """
        Get value from cache, calling factory() on miss.

        Args:
            key:     Cache key.
            factory: Zero-argument callable returning T.
            ttl:     TTL in seconds for new entry.

        Returns:
            Cached value (existing or freshly computed).
        """
        value = self.get(key)
        if value is not None:
            return value
        value = factory()
        self.set(key, value, ttl=ttl)
        return value

    def invalidate_prefix(self, prefix: str) -> int:
        """Remove all entries whose keys start with prefix. Returns count."""
        with self._lock:
            keys_to_delete = [k for k in self._store if k.startswith(prefix)]
            for key in keys_to_delete:
                del self._store[key]
            return len(keys_to_delete)

    def clear(self) -> int:
        """Clear all entries. Returns count cleared."""
        with self._lock:
            count = len(self._store)
            self._store.clear()
            return count

    def sweep_expired(self) -> int:
        """Remove all expired entries. Returns count removed."""
        with self._lock:
            expired = [k for k, v in self._store.items() if v.is_expired]
            for key in expired:
                del self._store[key]
            self._evictions += len(expired)
            return len(expired)

    # -------------------------------------------------------------------------
    # Introspection
    # -------------------------------------------------------------------------

    @property
    def size(self) -> int:
        """Current number of entries (including expired, not yet evicted)."""
        return len(self._store)

    @property
    def hit_rate(self) -> float:
        """Cache hit rate (0.0–1.0). 0.0 if no requests yet."""
        total = self._hits + self._misses
        return self._hits / total if total > 0 else 0.0

    def stats(self) -> dict[str, Any]:
        """Return cache performance statistics."""
        return {
            "name": self._name,
            "size": self.size,
            "max_size": self._max_size,
            "hits": self._hits,
            "misses": self._misses,
            "sets": self._sets,
            "evictions": self._evictions,
            "hit_rate": f"{self.hit_rate:.1%}",
            "default_ttl_seconds": self._default_ttl,
        }


# =============================================================================
# IHADRS CACHE REGISTRY
# =============================================================================

class CacheRegistry:
    """
    Centralized registry of all IHADRS caches.

    Provides named caches with appropriate TTLs for each data type.
    Also manages the background sweep thread that evicts expired entries.

    Usage:
        registry = CacheRegistry()
        registry.start()

        registry.process.set("pid:1234", proc_info)
        proc_info = registry.process.get("pid:1234")

        registry.stop()
    """

    # How often to run the background sweep
    _SWEEP_INTERVAL_SECONDS: float = 30.0

    def __init__(self) -> None:
        # Process information cache (short TTL — processes change frequently)
        self.process: TTLCache[dict[str, Any]] = TTLCache(
            max_size=2000,
            default_ttl=CACHE_PROCESS_TTL_SECONDS,
            name="process",
        )

        # Network state cache (medium TTL)
        self.network: TTLCache[dict[str, Any]] = TTLCache(
            max_size=1000,
            default_ttl=CACHE_NETWORK_TTL_SECONDS,
            name="network",
        )

        # File hash cache (long TTL — file contents rarely change)
        self.file_hash: TTLCache[str] = TTLCache(
            max_size=5000,
            default_ttl=CACHE_FILE_HASH_TTL_SECONDS,
            name="file_hash",
        )

        # Generic/miscellaneous cache
        self.general: TTLCache[Any] = TTLCache(
            max_size=CACHE_MAX_SIZE,
            default_ttl=300,  # 5 minutes
            name="general",
        )

        self._all_caches: list[TTLCache[Any]] = [
            self.process, self.network, self.file_hash, self.general
        ]

        self._running = False
        self._sweep_thread: Optional[threading.Thread] = None

    def start(self) -> None:
        """Start the background cache sweep thread."""
        self._running = True
        self._sweep_thread = threading.Thread(
            target=self._sweep_loop,
            name="ihadrs-cache-sweep",
            daemon=True,
        )
        self._sweep_thread.start()
        logger.debug("CacheRegistry started.")

    def stop(self) -> None:
        """Stop the background sweep thread."""
        self._running = False
        if self._sweep_thread:
            self._sweep_thread.join(timeout=5.0)
        logger.debug("CacheRegistry stopped.")

    def _sweep_loop(self) -> None:
        """Background thread: periodically evict expired entries."""
        while self._running:
            time.sleep(self._SWEEP_INTERVAL_SECONDS)
            if not self._running:
                break
            total_swept = sum(c.sweep_expired() for c in self._all_caches)
            if total_swept > 0:
                logger.debug(
                    "Cache sweep: evicted {n} expired entries.", n=total_swept
                )

    def clear_all(self) -> None:
        """Clear all caches — used when ML model is retrained."""
        for cache in self._all_caches:
            cache.clear()
        logger.info("All caches cleared.")

    def get_all_stats(self) -> list[dict[str, Any]]:
        """Return stats for all registered caches."""
        return [c.stats() for c in self._all_caches]

    def total_entries(self) -> int:
        """Total entries across all caches."""
        return sum(c.size for c in self._all_caches)


# =============================================================================
# MODULE-LEVEL SINGLETON
# =============================================================================

_registry: Optional[CacheRegistry] = None


def get_cache() -> CacheRegistry:
    """
    Return the global CacheRegistry singleton.

    Call initialize_cache() during startup before using this.
    """
    global _registry
    if _registry is None:
        _registry = CacheRegistry()
        _registry.start()
    return _registry


def initialize_cache() -> CacheRegistry:
    """Initialize and start the global cache registry."""
    global _registry
    _registry = CacheRegistry()
    _registry.start()
    return _registry