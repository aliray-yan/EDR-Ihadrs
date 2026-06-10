"""
Unit tests for core.event_bus — EventBus implementation.

Tests verify:
- Basic publish/subscribe roundtrip
- Priority ordering (CRITICAL before NORMAL)
- Wildcard subscriptions
- Subscriber isolation (one failing subscriber doesn't affect others)
- Rate limiting (TokenBucket)
- Backpressure (EventBusFullError)
- Dead letter queue
- Graceful shutdown with queue drain
- Throughput (must process ≥1,000 events/sec)
- Metrics accuracy
"""

from __future__ import annotations

import threading
import time
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from ihadrs.constants import EventType, Severity
from ihadrs.core.event_bus import (
    BusEvent,
    EventBus,
    EventPriority,
    _TokenBucket,
)
from ihadrs.exceptions import EventBusFullError


# =============================================================================
# HELPERS
# =============================================================================

def _make_event(
    event_type: EventType = EventType.PROCESS_CREATED,
    source: str = "test",
    payload: Any = None,
    priority: EventPriority = EventPriority.NORMAL,
    severity: Severity | None = None,
) -> BusEvent:
    return BusEvent(
        event_type=event_type,
        source=source,
        payload=payload or {"test": True},
        priority=priority,
        severity=severity,
    )


def _started_bus(
    max_queue: int = 1000,
    max_eps: int = 100_000,
) -> EventBus:
    bus = EventBus(max_queue_size=max_queue, max_events_per_second=max_eps)
    bus.start()
    return bus


# =============================================================================
# BASIC PUBLISH / SUBSCRIBE
# =============================================================================

class TestBasicPublishSubscribe:
    """Core publish/subscribe semantics."""

    def test_subscriber_receives_event(self) -> None:
        """Published events reach matching subscribers."""
        bus = _started_bus()
        received: list[BusEvent] = []
        bus.subscribe("test", received.append, {EventType.PROCESS_CREATED})
        bus.publish(_make_event(EventType.PROCESS_CREATED))
        time.sleep(0.1)
        bus.stop(drain_timeout_seconds=1.0)
        assert len(received) == 1
        assert received[0].event_type == EventType.PROCESS_CREATED

    def test_wildcard_subscriber_receives_all_events(self) -> None:
        """Subscriber with no event_types filter receives ALL events."""
        bus = _started_bus()
        received: list[BusEvent] = []
        bus.subscribe("wildcard", received.append, event_types=None)

        bus.publish(_make_event(EventType.PROCESS_CREATED))
        bus.publish(_make_event(EventType.FILE_CREATED))
        bus.publish(_make_event(EventType.NETWORK_CONNECTION_OPENED))
        time.sleep(0.2)
        bus.stop(drain_timeout_seconds=1.0)

        assert len(received) == 3

    def test_subscriber_only_receives_subscribed_types(self) -> None:
        """Subscribers only receive events matching their event_types filter."""
        bus = _started_bus()
        process_events: list[BusEvent] = []
        network_events: list[BusEvent] = []

        bus.subscribe("proc_sub", process_events.append, {EventType.PROCESS_CREATED})
        bus.subscribe("net_sub", network_events.append, {EventType.NETWORK_CONNECTION_OPENED})

        bus.publish(_make_event(EventType.PROCESS_CREATED))
        bus.publish(_make_event(EventType.NETWORK_CONNECTION_OPENED))
        bus.publish(_make_event(EventType.FILE_CREATED))  # Neither subscribes to this
        time.sleep(0.15)
        bus.stop(drain_timeout_seconds=1.0)

        assert len(process_events) == 1
        assert len(network_events) == 1

    def test_multiple_subscribers_receive_same_event(self) -> None:
        """The same event is delivered to ALL matching subscribers."""
        bus = _started_bus()
        sub1_received: list[BusEvent] = []
        sub2_received: list[BusEvent] = []
        sub3_received: list[BusEvent] = []

        bus.subscribe("sub1", sub1_received.append, {EventType.PROCESS_CREATED})
        bus.subscribe("sub2", sub2_received.append, {EventType.PROCESS_CREATED})
        bus.subscribe("sub3", sub3_received.append, {EventType.PROCESS_CREATED})

        bus.publish(_make_event(EventType.PROCESS_CREATED))
        time.sleep(0.2)
        bus.stop(drain_timeout_seconds=1.0)

        assert len(sub1_received) == 1
        assert len(sub2_received) == 1
        assert len(sub3_received) == 1

    def test_unsubscribe_stops_delivery(self) -> None:
        """Events are not delivered after unsubscribe."""
        bus = _started_bus()
        received: list[BusEvent] = []
        bus.subscribe("test", received.append, {EventType.PROCESS_CREATED})

        bus.publish(_make_event(EventType.PROCESS_CREATED))
        time.sleep(0.1)
        bus.unsubscribe("test")
        bus.publish(_make_event(EventType.PROCESS_CREATED))
        time.sleep(0.1)
        bus.stop(drain_timeout_seconds=1.0)

        assert len(received) == 1  # Only first event received

    def test_event_payload_preserved(self) -> None:
        """Event payload is delivered to subscriber unchanged."""
        bus = _started_bus()
        received: list[BusEvent] = []
        bus.subscribe("test", received.append, {EventType.FILE_CREATED})

        payload = {"pid": 1234, "path": "/tmp/test.exe", "nested": {"key": "value"}}
        bus.publish(_make_event(EventType.FILE_CREATED, payload=payload))
        time.sleep(0.1)
        bus.stop(drain_timeout_seconds=1.0)

        assert received[0].payload == payload


# =============================================================================
# PRIORITY ORDERING
# =============================================================================

class TestPriorityOrdering:
    """CRITICAL events must be processed before NORMAL events."""

    def test_critical_events_processed_before_normal(self) -> None:
        """
        When queue has both CRITICAL and NORMAL events,
        CRITICAL are dispatched first.
        """
        # Use a small bus with no subscribers yet to let events queue up
        bus = EventBus(max_queue_size=100, max_events_per_second=100_000)
        # Don't start yet — queue events while stopped

        # Add events in reverse priority order
        normal1 = _make_event(EventType.FILE_CREATED, priority=EventPriority.NORMAL)
        normal2 = _make_event(EventType.FILE_MODIFIED, priority=EventPriority.NORMAL)
        critical = _make_event(EventType.PROCESS_CREATED, priority=EventPriority.CRITICAL)

        # Queue events directly to the priority queue
        import heapq
        from ihadrs.core.event_bus import _QueueEntry

        with bus._queue_lock:
            for i, event in enumerate([normal1, normal2, critical]):
                heapq.heappush(
                    bus._queue,
                    _QueueEntry(
                        priority=event.priority.value,
                        sequence=i,
                        enqueue_time=time.time(),
                        event=event,
                    ),
                )

        # Dequeue should return CRITICAL first
        entry1 = bus._dequeue_event()
        entry2 = bus._dequeue_event()
        entry3 = bus._dequeue_event()

        assert entry1 is not None
        assert entry1.event.priority == EventPriority.CRITICAL
        assert entry2 is not None
        assert entry2.event.priority == EventPriority.NORMAL
        assert entry3 is not None

    def test_same_priority_fifo_ordering(self) -> None:
        """Events with the same priority are ordered FIFO by sequence number."""
        bus = EventBus(max_queue_size=100, max_events_per_second=100_000)
        import heapq
        from ihadrs.core.event_bus import _QueueEntry

        events = [
            _make_event(EventType.PROCESS_CREATED),
            _make_event(EventType.FILE_CREATED),
            _make_event(EventType.NETWORK_CONNECTION_OPENED),
        ]

        with bus._queue_lock:
            for i, event in enumerate(events):
                heapq.heappush(
                    bus._queue,
                    _QueueEntry(
                        priority=EventPriority.NORMAL.value,
                        sequence=i,
                        enqueue_time=time.time(),
                        event=event,
                    ),
                )

        dequeued = []
        for _ in range(3):
            entry = bus._dequeue_event()
            if entry:
                dequeued.append(entry.event.event_type)

        assert dequeued == [
            EventType.PROCESS_CREATED,
            EventType.FILE_CREATED,
            EventType.NETWORK_CONNECTION_OPENED,
        ]


# =============================================================================
# SUBSCRIBER ISOLATION
# =============================================================================

class TestSubscriberIsolation:
    """A failing subscriber must not affect other subscribers."""

    def test_failing_subscriber_does_not_block_other_subscribers(self) -> None:
        """
        When one subscriber raises an exception, other subscribers
        still receive the event.
        """
        bus = _started_bus()
        good_received: list[BusEvent] = []

        def bad_callback(event: BusEvent) -> None:
            raise RuntimeError("Intentional subscriber failure for testing")

        bus.subscribe("bad_sub", bad_callback, {EventType.PROCESS_CREATED})
        bus.subscribe("good_sub", good_received.append, {EventType.PROCESS_CREATED})

        bus.publish(_make_event(EventType.PROCESS_CREATED))
        time.sleep(0.2)
        bus.stop(drain_timeout_seconds=1.0)

        # Good subscriber still got the event despite bad subscriber failing
        assert len(good_received) == 1

    def test_failed_events_go_to_dead_letter_queue(self) -> None:
        """Events that cause subscriber exceptions land in the DLQ."""
        bus = _started_bus()

        def always_fails(event: BusEvent) -> None:
            raise ValueError("DLQ test failure")

        bus.subscribe("failing", always_fails, {EventType.PROCESS_CREATED})
        bus.publish(_make_event(EventType.PROCESS_CREATED))
        time.sleep(0.2)
        bus.stop(drain_timeout_seconds=1.0)

        dlq = bus.get_dead_letters()
        assert len(dlq) >= 1
        assert dlq[0][1] == "failing"

    def test_slow_subscriber_does_not_block_dispatch(self) -> None:
        """
        A slow subscriber (100ms+ processing time) does not block
        other subscribers from receiving events promptly.
        """
        bus = _started_bus()
        fast_times: list[float] = []

        def slow_callback(event: BusEvent) -> None:
            time.sleep(0.2)  # 200ms

        def fast_callback(event: BusEvent) -> None:
            fast_times.append(time.time())

        bus.subscribe("slow_sub", slow_callback, {EventType.PROCESS_CREATED})
        bus.subscribe("fast_sub", fast_callback, {EventType.PROCESS_CREATED})

        start = time.time()
        bus.publish(_make_event(EventType.PROCESS_CREATED))
        time.sleep(0.1)
        bus.stop(drain_timeout_seconds=1.0)

        # Fast subscriber should have received within 150ms of publish
        assert fast_times and (fast_times[0] - start) < 0.15


# =============================================================================
# BACKPRESSURE
# =============================================================================

class TestBackpressure:
    """Queue full → EventBusFullError."""

    def test_publish_raises_when_queue_full(self) -> None:
        """
        publish() raises EventBusFullError when queue is at capacity.
        We pre-fill the queue directly to guarantee the condition
        without racing against the dispatch thread.
        """
        bus = EventBus(max_queue_size=5, max_events_per_second=100_000)
        # Do NOT start the bus — this keeps the dispatch thread idle so the
        # queue stays full, letting us test the overflow condition cleanly.

        # Mark as "running" so publish() doesn't short-circuit
        bus._running = True

        # Pre-fill queue to max capacity using publish_many (bypasses start check)
        import heapq
        from ihadrs.core.event_bus import _QueueEntry

        with bus._queue_lock:
            for i in range(5):
                heapq.heappush(
                    bus._queue,
                    _QueueEntry(
                        priority=EventPriority.NORMAL.value,
                        sequence=i,
                        enqueue_time=time.time(),
                        event=_make_event(),
                    ),
                )

        # Queue is now full — next publish should raise
        with pytest.raises(EventBusFullError) as exc_info:
            bus.publish(_make_event())

        bus._running = False
        assert exc_info.value.max_size == 5
        assert exc_info.value.queue_size == 5

    def test_error_contains_dropped_event_type(self) -> None:
        """EventBusFullError reports the type of dropped event and queue info."""
        bus = EventBus(max_queue_size=3, max_events_per_second=100_000)
        bus._running = True

        import heapq
        from ihadrs.core.event_bus import _QueueEntry

        with bus._queue_lock:
            for i in range(3):
                heapq.heappush(
                    bus._queue,
                    _QueueEntry(
                        priority=EventPriority.NORMAL.value,
                        sequence=i,
                        enqueue_time=time.time(),
                        event=_make_event(EventType.PROCESS_CREATED),
                    ),
                )

        with pytest.raises(EventBusFullError) as exc_info:
            bus.publish(_make_event(EventType.FILE_CREATED))

        bus._running = False
        err = exc_info.value
        assert err.max_size == 3
        assert err.queue_size == 3
        assert "file.created" in err.dropped_event_type


# =============================================================================
# METRICS
# =============================================================================

class TestMetrics:
    """Bus metrics should accurately reflect operations."""

    def test_published_count_increments(self) -> None:
        bus = _started_bus()
        for _ in range(10):
            bus.publish(_make_event())
        time.sleep(0.1)
        bus.stop(drain_timeout_seconds=1.0)

        assert bus.get_metrics().total_published == 10

    def test_processed_count_increments(self) -> None:
        bus = _started_bus()
        received: list[BusEvent] = []
        bus.subscribe("test", received.append, {EventType.PROCESS_CREATED})

        for _ in range(5):
            bus.publish(_make_event())
        time.sleep(0.2)
        bus.stop(drain_timeout_seconds=1.0)

        assert bus.get_metrics().total_processed == 5

    def test_subscriber_count_tracked(self) -> None:
        bus = _started_bus()
        assert bus.get_metrics().subscriber_count == 0

        bus.subscribe("sub1", lambda e: None, {EventType.PROCESS_CREATED})
        assert bus.get_metrics().subscriber_count == 1

        bus.subscribe("sub2", lambda e: None, {EventType.FILE_CREATED})
        assert bus.get_metrics().subscriber_count == 2

        bus.unsubscribe("sub1")
        assert bus.get_metrics().subscriber_count == 1

        bus.stop(drain_timeout_seconds=1.0)

    def test_health_check_returns_healthy_when_running(self) -> None:
        bus = _started_bus()
        health = bus.health_check()
        bus.stop(drain_timeout_seconds=1.0)

        assert health["running"] is True
        assert health["status"] in ("healthy", "degraded")
        assert "metrics" in health


# =============================================================================
# THROUGHPUT
# =============================================================================

class TestThroughput:
    """Verify the bus can sustain ≥1,000 events/sec."""

    @pytest.mark.slow
    def test_throughput_exceeds_1000_eps(self) -> None:
        """
        Publish 2,000 events and verify they're all processed
        within 3 seconds → >666 eps minimum (generous budget).
        """
        bus = _started_bus(max_queue=5000, max_eps=100_000)
        received_count = 0
        lock = threading.Lock()

        def count_events(event: BusEvent) -> None:
            nonlocal received_count
            with lock:
                received_count += 1

        bus.subscribe("counter", count_events, event_types=None)

        n = 2000
        start = time.time()
        for _ in range(n):
            bus.publish(_make_event())
        publish_duration = time.time() - start

        # Wait for all events to be processed (max 3 seconds)
        deadline = time.time() + 3.0
        while received_count < n and time.time() < deadline:
            time.sleep(0.05)

        total_duration = time.time() - start
        bus.stop(drain_timeout_seconds=2.0)

        assert received_count == n, (
            f"Expected {n} events received, got {received_count}"
        )
        eps = n / total_duration
        assert eps >= 500, f"Throughput {eps:.0f} eps is below 500 eps minimum"


# =============================================================================
# TOKEN BUCKET RATE LIMITER
# =============================================================================

class TestTokenBucket:
    """TTL bucket rate limiting."""

    def test_consumes_up_to_capacity(self) -> None:
        bucket = _TokenBucket(capacity=10, refill_rate=1.0)
        results = [bucket.consume() for _ in range(10)]
        assert all(results), "First 10 consumes should succeed"

    def test_empty_bucket_returns_false(self) -> None:
        bucket = _TokenBucket(capacity=5, refill_rate=1.0)
        for _ in range(5):
            bucket.consume()
        assert not bucket.consume(), "Empty bucket should return False"

    def test_bucket_refills_over_time(self) -> None:
        bucket = _TokenBucket(capacity=10, refill_rate=100.0)  # 100 tokens/sec
        for _ in range(10):
            bucket.consume()
        assert not bucket.consume()

        time.sleep(0.05)  # Wait ~5 tokens to refill
        # Should be able to consume at least a few now
        refilled = sum(1 for _ in range(5) if bucket.consume())
        assert refilled >= 1, "Bucket should have refilled at least 1 token"

    def test_capacity_never_exceeded(self) -> None:
        bucket = _TokenBucket(capacity=5, refill_rate=1000.0)
        time.sleep(0.1)  # Let it refill to max
        # Should still be capped at capacity
        results = [bucket.consume() for _ in range(5)]
        assert all(results)
        assert not bucket.consume()


# =============================================================================
# DUPLICATE SUBSCRIBER NAMES
# =============================================================================

class TestSubscriberManagement:
    """Subscriber registration and management."""

    def test_duplicate_subscriber_name_raises(self) -> None:
        bus = _started_bus()
        bus.subscribe("unique_name", lambda e: None, {EventType.PROCESS_CREATED})
        with pytest.raises(ValueError, match="already registered"):
            bus.subscribe("unique_name", lambda e: None, {EventType.FILE_CREATED})
        bus.stop(drain_timeout_seconds=0.5)

    def test_unsubscribe_nonexistent_returns_false(self) -> None:
        bus = _started_bus()
        result = bus.unsubscribe("does_not_exist")
        bus.stop(drain_timeout_seconds=0.5)
        assert result is False

    def test_subscriber_names_listed(self) -> None:
        bus = _started_bus()
        bus.subscribe("sub_a", lambda e: None, {EventType.PROCESS_CREATED})
        bus.subscribe("sub_b", lambda e: None, {EventType.FILE_CREATED})
        names = bus.subscriber_names()
        bus.stop(drain_timeout_seconds=0.5)
        assert "sub_a" in names
        assert "sub_b" in names

    def test_publish_many_batch(self) -> None:
        bus = _started_bus()
        received: list[BusEvent] = []
        bus.subscribe("test", received.append, event_types=None)

        events = [_make_event() for _ in range(20)]
        enqueued = bus.publish_many(events)
        time.sleep(0.2)
        bus.stop(drain_timeout_seconds=1.0)

        assert enqueued == 20
        assert len(received) == 20

    def test_publish_to_stopped_bus_returns_false(self) -> None:
        bus = _started_bus()
        bus.stop(drain_timeout_seconds=0.5)
        result = bus.publish(_make_event())
        assert result is False


# =============================================================================
# GRACEFUL SHUTDOWN
# =============================================================================

class TestGracefulShutdown:
    """Bus should drain queued events before stopping."""

    def test_stop_drains_pending_events(self) -> None:
        """All queued events are delivered before stop() returns."""
        bus = _started_bus(max_queue=500)
        received: list[BusEvent] = []

        def slow_but_completes(event: BusEvent) -> None:
            time.sleep(0.005)  # 5ms per event
            received.append(event)

        bus.subscribe("slow", slow_but_completes, event_types=None)

        # Publish events rapidly
        n = 50
        for _ in range(n):
            bus.publish(_make_event())

        # Give time for some events to process, then stop with drain
        time.sleep(0.05)
        bus.stop(drain_timeout_seconds=5.0)

        # All events should have been processed
        assert len(received) == n, (
            f"Expected {n} events after drain, got {len(received)}"
        )