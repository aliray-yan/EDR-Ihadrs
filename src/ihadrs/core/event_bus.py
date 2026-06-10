"""
Module: core.event_bus
Purpose: Central publish/subscribe event distribution system for IHADRS.
         All inter-component communication flows through this bus.
         Monitors publish events; detectors, loggers, and alerters subscribe.
Owner: core
Dependencies: asyncio, threading, collections, loguru
Performance: Target ≥10,000 events/sec throughput.
             Priority queue ensures critical events are never starved.
             Subscriber callbacks run in isolated executor threads to
             prevent one slow subscriber from blocking others.

Architecture:
    - Priority queue (heap): 4 priority levels (CRITICAL > HIGH > MEDIUM > LOW)
    - Typed subscriptions: subscribers filter by EventType
    - Wildcard subscriptions: subscribe to ALL events
    - Subscriber isolation: each subscriber runs in its own ThreadPoolExecutor
    - Backpressure: publishers receive EventBusFullError when queue is full
    - Dead letter queue: events that fail processing land here for inspection
    - Metrics: per-subscriber and global throughput/latency counters
    - Graceful shutdown: drains the queue before stopping
"""

from __future__ import annotations

import asyncio
import heapq
import threading
import time
import uuid
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor, Future
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Callable, ClassVar, Optional

from loguru import logger

from ihadrs.constants import (
    EVENT_MAX_AGE_SECONDS,
    EVENT_QUEUE_SIZE,
    MAX_EVENTS_PER_SECOND,
    MAX_SUBSCRIBER_EVENTS_PER_SECOND,
    PUBLISHER_TIMEOUT_SECONDS,
    EventType,
    Severity,
)
from ihadrs.exceptions import (
    EventBusFullError,
    EventPublishError,
    SubscriberError,
    UnexpectedInternalError,
)


# =============================================================================
# PRIORITY LEVELS
# =============================================================================

class EventPriority(IntEnum):
    """
    Event priority levels for the internal priority queue.

    Lower integer = higher priority (Python's heapq is a min-heap).
    CRITICAL events are always processed before NORMAL events.
    """

    CRITICAL = 0    # Ransomware detected, C2 confirmed — process immediately
    HIGH = 1        # Suspicious behavior needing fast response
    NORMAL = 2      # Standard monitoring events
    LOW = 3         # Informational, telemetry, housekeeping

    @classmethod
    def from_severity(cls, severity: Severity) -> EventPriority:
        """Map a threat severity to an event priority."""
        mapping = {
            Severity.CRITICAL: cls.CRITICAL,
            Severity.HIGH: cls.HIGH,
            Severity.MEDIUM: cls.NORMAL,
            Severity.LOW: cls.LOW,
        }
        return mapping.get(severity, cls.NORMAL)


# =============================================================================
# PRIORITY QUEUE ENTRY
# =============================================================================

@dataclass(order=True)
class _QueueEntry:
    """
    Internal wrapper for events in the priority queue.

    Ordered by: (priority, sequence_number) — sequence_number breaks
    ties between same-priority events, preserving FIFO ordering within
    each priority level.
    """

    priority: int                         # EventPriority value (lower = higher priority)
    sequence: int                         # Monotonically increasing, for FIFO tie-breaking
    enqueue_time: float = field(compare=False)   # Unix timestamp (UTC)
    event: "BusEvent" = field(compare=False)     # The actual event payload


# =============================================================================
# BUS EVENT
# =============================================================================

@dataclass
class BusEvent:
    """
    Wrapper around any event published to the bus.

    All events flowing through IHADRS are wrapped in BusEvent before
    being placed on the priority queue. The wrapped payload is the
    domain event object (ProcessEvent, NetworkEvent, ThreatEvent, etc.).

    Attributes:
        event_id: Globally unique event identifier (UUID4).
        event_type: Classification used for subscriber routing.
        source: Name of the monitor/component that published this event.
        payload: The actual event data (any dataclass or dict).
        priority: Queue priority level.
        timestamp: When this event was created (Unix timestamp, UTC).
        severity: Optional severity hint for priority auto-assignment.
        tags: Optional free-form tags for filtering.
        correlation_id: Link multiple related events (e.g., attack chain).
    """

    event_type: EventType
    source: str
    payload: Any
    priority: EventPriority = EventPriority.NORMAL
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: float = field(default_factory=time.time)
    severity: Optional[Severity] = None
    tags: list[str] = field(default_factory=list)
    correlation_id: Optional[str] = None

    def __post_init__(self) -> None:
        """Auto-assign priority from severity if not explicitly set."""
        if self.severity is not None and self.priority == EventPriority.NORMAL:
            self.priority = EventPriority.from_severity(self.severity)

    @property
    def age_seconds(self) -> float:
        """Return how many seconds have passed since this event was created."""
        return time.time() - self.timestamp

    @property
    def is_expired(self) -> bool:
        """Return True if this event has been waiting too long and should be dropped."""
        return self.age_seconds > EVENT_MAX_AGE_SECONDS

    def to_log_dict(self) -> dict[str, Any]:
        """Minimal representation for logging (avoids serializing large payloads)."""
        return {
            "event_id": self.event_id,
            "event_type": self.event_type.value,
            "source": self.source,
            "priority": self.priority.name,
            "timestamp": self.timestamp,
            "severity": self.severity.value if self.severity else None,
            "correlation_id": self.correlation_id,
            "tags": self.tags,
        }


# =============================================================================
# SUBSCRIBER
# =============================================================================

# Type alias for subscriber callbacks
SubscriberCallback = Callable[[BusEvent], None]


@dataclass
class Subscriber:
    """
    Represents a registered event bus subscriber.

    Attributes:
        name: Human-readable name for logging and metrics.
        callback: Function called with each matching BusEvent.
        event_types: If non-empty, only receive these event types.
                     If empty, receive ALL events (wildcard subscription).
        min_priority: Only receive events at or above this priority.
        min_severity: Only receive events at or above this severity.
        is_async: True if callback is a coroutine function.
        max_queue_depth: Per-subscriber backlog limit.
    """

    name: str
    callback: SubscriberCallback
    event_types: frozenset[EventType]       # Empty = subscribe to all
    min_priority: EventPriority = EventPriority.LOW
    min_severity: Optional[Severity] = None
    is_async: bool = False
    max_queue_depth: int = 1000

    # Runtime metrics (mutable despite dataclass — use slots is optional)
    _events_received: int = field(default=0, repr=False)
    _events_processed: int = field(default=0, repr=False)
    _events_failed: int = field(default=0, repr=False)
    _last_event_time: float = field(default=0.0, repr=False)
    _total_processing_time: float = field(default=0.0, repr=False)

    def matches(self, event: BusEvent) -> bool:
        """
        Return True if this subscriber should receive the given event.

        Applies all filters: event type, priority, and severity.
        """
        # Priority filter — skip events below minimum priority
        if event.priority > self.min_priority:
            return False

        # Severity filter
        if self.min_severity is not None and event.severity is not None:
            if event.severity < self.min_severity:
                return False

        # Event type filter — empty frozenset = wildcard (all events)
        if self.event_types and event.event_type not in self.event_types:
            return False

        return True

    @property
    def avg_processing_time_ms(self) -> float:
        """Average processing time per event in milliseconds."""
        if self._events_processed == 0:
            return 0.0
        return (self._total_processing_time / self._events_processed) * 1000

    @property
    def failure_rate(self) -> float:
        """Fraction of events that resulted in errors (0.0–1.0)."""
        total = self._events_received
        if total == 0:
            return 0.0
        return self._events_failed / total


# =============================================================================
# METRICS
# =============================================================================

@dataclass
class EventBusMetrics:
    """
    Real-time performance metrics for the event bus.

    Sampled every health check interval by the resource manager.
    """

    total_published: int = 0
    total_processed: int = 0
    total_dropped: int = 0
    total_expired: int = 0
    total_dead_lettered: int = 0
    current_queue_depth: int = 0
    peak_queue_depth: int = 0
    current_throughput_eps: float = 0.0     # Events per second
    avg_dispatch_latency_ms: float = 0.0    # Time from enqueue to first dispatch
    subscriber_count: int = 0
    start_time: float = field(default_factory=time.time)

    @property
    def uptime_seconds(self) -> float:
        return time.time() - self.start_time

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_published": self.total_published,
            "total_processed": self.total_processed,
            "total_dropped": self.total_dropped,
            "total_expired": self.total_expired,
            "dead_lettered": self.total_dead_lettered,
            "queue_depth": self.current_queue_depth,
            "peak_queue_depth": self.peak_queue_depth,
            "throughput_eps": round(self.current_throughput_eps, 2),
            "avg_latency_ms": round(self.avg_dispatch_latency_ms, 3),
            "subscriber_count": self.subscriber_count,
            "uptime_seconds": round(self.uptime_seconds, 1),
        }


# =============================================================================
# EVENT BUS
# =============================================================================

class EventBus:
    """
    Central publish/subscribe event distribution system.

    Thread-safe and asyncio-compatible. Publishers can be either
    synchronous threads or asyncio coroutines. Subscribers run
    in isolated thread pools to prevent blocking each other.

    Lifecycle:
        bus = EventBus()
        bus.start()
        ...
        bus.subscribe("my_detector", callback, {EventType.PROCESS_CREATED})
        bus.publish(BusEvent(EventType.PROCESS_CREATED, "process_monitor", data))
        ...
        bus.stop()

    Thread Safety:
        All public methods are thread-safe. Subscribers are called from
        their own ThreadPoolExecutor threads, so callbacks do NOT need
        to be thread-safe with respect to the bus itself.

    Performance Notes:
        - Uses a heap-based priority queue with a threading.Condition
          for efficient waiting without busy-looping.
        - Subscriber callbacks run in thread pools to enable parallel
          processing of the same event by multiple subscribers.
        - Rate limiting prevents any single publisher from flooding the bus.
    """

    # Maximum dead letter queue size
    _DLQ_MAX_SIZE: ClassVar[int] = 1000

    # Number of worker threads in the dispatch executor
    _DISPATCH_WORKERS: ClassVar[int] = 4

    # Maximum workers per subscriber's isolated executor
    _SUBSCRIBER_WORKERS: ClassVar[int] = 2

    def __init__(
        self,
        max_queue_size: int = EVENT_QUEUE_SIZE,
        max_events_per_second: int = MAX_EVENTS_PER_SECOND,
    ) -> None:
        """
        Initialize the event bus.

        Args:
            max_queue_size: Maximum events in the priority queue before
                           back-pressure is applied.
            max_events_per_second: Global rate limit for all publishers.
        """
        self._max_queue_size = max_queue_size
        self._max_eps = max_events_per_second

        # Priority queue internals
        self._queue: list[_QueueEntry] = []
        self._queue_lock = threading.Condition(threading.Lock())
        self._sequence = 0

        # Subscribers registry
        self._subscribers: dict[str, Subscriber] = {}
        self._subscribers_lock = threading.RLock()

        # Per-subscriber thread pool executors (isolated to prevent blocking)
        self._subscriber_executors: dict[str, ThreadPoolExecutor] = {}

        # Central dispatch thread pool
        self._dispatch_executor: Optional[ThreadPoolExecutor] = None

        # Dead Letter Queue — events that failed all delivery attempts
        self._dlq: deque[tuple[BusEvent, str]] = deque(maxlen=self._DLQ_MAX_SIZE)
        self._dlq_lock = threading.Lock()

        # State
        self._running = False
        self._dispatch_thread: Optional[threading.Thread] = None
        self._metrics = EventBusMetrics()

        # Rate limiting — token bucket per publisher
        self._rate_limiter = _TokenBucket(
            capacity=max_events_per_second,
            refill_rate=max_events_per_second,
        )

        # Throughput tracking
        self._throughput_window: deque[float] = deque(maxlen=1000)
        self._throughput_window_lock = threading.Lock()

        logger.debug(
            "EventBus initialized: max_queue={q}, max_eps={eps}",
            q=max_queue_size,
            eps=max_events_per_second,
        )

    # -------------------------------------------------------------------------
    # Lifecycle
    # -------------------------------------------------------------------------

    def start(self) -> None:
        """
        Start the event bus dispatch loop.

        Spawns the background dispatch thread and initializes the executor.
        Must be called before any publish() calls.

        Raises:
            RuntimeError: If already running.
        """
        if self._running:
            raise RuntimeError("EventBus is already running.")

        self._running = True
        self._dispatch_executor = ThreadPoolExecutor(
            max_workers=self._DISPATCH_WORKERS,
            thread_name_prefix="ihadrs-dispatch",
        )

        self._dispatch_thread = threading.Thread(
            target=self._dispatch_loop,
            name="ihadrs-event-bus",
            daemon=True,
        )
        self._dispatch_thread.start()

        logger.info(
            "EventBus started with {workers} dispatch workers.",
            workers=self._DISPATCH_WORKERS,
        )

    def stop(self, drain_timeout_seconds: float = 10.0) -> None:
        """
        Stop the event bus gracefully.

        Waits up to ``drain_timeout_seconds`` for the queue to drain
        before forcefully shutting down.

        Args:
            drain_timeout_seconds: Max seconds to wait for queue drain.
        """
        if not self._running:
            return

        logger.info("EventBus shutting down — draining queue...")
        self._running = False

        # Wake up the dispatch thread so it can exit
        with self._queue_lock:
            self._queue_lock.notify_all()

        # Wait for dispatch thread to finish
        if self._dispatch_thread is not None:
            self._dispatch_thread.join(timeout=drain_timeout_seconds)
            if self._dispatch_thread.is_alive():
                logger.warning(
                    "EventBus dispatch thread did not stop within {t}s — forcing.",
                    t=drain_timeout_seconds,
                )

        # Shutdown executor pools
        if self._dispatch_executor:
            self._dispatch_executor.shutdown(wait=True, cancel_futures=False)

        for name, executor in self._subscriber_executors.items():
            executor.shutdown(wait=True, cancel_futures=False)
            logger.debug("Subscriber executor '{name}' shut down.", name=name)

        self._subscriber_executors.clear()

        remaining = len(self._queue)
        if remaining > 0:
            logger.warning(
                "EventBus stopped with {n} unprocessed events in queue.",
                n=remaining,
            )

        logger.info("EventBus stopped. Metrics: {m}", m=self._metrics.to_dict())

    # -------------------------------------------------------------------------
    # Subscription Management
    # -------------------------------------------------------------------------

    def subscribe(
        self,
        name: str,
        callback: SubscriberCallback,
        event_types: set[EventType] | None = None,
        min_priority: EventPriority = EventPriority.LOW,
        min_severity: Severity | None = None,
        is_async: bool = False,
        max_queue_depth: int = 1000,
    ) -> str:
        """
        Register a subscriber for one or more event types.

        Args:
            name: Unique subscriber name for logging and metrics.
            callback: Function or coroutine called with each matching BusEvent.
            event_types: Set of EventTypes to subscribe to. None = all events.
            min_priority: Ignore events below this priority.
            min_severity: Ignore events below this severity.
            is_async: True if callback is an async coroutine function.
            max_queue_depth: Per-subscriber backlog limit.

        Returns:
            The subscriber name (same as ``name`` arg).

        Raises:
            ValueError: If a subscriber with this name is already registered.
        """
        with self._subscribers_lock:
            if name in self._subscribers:
                raise ValueError(
                    f"Subscriber '{name}' is already registered. "
                    "Unsubscribe first or use a unique name."
                )

            subscriber = Subscriber(
                name=name,
                callback=callback,
                event_types=frozenset(event_types) if event_types else frozenset(),
                min_priority=min_priority,
                min_severity=min_severity,
                is_async=is_async,
                max_queue_depth=max_queue_depth,
            )
            self._subscribers[name] = subscriber

            # Give each subscriber an isolated thread pool
            self._subscriber_executors[name] = ThreadPoolExecutor(
                max_workers=self._SUBSCRIBER_WORKERS,
                thread_name_prefix=f"ihadrs-sub-{name[:20]}",
            )

            self._metrics.subscriber_count = len(self._subscribers)

            event_desc = (
                f"{len(event_types)} types"
                if event_types
                else "ALL events (wildcard)"
            )
            logger.info(
                "Subscriber registered: '{name}' | events={events} | "
                "priority≥{prio} | async={async_}",
                name=name,
                events=event_desc,
                prio=min_priority.name,
                async_=is_async,
            )
            return name

    def unsubscribe(self, name: str) -> bool:
        """
        Unregister a subscriber by name.

        Args:
            name: The subscriber name returned by subscribe().

        Returns:
            True if the subscriber was found and removed, False if not found.
        """
        with self._subscribers_lock:
            if name not in self._subscribers:
                logger.warning(
                    "Attempted to unsubscribe unknown subscriber: '{name}'",
                    name=name,
                )
                return False

            del self._subscribers[name]

            # Shut down its executor
            if name in self._subscriber_executors:
                self._subscriber_executors[name].shutdown(
                    wait=False, cancel_futures=True
                )
                del self._subscriber_executors[name]

            self._metrics.subscriber_count = len(self._subscribers)
            logger.info("Subscriber unregistered: '{name}'", name=name)
            return True

    def subscriber_names(self) -> list[str]:
        """Return names of all currently registered subscribers."""
        with self._subscribers_lock:
            return list(self._subscribers.keys())

    # -------------------------------------------------------------------------
    # Publishing
    # -------------------------------------------------------------------------

    def publish(
        self,
        event: BusEvent,
        timeout: float = PUBLISHER_TIMEOUT_SECONDS,
    ) -> bool:
        """
        Publish an event to the bus (synchronous).

        Thread-safe. Can be called from any thread. The event is placed
        on the priority queue and dispatched asynchronously to subscribers.

        Args:
            event: The BusEvent to publish.
            timeout: Maximum seconds to wait if the queue is full.

        Returns:
            True if the event was enqueued successfully.

        Raises:
            EventBusFullError: If the queue is full and timeout expires.
            EventPublishError: For unexpected publishing errors.
        """
        if not self._running:
            logger.warning(
                "Attempted to publish to stopped EventBus: {type}",
                type=event.event_type.value,
            )
            return False

        # Global rate limiting — token bucket
        if not self._rate_limiter.consume():
            logger.debug(
                "EventBus rate limit hit — throttling publisher '{source}'",
                source=event.source,
            )
            # Rate limit: don't error, just slow down
            time.sleep(0.001)

        with self._queue_lock:
            # Check queue capacity
            if len(self._queue) >= self._max_queue_size:
                self._metrics.total_dropped += 1
                raise EventBusFullError(
                    queue_size=len(self._queue),
                    max_size=self._max_queue_size,
                    dropped_event_type=event.event_type.value,
                )

            # Enqueue with priority
            sequence = self._sequence
            self._sequence += 1

            entry = _QueueEntry(
                priority=event.priority.value,
                sequence=sequence,
                enqueue_time=time.time(),
                event=event,
            )
            heapq.heappush(self._queue, entry)

            depth = len(self._queue)
            self._metrics.total_published += 1
            self._metrics.current_queue_depth = depth
            if depth > self._metrics.peak_queue_depth:
                self._metrics.peak_queue_depth = depth

            # Wake dispatch thread
            self._queue_lock.notify()

        # Track throughput
        with self._throughput_window_lock:
            self._throughput_window.append(time.time())

        return True

    async def publish_async(self, event: BusEvent) -> bool:
        """
        Publish an event to the bus (async-friendly).

        Wraps the synchronous publish() in an asyncio executor to avoid
        blocking the event loop when the queue is full.

        Args:
            event: The BusEvent to publish.

        Returns:
            True if enqueued successfully.
        """
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self.publish, event)

    def publish_many(self, events: list[BusEvent]) -> int:
        """
        Batch-publish multiple events.

        More efficient than calling publish() in a loop because it
        acquires the queue lock once.

        Args:
            events: List of BusEvents to enqueue.

        Returns:
            Number of events successfully enqueued.
        """
        if not events:
            return 0

        enqueued = 0
        with self._queue_lock:
            for event in events:
                if len(self._queue) >= self._max_queue_size:
                    self._metrics.total_dropped += len(events) - enqueued
                    logger.warning(
                        "EventBus full during batch publish — dropped {n} events.",
                        n=len(events) - enqueued,
                    )
                    break

                sequence = self._sequence
                self._sequence += 1
                entry = _QueueEntry(
                    priority=event.priority.value,
                    sequence=sequence,
                    enqueue_time=time.time(),
                    event=event,
                )
                heapq.heappush(self._queue, entry)
                enqueued += 1

            self._metrics.total_published += enqueued
            self._metrics.current_queue_depth = len(self._queue)
            if len(self._queue) > self._metrics.peak_queue_depth:
                self._metrics.peak_queue_depth = len(self._queue)

            if enqueued > 0:
                self._queue_lock.notify_all()

        return enqueued

    # -------------------------------------------------------------------------
    # Dispatch Loop (runs in background thread)
    # -------------------------------------------------------------------------

    def _dispatch_loop(self) -> None:
        """
        Main dispatch loop running in the background thread.

        Continuously dequeues events from the priority queue and
        dispatches them to matching subscribers via their executor pools.
        """
        logger.debug("EventBus dispatch loop started.")

        while self._running or len(self._queue) > 0:
            entry = self._dequeue_event()

            if entry is None:
                # No events — wait for up to 100ms before checking again
                with self._queue_lock:
                    self._queue_lock.wait(timeout=0.1)
                continue

            event = entry.event

            # Drop expired events
            if event.is_expired:
                self._metrics.total_expired += 1
                logger.debug(
                    "Dropping expired event {id} (age={age:.1f}s > max={max}s)",
                    id=event.event_id,
                    age=event.age_seconds,
                    max=EVENT_MAX_AGE_SECONDS,
                )
                continue

            # Calculate dispatch latency
            dispatch_latency = time.time() - entry.enqueue_time
            self._update_latency_metric(dispatch_latency)

            # Dispatch to all matching subscribers
            self._dispatch_to_subscribers(event)
            self._metrics.total_processed += 1

            with self._throughput_window_lock:
                self._update_throughput_metric()

        logger.debug("EventBus dispatch loop exited.")

    def _dequeue_event(self) -> _QueueEntry | None:
        """
        Dequeue the highest-priority event from the queue.

        Returns None if the queue is empty.
        Thread-safe via the queue lock.
        """
        with self._queue_lock:
            if not self._queue:
                return None
            entry = heapq.heappop(self._queue)
            self._metrics.current_queue_depth = len(self._queue)
            return entry

    def _dispatch_to_subscribers(self, event: BusEvent) -> None:
        """
        Dispatch a single event to all matching subscribers.

        Each subscriber receives the event in its own isolated executor
        thread, preventing one slow subscriber from blocking others.
        """
        with self._subscribers_lock:
            # Snapshot the subscriber dict to avoid lock-holding during dispatch
            matching = [
                (name, sub)
                for name, sub in self._subscribers.items()
                if sub.matches(event)
            ]

        if not matching:
            return  # No subscribers interested in this event

        futures: list[Future[None]] = []
        for name, subscriber in matching:
            executor = self._subscriber_executors.get(name)
            if executor is None:
                continue  # Subscriber was removed during dispatch

            subscriber._events_received += 1
            future = executor.submit(
                self._invoke_subscriber, subscriber, event
            )
            futures.append(future)

        # We don't wait for futures here — fire and forget for throughput.
        # Errors are caught inside _invoke_subscriber.

    def _invoke_subscriber(
        self, subscriber: Subscriber, event: BusEvent
    ) -> None:
        """
        Safely invoke a subscriber callback with error isolation.

        Errors in one subscriber do NOT propagate to others or crash the bus.
        Repeated failures are tracked and can trigger subscriber health alerts.

        Args:
            subscriber: The subscriber to invoke.
            event: The event to deliver.
        """
        start_time = time.monotonic()

        try:
            if subscriber.is_async:
                # Run coroutine in a new event loop in this thread
                loop = asyncio.new_event_loop()
                try:
                    loop.run_until_complete(subscriber.callback(event))  # type: ignore[arg-type]
                finally:
                    loop.close()
            else:
                subscriber.callback(event)

            elapsed = time.monotonic() - start_time
            subscriber._events_processed += 1
            subscriber._total_processing_time += elapsed
            subscriber._last_event_time = time.time()

            # Warn if subscriber is slow (>100ms blocks the thread pool)
            if elapsed > 0.1:
                logger.warning(
                    "Slow subscriber '{name}': processed {type} in {ms:.0f}ms",
                    name=subscriber.name,
                    type=event.event_type.value,
                    ms=elapsed * 1000,
                )

        except SubscriberError:
            # Already formatted — re-raise won't propagate, just log
            subscriber._events_failed += 1
            logger.error(
                "Subscriber '{name}' error processing {type}: dropping event {id}",
                name=subscriber.name,
                type=event.event_type.value,
                id=event.event_id,
            )
            self._add_to_dlq(event, subscriber.name)

        except Exception as exc:
            subscriber._events_failed += 1
            error = UnexpectedInternalError(
                component=f"subscriber:{subscriber.name}",
                original_error=exc,
            )
            logger.error(
                "Subscriber '{name}' raised unhandled exception: {exc}",
                name=subscriber.name,
                exc=error,
            )
            self._add_to_dlq(event, subscriber.name)

            # Log failure rate warning
            if subscriber.failure_rate > 0.1:
                logger.warning(
                    "Subscriber '{name}' has high failure rate: {rate:.1%}",
                    name=subscriber.name,
                    rate=subscriber.failure_rate,
                )

    # -------------------------------------------------------------------------
    # Dead Letter Queue
    # -------------------------------------------------------------------------

    def _add_to_dlq(self, event: BusEvent, failed_subscriber: str) -> None:
        """Add a failed event to the dead letter queue."""
        with self._dlq_lock:
            self._dlq.append((event, failed_subscriber))
            self._metrics.total_dead_lettered += 1

    def get_dead_letters(self) -> list[tuple[BusEvent, str]]:
        """
        Return all events in the dead letter queue.

        Returns:
            List of (event, subscriber_name) tuples for failed events.
        """
        with self._dlq_lock:
            return list(self._dlq)

    def clear_dead_letters(self) -> int:
        """Clear the dead letter queue and return the number cleared."""
        with self._dlq_lock:
            count = len(self._dlq)
            self._dlq.clear()
            return count

    # -------------------------------------------------------------------------
    # Metrics & Health
    # -------------------------------------------------------------------------

    def _update_latency_metric(self, latency: float) -> None:
        """Exponential moving average of dispatch latency."""
        alpha = 0.1
        current = self._metrics.avg_dispatch_latency_ms
        self._metrics.avg_dispatch_latency_ms = (
            alpha * (latency * 1000) + (1 - alpha) * current
        )

    def _update_throughput_metric(self) -> None:
        """Calculate events/sec over a 1-second sliding window."""
        now = time.time()
        cutoff = now - 1.0
        # Remove entries older than 1 second
        while self._throughput_window and self._throughput_window[0] < cutoff:
            self._throughput_window.popleft()
        self._metrics.current_throughput_eps = float(len(self._throughput_window))

    def get_metrics(self) -> EventBusMetrics:
        """Return a snapshot of current bus metrics."""
        return self._metrics

    def get_subscriber_metrics(self) -> list[dict[str, Any]]:
        """Return per-subscriber performance metrics."""
        with self._subscribers_lock:
            return [
                {
                    "name": sub.name,
                    "events_received": sub._events_received,
                    "events_processed": sub._events_processed,
                    "events_failed": sub._events_failed,
                    "failure_rate": f"{sub.failure_rate:.1%}",
                    "avg_processing_ms": f"{sub.avg_processing_time_ms:.2f}",
                    "subscribed_types": (
                        [et.value for et in sub.event_types]
                        if sub.event_types
                        else ["*ALL*"]
                    ),
                }
                for sub in self._subscribers.values()
            ]

    def health_check(self) -> dict[str, Any]:
        """
        Return health status of the event bus.

        Used by the resource manager and API /health endpoint.
        """
        metrics = self._metrics
        queue_pct = (
            (metrics.current_queue_depth / self._max_queue_size) * 100
            if self._max_queue_size > 0
            else 0
        )

        status = "healthy"
        issues: list[str] = []

        if not self._running:
            status = "stopped"
            issues.append("Bus is not running")
        elif queue_pct > 80:
            status = "degraded"
            issues.append(f"Queue at {queue_pct:.0f}% capacity")
        elif metrics.avg_dispatch_latency_ms > 500:
            status = "degraded"
            issues.append(f"High dispatch latency: {metrics.avg_dispatch_latency_ms:.0f}ms")

        # Check for consistently failing subscribers
        with self._subscribers_lock:
            for sub in self._subscribers.values():
                if sub.failure_rate > 0.5 and sub._events_received > 10:
                    status = "degraded"
                    issues.append(
                        f"Subscriber '{sub.name}' failure rate: {sub.failure_rate:.0%}"
                    )

        return {
            "status": status,
            "running": self._running,
            "issues": issues,
            "metrics": metrics.to_dict(),
            "dead_letter_count": len(self._dlq),
        }


# =============================================================================
# TOKEN BUCKET RATE LIMITER
# =============================================================================

class _TokenBucket:
    """
    Thread-safe token bucket rate limiter.

    Used to enforce the global events-per-second limit across all publishers.

    The bucket fills at ``refill_rate`` tokens/second up to ``capacity``.
    Each consume() call removes one token. If no tokens are available,
    consume() returns False (caller should throttle).
    """

    def __init__(self, capacity: int, refill_rate: float) -> None:
        """
        Args:
            capacity: Maximum tokens (= max burst size).
            refill_rate: Tokens added per second.
        """
        self._capacity = float(capacity)
        self._refill_rate = refill_rate
        self._tokens = float(capacity)
        self._last_refill = time.monotonic()
        self._lock = threading.Lock()

    def consume(self, tokens: float = 1.0) -> bool:
        """
        Attempt to consume ``tokens`` from the bucket.

        Returns:
            True if tokens were available and consumed.
            False if the bucket is empty (caller should slow down).
        """
        with self._lock:
            self._refill()
            if self._tokens >= tokens:
                self._tokens -= tokens
                return True
            return False

    def _refill(self) -> None:
        """Add tokens based on elapsed time since last refill."""
        now = time.monotonic()
        elapsed = now - self._last_refill
        added = elapsed * self._refill_rate
        self._tokens = min(self._capacity, self._tokens + added)
        self._last_refill = now


# =============================================================================
# MODULE-LEVEL SINGLETON
# =============================================================================

# The application instantiates one EventBus and stores it here.
# Other modules import and use the singleton via get_event_bus().
_singleton_bus: Optional[EventBus] = None


def initialize_event_bus(
    max_queue_size: int = EVENT_QUEUE_SIZE,
    max_events_per_second: int = MAX_EVENTS_PER_SECOND,
) -> EventBus:
    """
    Initialize and start the global EventBus singleton.

    Must be called once during application startup (in app.py).

    Args:
        max_queue_size: Maximum event queue depth.
        max_events_per_second: Global publisher rate limit.

    Returns:
        The started EventBus instance.
    """
    global _singleton_bus
    bus = EventBus(
        max_queue_size=max_queue_size,
        max_events_per_second=max_events_per_second,
    )
    bus.start()
    _singleton_bus = bus
    return bus


def get_event_bus() -> EventBus:
    """
    Return the global EventBus singleton.

    Raises:
        RuntimeError: If initialize_event_bus() has not been called.
    """
    if _singleton_bus is None:
        raise RuntimeError(
            "EventBus has not been initialized. "
            "Call core.event_bus.initialize_event_bus() during startup."
        )
    return _singleton_bus


def get_bus() -> EventBus:
    """Alias for get_event_bus() — shorter to type in hot paths."""
    return get_event_bus()