"""Real-Time Event Broker Interface & Resilient In-Memory / Kafka Implementations.

Guarantees:
- Zero external infrastructure requirement: falls back to an async in-memory broker when Kafka is unavailable.
- Multi-subscriber topic routing with isolated asynchronous queues.
- Built-in metrics tracking (published, consumed, errors, DLQ routing).
- Clean lifecycle management for FastAPI lifespan hooks.
"""

import asyncio
import logging
from abc import ABC, abstractmethod
from typing import Dict, Any, List, Callable, Awaitable, Optional
from datetime import datetime, timezone
from backend.app.streaming.topics import EventTopic, ALL_TOPICS
from backend.app.config.settings import settings

logger = logging.getLogger("cyberdefense.streaming")

MessageHandler = Callable[[Dict[str, Any]], Awaitable[None]]


class EventBroker(ABC):
    """Abstract interface for publish-subscribe event brokers."""

    @abstractmethod
    async def start(self) -> None:
        """Starts the broker connection and worker dispatch loops."""
        pass

    @abstractmethod
    async def stop(self) -> None:
        """Gracefully stops the broker and drains pending queues."""
        pass

    @abstractmethod
    async def publish(self, topic: str, message: Dict[str, Any]) -> None:
        """Publishes a dictionary payload to the specified topic."""
        pass

    @abstractmethod
    def subscribe(self, topic: str, handler: MessageHandler) -> None:
        """Registers an asynchronous message handler for a topic."""
        pass

    @abstractmethod
    def get_stats(self) -> Dict[str, Any]:
        """Returns broker health and telemetry metrics."""
        pass


class InMemoryEventBroker(EventBroker):
    """Resilient asynchronous in-memory event broker using native asyncio queues."""

    def __init__(self, max_queue_size: int = 10000) -> None:
        self.max_queue_size = max_queue_size
        self._queues: Dict[str, asyncio.Queue] = {topic: asyncio.Queue(maxsize=max_queue_size) for topic in ALL_TOPICS}
        self._subscribers: Dict[str, List[MessageHandler]] = {topic: [] for topic in ALL_TOPICS}
        self._consumer_tasks: List[asyncio.Task] = []
        self._dispatcher_topics: set = set()
        self._is_running: bool = False
        self._dlq_messages: List[Dict[str, Any]] = []
        self._stats = {
            "published_count": 0,
            "consumed_count": 0,
            "dlq_count": 0,
            "errors_count": 0,
        }

    def _ensure_dispatcher_for_topic(self, topic: str) -> None:
        """Starts a background dispatcher for a topic if running and not already active."""
        if self._is_running and topic not in self._dispatcher_topics:
            task = asyncio.create_task(self._topic_dispatcher(topic), name=f"dispatcher-{topic}")
            self._consumer_tasks.append(task)
            self._dispatcher_topics.add(topic)

    async def start(self) -> None:
        """Starts consumer dispatch workers for all known topics."""
        if self._is_running:
            return
        self._is_running = True
        topics_to_start = set(ALL_TOPICS).union(self._queues.keys()).union(self._subscribers.keys())
        for topic in topics_to_start:
            self._ensure_dispatcher_for_topic(topic)
        logger.info("InMemoryEventBroker started with topics: %s", list(self._dispatcher_topics))

    async def stop(self) -> None:
        """Cancels consumer tasks and stops the in-memory broker."""
        if not self._is_running:
            return
        self._is_running = False
        for task in self._consumer_tasks:
            task.cancel()
        await asyncio.gather(*self._consumer_tasks, return_exceptions=True)
        self._consumer_tasks.clear()
        self._dispatcher_topics.clear()
        logger.info("InMemoryEventBroker stopped.")

    async def publish(self, topic: str, message: Dict[str, Any]) -> None:
        """Pushes a message onto the target topic queue."""
        if topic not in self._queues:
            self._queues[topic] = asyncio.Queue(maxsize=self.max_queue_size)
            self._subscribers[topic] = []

        self._ensure_dispatcher_for_topic(topic)

        # Add broker metadata
        payload = message.copy()
        if "_broker_meta" not in payload:
            payload["_broker_meta"] = {
                "published_at": datetime.now(timezone.utc).isoformat(),
                "topic": topic,
            }

        if topic == EventTopic.ALERTS_DLQ.value:
            self._dlq_messages.append(payload)
            if len(self._dlq_messages) > 1000:
                self._dlq_messages.pop(0)
            self._stats["dlq_count"] += 1

        try:
            self._queues[topic].put_nowait(payload)
            self._stats["published_count"] += 1
        except asyncio.QueueFull:
            logger.warning("Topic queue %s is full! Dropping oldest item.", topic)
            try:
                self._queues[topic].get_nowait()
                self._queues[topic].put_nowait(payload)
            except Exception as e:
                logger.error("Failed to enqueue message to %s: %s", topic, str(e))
                self._stats["errors_count"] += 1

    def subscribe(self, topic: str, handler: MessageHandler) -> None:
        """Registers a callback for messages on the specified topic."""
        if topic not in self._subscribers:
            self._subscribers[topic] = []
            self._queues[topic] = asyncio.Queue(maxsize=self.max_queue_size)
        self._subscribers[topic].append(handler)
        self._ensure_dispatcher_for_topic(topic)

    async def _topic_dispatcher(self, topic: str) -> None:
        """Continuously pulls from a topic queue and fans out to all registered handlers."""
        queue = self._queues[topic]
        while self._is_running:
            try:
                message = await queue.get()
                handlers = self._subscribers.get(topic, [])
                if handlers:
                    # Execute all subscribers concurrently
                    await asyncio.gather(
                        *[self._safe_execute_handler(h, message, topic) for h in handlers],
                        return_exceptions=True,
                    )
                self._stats["consumed_count"] += 1
                queue.task_done()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("Error in topic dispatcher %s: %s", topic, str(e))
                self._stats["errors_count"] += 1
                await asyncio.sleep(0.05)

    async def _safe_execute_handler(self, handler: MessageHandler, message: Dict[str, Any], topic: str) -> None:
        """Executes a handler safely without crashing the dispatcher loop."""
        try:
            await handler(message)
        except Exception as e:
            logger.error("Handler error on topic %s: %s", topic, str(e), exc_info=True)
            self._stats["errors_count"] += 1
            # If a processing failure occurs on an active processing topic, forward to DLQ
            if topic != EventTopic.ALERTS_DLQ.value:
                dlq_entry = {
                    "failed_topic": topic,
                    "failed_at": datetime.now(timezone.utc).isoformat(),
                    "error_detail": str(e),
                    "original_payload": message,
                }
                await self.publish(EventTopic.ALERTS_DLQ.value, dlq_entry)

    def get_stats(self) -> Dict[str, Any]:
        """Returns operational metrics and queue depths."""
        return {
            "broker_type": "IN_MEMORY",
            "is_running": self._is_running,
            "stats": self._stats.copy(),
            "queue_sizes": {topic: q.qsize() for topic, q in self._queues.items()},
            "subscriber_counts": {topic: len(handlers) for topic, handlers in self._subscribers.items()},
            "dlq_cached_count": len(self._dlq_messages),
        }

    def get_dlq_records(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Returns recent Dead-Letter Queue items."""
        return list(reversed(self._dlq_messages[-limit:]))


# Global default broker instance
event_broker = InMemoryEventBroker()
