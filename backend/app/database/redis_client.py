"""Redis connection manager with resilient in-memory fallback.

Provides sub-millisecond key-value caching for rate limits, sliding windows, and IOCs.
"""

import time
from typing import Optional, Any, Dict
import redis.asyncio as aioredis
from backend.app.config.settings import settings


class InMemoryCacheFallback:
    """Mock Redis client for local development or testing when Redis is offline."""

    def __init__(self) -> None:
        self._store: Dict[str, Any] = {}
        self._expires: Dict[str, float] = {}

    async def get(self, key: str) -> Optional[str]:
        if key in self._expires and time.time() > self._expires[key]:
            self._store.pop(key, None)
            self._expires.pop(key, None)
            return None
        return self._store.get(key)

    async def set(self, key: str, value: Any, ex: Optional[int] = None) -> bool:
        self._store[key] = str(value)
        if ex is not None:
            self._expires[key] = time.time() + ex
        elif key in self._expires:
            del self._expires[key]
        return True

    async def delete(self, key: str) -> int:
        removed = 1 if key in self._store else 0
        self._store.pop(key, None)
        self._expires.pop(key, None)
        return removed

    async def exists(self, key: str) -> int:
        val = await self.get(key)
        return 1 if val is not None else 0

    async def incr(self, key: str) -> int:
        val = await self.get(key)
        current = int(val) if val is not None else 0
        current += 1
        await self.set(key, current)
        return current

    async def ping(self) -> bool:
        return True

    async def close(self) -> None:
        pass


class RedisManager:
    """Manages Redis connection lifecycle."""

    def __init__(self) -> None:
        self.client: Any = None
        self._is_connected: bool = True

    async def connect(self) -> None:
        if settings.REDIS_ENABLED:
            try:
                client = aioredis.from_url(
                    settings.REDIS_URL,
                    encoding="utf-8",
                    decode_responses=True,
                )
                await client.ping()
                self.client = client
            except Exception:
                # Fallback to in-memory cache gracefully
                self.client = InMemoryCacheFallback()
        else:
            self.client = InMemoryCacheFallback()

    async def disconnect(self) -> None:
        if self.client:
            await self.client.close()


redis_manager = RedisManager()


async def get_redis() -> Any:
    """FastAPI dependency for accessing Redis/Cache."""
    if redis_manager.client is None:
        await redis_manager.connect()
    return redis_manager.client

