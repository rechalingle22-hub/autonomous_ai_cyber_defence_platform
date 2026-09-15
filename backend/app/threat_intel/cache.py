# type: ignore
# pyright: reportMissingImports=false, reportUndefinedVariable=false, reportGeneralTypeIssues=false
"""Dual-Tier (In-Memory LRU + Optional Redis) Threat Intelligence IOC Cache."""

import os
import sys
import time
import json
from collections import OrderedDict
from typing import Optional, Dict, Any, List

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))
VENV_SITE = os.path.join(ROOT_DIR, ".venv", "lib", "python3.13", "site-packages")
for p in (ROOT_DIR, VENV_SITE):
    if p not in sys.path and os.path.exists(p):
        sys.path.insert(0, p)

from backend.app.config.settings import settings
from backend.app.threat_intel.models import IOCRecord, IndicatorType, ThreatSeverity, ConfidenceLevel


class IOCCache:
    """High-performance dual-tier IOC Cache with TTL and LRU eviction."""

    def __init__(self, max_size: int = 10000, default_ttl_seconds: int = 86400):
        self.max_size = max_size
        self.default_ttl = default_ttl_seconds
        self._memory_cache: OrderedDict[str, tuple[IOCRecord, float]] = OrderedDict()
        self._hits = 0
        self._misses = 0
        self._evictions = 0

    def _normalize_key(self, key: str) -> str:
        """Normalizes indicator keys (trimmed and lowercased for domains/hashes)."""
        clean = key.strip()
        # Preserve case for URLs/mixed tokens, lower for IPs, domains, hashes
        return clean.lower()

    async def get(self, indicator_value: str) -> Optional[IOCRecord]:
        """Retrieves an IOC record from memory or Redis cache if valid and unexpired."""
        norm_key = self._normalize_key(indicator_value)
        now = time.time()

        # Tier 1: Local In-Memory LRU
        if norm_key in self._memory_cache:
            record, expire_at = self._memory_cache[norm_key]
            if now < expire_at:
                # Cache hit: mark recently used
                self._memory_cache.move_to_end(norm_key)
                self._hits += 1
                return record
            else:
                # Expired
                del self._memory_cache[norm_key]

        # Tier 2: Redis (if enabled)
        if getattr(settings, "REDIS_ENABLED", False):
            try:
                from backend.app.database.redis_client import redis_manager
                client = redis_manager.client
                if client is not None:
                    cached_json = await client.get(f"ioc:{norm_key}")
                    if cached_json:
                        data = json.loads(cached_json)
                        record = IOCRecord(**data)
                        # Back-populate Tier 1 memory cache
                        self._set_memory(norm_key, record, self.default_ttl)
                        self._hits += 1
                        return record
            except Exception:
                pass

        self._misses += 1
        return None

    def _set_memory(self, norm_key: str, record: IOCRecord, ttl_seconds: int) -> None:
        """Helper to insert into memory cache with LRU eviction."""
        expire_at = time.time() + ttl_seconds
        if norm_key in self._memory_cache:
            self._memory_cache.move_to_end(norm_key)
        self._memory_cache[norm_key] = (record, expire_at)

        # Enforce LRU cap
        if len(self._memory_cache) > self.max_size:
            self._memory_cache.popitem(last=False)
            self._evictions += 1

    async def set(
        self,
        indicator_value: str,
        record: IOCRecord,
        ttl_seconds: Optional[int] = None,
    ) -> None:
        """Stores an IOC record in the dual-tier cache."""
        norm_key = self._normalize_key(indicator_value)
        ttl = ttl_seconds if ttl_seconds is not None else self.default_ttl

        # 1. Update Tier 1 Memory Cache
        self._set_memory(norm_key, record, ttl)

        # 2. Update Tier 2 Redis (if enabled)
        if getattr(settings, "REDIS_ENABLED", False):
            try:
                from backend.app.database.redis_client import redis_manager
                client = redis_manager.client
                if client is not None:
                    payload = record.model_dump_json()
                    await client.setex(f"ioc:{norm_key}", ttl, payload)
            except Exception:
                pass

    async def bulk_get(self, indicators: List[str]) -> Dict[str, Optional[IOCRecord]]:
        """Batch lookup for multiple indicators."""
        results: Dict[str, Optional[IOCRecord]] = {}
        for ind in indicators:
            results[ind] = await self.get(ind)
        return results

    async def bulk_set(self, records: List[IOCRecord], ttl_seconds: Optional[int] = None) -> None:
        """Batch store for multiple IOC records."""
        for rec in records:
            await self.set(rec.indicator_value, rec, ttl_seconds=ttl_seconds)

    async def delete(self, indicator_value: str) -> None:
        """Evicts an indicator from cache."""
        norm_key = self._normalize_key(indicator_value)
        if norm_key in self._memory_cache:
            del self._memory_cache[norm_key]

        if getattr(settings, "REDIS_ENABLED", False):
            try:
                from backend.app.database.redis_client import redis_manager
                client = redis_manager.client
                if client is not None:
                    await client.delete(f"ioc:{norm_key}")
            except Exception:
                pass

    async def clear(self) -> None:
        """Flushes the local in-memory cache."""
        self._memory_cache.clear()

    def get_stats(self) -> Dict[str, Any]:
        """Returns cache telemetry and operational performance metrics."""
        total_queries = self._hits + self._misses
        hit_ratio = (self._hits / total_queries) if total_queries > 0 else 0.0
        return {
            "cached_items_count": len(self._memory_cache),
            "max_size": self.max_size,
            "hits": self._hits,
            "misses": self._misses,
            "evictions": self._evictions,
            "hit_ratio": round(hit_ratio, 4),
        }


# Global singleton instance
ioc_cache = IOCCache()

