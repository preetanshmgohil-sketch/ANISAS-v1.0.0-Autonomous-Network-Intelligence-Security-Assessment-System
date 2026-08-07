"""Simple async TTL in-memory cache used for external lookups.

This is intentionally lightweight to avoid adding runtime dependencies. It
supports an async get_or_set(key, factory) that calls factory() to produce
the value (a coroutine) when the key is missing or expired.
"""
from __future__ import annotations

import asyncio
import time
from typing import Any, Callable, Awaitable


class AsyncTTLCache:
    def __init__(self, ttl: int = 300) -> None:
        self.ttl = ttl
        self._store: dict[str, tuple[Any, float]] = {}
        self._lock = asyncio.Lock()

    async def get(self, key: str) -> Any | None:
        async with self._lock:
            entry = self._store.get(key)
            if not entry:
                return None
            value, expiry = entry
            if expiry < time.time():
                # expired
                del self._store[key]
                return None
            return value

    async def set(self, key: str, value: Any, ttl: int | None = None) -> None:
        expiry = time.time() + (ttl or self.ttl)
        async with self._lock:
            self._store[key] = (value, expiry)

    async def get_or_set(self, key: str, factory: Callable[[], Awaitable[Any]], ttl: int | None = None) -> Any:
        """Retrieve a value from cache or call factory() to compute and store it.

        factory must be a callable that returns an awaitable (coroutine).
        """
        # Fast path: try without locking to reduce contention
        entry = self._store.get(key)
        if entry:
            value, expiry = entry
            if expiry >= time.time():
                return value
        # Slow path: acquire lock and check again
        async with self._lock:
            entry = self._store.get(key)
            if entry:
                value, expiry = entry
                if expiry >= time.time():
                    return value
            # compute and store
            value = await factory()
            self._store[key] = (value, time.time() + (ttl or self.ttl))
            return value


# module-level default cache instance
cache = AsyncTTLCache(ttl=300)  # 5 minutes default TTL


# convenience wrapper
async def get_or_set(key: str, factory: Callable[[], Awaitable[Any]], ttl: int | None = None) -> Any:
    return await cache.get_or_set(key, factory, ttl=ttl)
