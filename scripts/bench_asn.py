"""Benchmark script to measure latency and memory of resolve_asn with a fake client.

Run: python scripts/bench_asn.py
"""
from __future__ import annotations

import asyncio
import time
import tracemalloc

from anisas import asn_resolver as ar
from anisas import cache as cache_mod


class FakeResponse:
    def __init__(self, json_data=None, text_data=None, lines=None):
        self._json = json_data or {}
        self._text = text_data or ""
        self._lines = lines or []

    def raise_for_status(self):
        return None

    def json(self):
        return self._json

    @property
    def text(self):
        return self._text

    async def aiter_lines(self):
        for l in self._lines:
            yield l


class SlowFakeClient:
    def __init__(self, mapping, delay=0.05):
        self.mapping = mapping
        self.delay = delay

    async def get(self, url, params=None, timeout=None, **kwargs):
        # simulate network latency
        await asyncio.sleep(self.delay)
        for prefix, resp in self.mapping.items():
            if url.startswith(prefix):
                return resp
        return FakeResponse(json_data={})


async def run_once(ip, client):
    orig = ar.get_client
    try:
        ar.get_client = lambda: client
        return await ar.resolve_asn(ip)
    finally:
        ar.get_client = orig


async def bench(ip, iterations=5):
    ipinfo_json = {"org": "AS33333 Benchmark ISP", "country": "US"}
    mapping = {"https://ipinfo.io/": FakeResponse(json_data=ipinfo_json)}
    client = SlowFakeClient(mapping, delay=0.05)

    # cold (clear cache)
    cache_mod.cache._store.clear()
    tracemalloc.start()
    t0 = time.perf_counter()
    await run_once(ip, client)
    elapsed_cold = time.perf_counter() - t0
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    # warm (cache hit)
    t0 = time.perf_counter()
    await run_once(ip, client)
    elapsed_warm = time.perf_counter() - t0

    print(f"Cold run: {elapsed_cold:.3f}s, memory peak: {peak/1024:.1f} KiB")
    print(f"Warm run: {elapsed_warm:.3f}s")


if __name__ == '__main__':
    asyncio.run(bench('8.8.8.8'))
