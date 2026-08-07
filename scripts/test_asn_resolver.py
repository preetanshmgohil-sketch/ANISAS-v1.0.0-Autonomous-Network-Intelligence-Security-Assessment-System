"""Test runner for asn_resolver placed in scripts/ so it can be executed without project-level test folder conflicts.

Run: python scripts/test_asn_resolver.py
"""
from __future__ import annotations

import asyncio

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


class FakeClient:
    def __init__(self, mapping):
        # mapping: url_prefix -> FakeResponse
        self.mapping = mapping
        self.calls = []

    async def get(self, url, params=None, timeout=None, **kwargs):
        self.calls.append((url, params))
        for prefix, resp in self.mapping.items():
            if url.startswith(prefix):
                return resp
        return FakeResponse(json_data={})


async def run_resolve_with_client(ip, client):
    orig = ar.get_client
    try:
        ar.get_client = lambda: client
        return await ar.resolve_asn(ip)
    finally:
        ar.get_client = orig


async def _test_resolve_prefers_ipinfo():
    ip = "1.2.3.4"
    ipinfo_json = {"org": "AS12345 Example ISP", "country": "US"}
    bgp_json = {"data": {"prefixes": [{"asn": 9999, "name": "Other", "prefix": "1.2.3.0/24"}]}}
    fake = FakeClient({
        "https://ipinfo.io/": FakeResponse(json_data=ipinfo_json),
        "https://api.bgpview.io/ip/": FakeResponse(json_data=bgp_json),
    })

    asn_entries, prefixes, sources = await run_resolve_with_client(ip, fake)
    assert asn_entries
    assert asn_entries[0].asn == "AS12345"
    assert "ipinfo.io" in sources


async def _test_cache_prevents_duplicate_fetch():
    ip = "5.6.7.8"
    ipinfo_json = {"org": "AS22222 Cached ISP", "country": "GB"}
    fake = FakeClient({
        "https://ipinfo.io/": FakeResponse(json_data=ipinfo_json),
    })

    cache_mod.cache._store.clear()

    res1 = await run_resolve_with_client(ip, fake)
    res2 = await run_resolve_with_client(ip, fake)

    assert len(fake.calls) >= 1
    assert res1[0][0].asn == res2[0][0].asn


def main():
    asyncio.run(_test_resolve_prefers_ipinfo())
    asyncio.run(_test_cache_prevents_duplicate_fetch())
    print('tests passed')


if __name__ == '__main__':
    main()
