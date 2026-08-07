"""ISP profile discovery and multi-ASN detection."""

from __future__ import annotations

import asyncio
import logging

import httpx
from cachetools import TTLCache

from .models import ASNEntry, ISPProfile

logger = logging.getLogger(__name__)

_TIMEOUT = httpx.Timeout(8.0, connect=5.0)

_BGPVIEW_ASN_URL = "https://api.bgpview.io/asn/{asn}"
_BGPVIEW_UPSTREAM_URL = "https://api.bgpview.io/asn/{asn}/upstreams"
_BGPVIEW_DOWNSTREAM_URL = "https://api.bgpview.io/asn/{asn}/downstreams"

_cache_asn_meta: TTLCache = TTLCache(maxsize=512, ttl=1800)
_cache_peering: TTLCache = TTLCache(maxsize=512, ttl=1800)
_cache_secondary_isp: TTLCache = TTLCache(maxsize=256, ttl=3600)


async def _fetch_asn_meta(asn: str, client: httpx.AsyncClient) -> dict | None:
    """Fetch ASN metadata from bgpview.io."""
    cached = _cache_asn_meta.get(asn)
    if cached is not None:
        return cached

    asn_num = asn.replace("AS", "")
    try:
        resp = await client.get(_BGPVIEW_ASN_URL.format(asn=asn_num))
        resp.raise_for_status()
        result = resp.json().get("data", {})
        _cache_asn_meta[asn] = result
        return result
    except Exception as exc:
        logger.debug("bgpview.io ASN meta failed for %s: %s", asn, exc)
        return None


async def _fetch_peering(asn: str, client: httpx.AsyncClient) -> list[str]:
    """Fetch upstream + downstream peers concurrently."""
    cached = _cache_peering.get(asn)
    if cached is not None:
        return cached

    asn_num = asn.replace("AS", "")

    async def _fetch_one(url_template: str) -> list[str]:
        try:
            resp = await client.get(url_template.format(asn=asn_num))
            resp.raise_for_status()
            data = resp.json().get("data", {})
            peers: list[str] = []
            for entry in data:
                name = entry.get("name") or entry.get("asn", "")
                asn_id = entry.get("asn", "")
                peers.append(f"AS{asn_id} - {name}" if name else f"AS{asn_id}")
            return peers
        except Exception as exc:
            logger.debug("Peering query failed for %s: %s", asn, exc)
            return []

    results = await asyncio.gather(
        _fetch_one(_BGPVIEW_UPSTREAM_URL),
        _fetch_one(_BGPVIEW_DOWNSTREAM_URL),
    )
    seen: set[str] = set()
    unique: list[str] = []
    for peer_list in results:
        for p in peer_list:
            if p not in seen:
                seen.add(p)
                unique.append(p)
    _cache_peering[asn] = unique
    return unique


async def _find_secondary_asns(
    ip: str, primary_asn: str, client: httpx.AsyncClient
) -> list[ASNEntry]:
    """Detect additional ASNs serving the same organization."""
    cache_key = f"{primary_asn}:{ip}"
    cached = _cache_secondary_isp.get(cache_key)
    if cached is not None:
        return cached

    try:
        meta = await _fetch_asn_meta(primary_asn, client)
        if not meta:
            return []
        description = meta.get("description", "")
        if not description:
            return []

        search_url = "https://api.bgpview.io/search"
        resp = await client.get(search_url, params={"query_term": description, "page_size": 50})
        resp.raise_for_status()
        results = resp.json().get("data", {}).get("asns", [])
        secondary: list[ASNEntry] = []
        for r in results:
            asn_str = f"AS{r.get('asn', '')}"
            if asn_str == primary_asn:
                continue
            r_desc = (r.get("description") or "").lower()
            if description.lower()[:10] in r_desc or r_desc[:10] in description.lower():
                secondary.append(ASNEntry(
                    asn=asn_str,
                    organization=r.get("name") or r.get("description", ""),
                    country=r.get("country_code", ""),
                    registry=r.get("registry", ""),
                    is_primary=False,
                ))
        result = secondary[:5]
        _cache_secondary_isp[cache_key] = result
        return result
    except Exception as exc:
        logger.debug("Secondary ASN detection failed: %s", exc)
        return []


async def build_isp_profile(
    ip: str,
    asn_entries: list[ASNEntry],
    client: httpx.AsyncClient | None = None,
) -> tuple[ISPProfile, list[ASNEntry]]:
    """Build ISP profile and detect secondary ASNs.

    Args:
        ip: Target IP address.
        asn_entries: List of ASN entries from Module 1.
        client: Optional shared httpx.AsyncClient. If None, a new client is created.

    Returns:
        (isp_profile, secondary_asn_entries)
    """
    if not asn_entries:
        return ISPProfile(), []

    primary = asn_entries[0]

    _own_client = client is None
    if _own_client:
        client = httpx.AsyncClient(timeout=_TIMEOUT, follow_redirects=True)
    try:
        # Fetch metadata, peering, and secondary ASNs concurrently
        meta, peering, secondary = await asyncio.gather(
            _fetch_asn_meta(primary.asn, client),
            _fetch_peering(primary.asn, client),
            _find_secondary_asns(ip, primary.asn, client),
        )

        noc_contact = ""
        abuse_contact = ""
        isp_name = primary.organization

        if meta:
            noc_contact = meta.get("email_fixed") or meta.get("phone_fixed") or ""
            abuse_contact = meta.get("abuse_fixed") or meta.get("email_fixed") or ""
            if not isp_name:
                isp_name = meta.get("name") or meta.get("description", "")

        return ISPProfile(
            name=isp_name,
            noc_contact=noc_contact,
            abuse_contact=abuse_contact,
            peering_relationships=peering,
        ), secondary
    finally:
        if _own_client:
            await client.aclose()
