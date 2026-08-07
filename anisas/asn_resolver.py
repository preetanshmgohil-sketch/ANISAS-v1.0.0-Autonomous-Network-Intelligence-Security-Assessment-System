"""ASN resolution and IP prefix enumeration via public BGP/registry APIs."""

from __future__ import annotations

import logging
import re
from typing import Any

import httpx
from .httpx_client import get_client

from .models import ASNEntry

logger = logging.getLogger(__name__)

# API endpoints (fallback order: ipinfo → bgpview → team-cymru)
_IPINFO_URL = "https://ipinfo.io/{ip}/json"
_BGPVIEW_IP_URL = "https://api.bgpview.io/ip/{ip}"
_BGPVIEW_ASN_URL = "https://api.bgpview.io/asn/{asn}/prefixes"
_CYMRU_URL = "https://teamcymru.com/IPToASN/v1/output.txt"

_TIMEOUT = httpx.Timeout(8.0, connect=5.0)


def _parse_cymru_line(line: str) -> dict[str, Any] | None:
    """Parse a single Team Cymru output line."""
    parts = line.strip().split("|")
    if len(parts) < 6:
        return None
    ip_range = parts[1].strip()
    asn_raw = parts[5].strip()
    if not asn_raw or asn_raw.startswith("_"):
        return None
    asn_str = f"AS{asn_raw}" if not asn_raw.startswith("AS") else asn_raw
    return {"asn": asn_str, "ip_range": ip_range}


async def _query_ipinfo(ip: str, client: httpx.AsyncClient) -> dict[str, Any] | None:
    """Query ipinfo.io for ASN data."""
    try:
        resp = await client.get(_IPINFO_URL.format(ip=ip))
        resp.raise_for_status()
        data = resp.json()
        # ipinfo returns 'org' like 'AS15169 Google LLC'
        org_raw: str = data.get("org", "")
        match = re.match(r"(AS\d+)\s*(.*)", org_raw)
        if not match:
            return None
        return {
            "asn": match.group(1),
            "organization": match.group(2).strip(),
            "country": data.get("country", ""),
            "registry": "",
            "ip_range": "",
        }
    except Exception as exc:
        logger.debug("ipinfo.io query failed: %s", exc)
        return None


async def _query_bgpview_ip(ip: str, client: httpx.AsyncClient) -> dict[str, Any] | None:
    """Query bgpview.io for IP-to-ASN mapping."""
    try:
        resp = await client.get(_BGPVIEW_IP_URL.format(ip=ip))
        resp.raise_for_status()
        data = resp.json().get("data", {})
        origin_asns = data.get("prefixes", [])
        if not origin_asns:
            return None
        first = origin_asns[0]
        asn_raw = first.get("asn", "")
        asn_str = f"AS{asn_raw}" if not str(asn_raw).startswith("AS") else str(asn_raw)
        return {
            "asn": asn_str,
            "organization": first.get("name", ""),
            "country": first.get("country_code", ""),
            "registry": first.get("registry", ""),
            "ip_range": first.get("prefix", ""),
        }
    except Exception as exc:
        logger.debug("bgpview.io IP query failed: %s", exc)
        return None


async def _query_bgpview_asn(asn: str, client: httpx.AsyncClient) -> list[str]:
    """Fetch IPv4/IPv6 prefixes announced by an ASN via bgpview.io."""
    asn_num = asn.replace("AS", "")
    try:
        resp = await client.get(_BGPVIEW_ASN_URL.format(asn=asn_num))
        resp.raise_for_status()
        data = resp.json().get("data", {})
        prefixes = data.get("ipv4_prefixes", []) + data.get("ipv6_prefixes", [])
        return [p.get("prefix", "") for p in prefixes if p.get("prefix")]
    except Exception as exc:
        logger.debug("bgpview.io ASN prefix query failed: %s", exc)
        return []


async def _query_cymru(ip: str, client: httpx.AsyncClient) -> dict[str, Any] | None:
    """Query Team Cymru IP-to-ASN mapping as a last-resort fallback."""
    try:
        resp = await client.get(
            _CYMRU_URL,
            params={"ip": ip},
        )
        resp.raise_for_status()
        lines = resp.text.strip().splitlines()
        for line in lines:
            if line.startswith("#") or not line.strip():
                continue
            parsed = _parse_cymru_line(line)
            if parsed:
                return {
                    "asn": parsed["asn"],
                    "organization": "",
                    "country": "",
                    "registry": "",
                    "ip_range": parsed["ip_range"],
                }
    except Exception as exc:
        logger.debug("Team Cymru query failed: %s", exc)
    return None


async def resolve_asn(ip: str) -> tuple[list[ASNEntry], list[str], list[str]]:
    """Resolve ASN details and IP prefixes for a target IP.

    Returns:
        (asn_entries, ip_prefixes, sources_queried)
    """
    sources_queried: list[str] = []
    client = get_client()
    # --- ASN Resolution (try providers in order) ---
    info: dict[str, Any] | None = None

    info = await _query_ipinfo(ip, client)
    if info:
        sources_queried.append("ipinfo.io")
    else:
        info = await _query_bgpview_ip(ip, client)
        if info:
            sources_queried.append("bgpview.io")
        else:
            info = await _query_cymru(ip, client)
            if info:
                sources_queried.append("team-cymru")

    if not info:
        logger.warning("All ASN resolution providers failed for %s", ip)
        return [], [], sources_queried

    primary_asn = ASNEntry(
        asn=info["asn"],
        organization=info.get("organization", ""),
        country=info.get("country", ""),
        registry=info.get("registry", ""),
        is_primary=True,
    )
    asn_entries = [primary_asn]

    # --- IP Prefix Enumeration ---
    prefixes: list[str] = []
    if info.get("ip_range"):
        prefixes.append(info["ip_range"])

    bgpview_prefixes = await _query_bgpview_asn(primary_asn.asn, client)
    if bgpview_prefixes:
        sources_queried.append("bgpview.io/asn_prefixes")
        prefixes.extend(bgpview_prefixes)

    # Deduplicate while preserving order
    seen: set[str] = set()
    unique: list[str] = []
    for p in prefixes:
        if p and p not in seen:
            seen.add(p)
            unique.append(p)

    return asn_entries, unique, sources_queried
