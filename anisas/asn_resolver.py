"""ASN resolution and IP prefix enumeration via RDAP and BGP APIs."""

from __future__ import annotations

import asyncio
import logging
import re
from typing import Any

import httpx
from cachetools import TTLCache

from ._safety import redact
from .models import ASNEntry

logger = logging.getLogger(__name__)

_TIMEOUT = httpx.Timeout(10.0, connect=5.0)


async def _first_successful(coro_factories):
    """Run coroutines concurrently, return first non-None result.

    Unlike asyncio.wait(FIRST_COMPLETED), this ignores failed/None results
    and keeps waiting until a successful result appears or all tasks exhaust.
    coro_factories: list of callables that return coroutines (to avoid already-started issues).
    """
    tasks = [asyncio.create_task(fn()) for fn in coro_factories]
    try:
        done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        # Check completed tasks for a non-None result
        for task in done:
            if not task.cancelled():
                result = task.result()
                if result is not None:
                    # Cancel remaining tasks
                    for t in tasks:
                        if not t.done():
                            t.cancel()
                    return result
        # No success in first batch — wait for remaining tasks
        remaining = [t for t in tasks if not t.done()]
        while remaining:
            done2, remaining = await asyncio.wait(remaining, return_when=asyncio.FIRST_COMPLETED)
            for task in done2:
                if not task.cancelled():
                    result = task.result()
                    if result is not None:
                        for t in tasks:
                            if not t.done():
                                t.cancel()
                        return result
        return None
    finally:
        for t in tasks:
            if not t.done():
                t.cancel()

# Safety caps for streaming responses
_CYMRU_MAX_LINES = 100
_CYMRU_MAX_BYTES = 100_000
_MAX_PREFIXES = 500
_MAX_PEERS = 200

# TTL caches: maxsize caps memory, ttl prevents stale data
_cache_rdap_ip: TTLCache = TTLCache(maxsize=512, ttl=3600)
_cache_rdap_asn: TTLCache = TTLCache(maxsize=512, ttl=3600)
_cache_bgpview_ip: TTLCache = TTLCache(maxsize=512, ttl=1800)
_cache_bgpview_asn: TTLCache = TTLCache(maxsize=512, ttl=1800)
_cache_bgpview_asn_meta: TTLCache = TTLCache(maxsize=512, ttl=1800)
_cache_bgpview_peering: TTLCache = TTLCache(maxsize=512, ttl=1800)
_cache_ipinfo: TTLCache = TTLCache(maxsize=512, ttl=1800)
_cache_cymru: TTLCache = TTLCache(maxsize=512, ttl=3600)
_cache_secondary: TTLCache = TTLCache(maxsize=256, ttl=3600)

# RDAP endpoints (authoritative, always accessible)
_RDAP_APNIC_IP = "https://rdap.apnic.net/ip/{ip}"
_RDAP_ARIN_IP = "https://rdap.arin.net/registry/ip/{ip}"
_RDAP_RIPE_IP = "https://rdap.ripe.net/ip/{ip}"
_RDAP_LACNIC_IP = "https://rdap.lacnic.net/rdap/ip/{ip}"
_RDAP_AFRINIC_IP = "https://rdap.afrinic.net/rdap/ip/{ip}"

# RDAP ASN endpoints for peering lookups
_RDAP_APNIC_ASN = "https://rdap.apnic.net/autnum/{asn}"
_RDAP_ARIN_ASN = "https://rdap.arin.net/registry/autnum/{asn}"

# BGP data (fallback)
_BGPVIEW_IP_URL = "https://api.bgpview.io/ip/{ip}"
_BGPVIEW_ASN_URL = "https://api.bgpview.io/asn/{asn}/prefixes"
_BGPVIEW_ASN_URL2 = "https://api.bgpview.io/asn/{asn}"
_BGPVIEW_UPSTREAM_URL = "https://api.bgpview.io/asn/{asn}/upstreams"
_BGPVIEW_DOWNSTREAM_URL = "https://api.bgpview.io/asn/{asn}/downstreams"
_IPINFO_URL = "https://ipinfo.io/{ip}/json"
_CYMRU_URL = "https://teamcymru.com/IPToASN/v1/output.txt"

# Country code to registry mapping
_REGISTRY_MAP = {
    "APNIC": ["IN", "CN", "JP", "KR", "AU", "SG", "HK", "TW", "TH", "VN",
              "PH", "MY", "ID", "BD", "PK", "LK", "NP", "MM", "KH", "LA"],
    "RIPE": ["GB", "DE", "FR", "NL", "IT", "ES", "PL", "SE", "NO", "FI",
             "DK", "AT", "CH", "BE", "IE", "PT", "CZ", "RO", "HU", "BG"],
    "ARIN": ["US", "CA"],
    "LACNIC": ["BR", "MX", "AR", "CL", "CO", "PE", "VE", "EC", "BO", "PY"],
    "AFRINIC": ["ZA", "NG", "KE", "EG", "GH", "TZ", "UG", "SN", "CI", "CM"],
}


def _detect_registry(country: str) -> str:
    """Detect the Regional Internet Registry from country code."""
    if not country:
        return "Unknown"
    for registry, codes in _REGISTRY_MAP.items():
        if country.upper() in codes:
            return registry
    return "Unknown"


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


async def _query_rdap(ip: str, client: httpx.AsyncClient) -> dict[str, Any] | None:
    """Query RDAP for IP-to-ASN mapping, racing all RIRs concurrently."""
    cached = _cache_rdap_ip.get(ip)
    if cached is not None:
        return cached

    rdap_urls = [
        (_RDAP_ARIN_IP, "ARIN"),
        (_RDAP_APNIC_IP, "APNIC"),
        (_RDAP_RIPE_IP, "RIPE"),
        (_RDAP_LACNIC_IP, "LACNIC"),
        (_RDAP_AFRINIC_IP, "AFRINIC"),
    ]

    async def _try_rir(url_template: str, rir_name: str) -> dict[str, Any] | None:
        try:
            resp = await client.get(url_template.format(ip=ip))
            if resp.status_code != 200:
                return None
            data = resp.json()

            # Extract network name from remarks or registrant entity
            network_name = ""
            for remark in data.get("remarks", []):
                if remark.get("title") in ("description", "network-name"):
                    descs = remark.get("description", [])
                    if isinstance(descs, list) and descs:
                        network_name = descs[0]
                    elif isinstance(descs, str):
                        network_name = descs
                    break

            if not network_name:
                for entity in data.get("entities", []):
                    roles = entity.get("roles", [])
                    if "registrant" in roles:
                        handle = entity.get("handle", "")
                        name = entity.get("name", "")
                        if handle and not handle.startswith("NET-"):
                            network_name = handle
                        elif name:
                            network_name = name
                        break

            if not network_name:
                for entity in data.get("entities", []):
                    roles = entity.get("roles", [])
                    if "registrant" in roles:
                        for sub in entity.get("entities", []):
                            sub_handle = sub.get("handle", "")
                            if sub_handle and not sub_handle.startswith(("ABUSE", "ZG")):
                                network_name = sub_handle
                                break
                    if network_name:
                        break

            cidrs = data.get("cidr0_cidrs", [])
            ip_range = ""
            if cidrs:
                c = cidrs[0]
                v4 = c.get("v4prefix", "")
                length = c.get("length", "")
                if v4:
                    ip_range = f"{v4}/{length}"

            start_ip = data.get("startAddress", "")
            end_ip = data.get("endAddress", "")

            country = data.get("country", "")
            if not country:
                handle = data.get("handle", "")
                country_match = re.search(r"\b([A-Z]{2})\b", handle)
                if country_match:
                    country = country_match.group(1)

            abuse_contact = ""
            for entity in data.get("entities", []):
                roles = entity.get("roles", [])
                if "abuse" in roles:
                    for vc in entity.get("vcardArray", [])[1] if len(entity.get("vcardArray", [])) > 1 else []:
                        if vc[0] == "email":
                            abuse_contact = vc[3]
                            break
                    break

            noc_contact = ""
            for entity in data.get("entities", []):
                roles = entity.get("roles", [])
                if "technical" in roles:
                    for vc in entity.get("vcardArray", [])[1] if len(entity.get("vcardArray", [])) > 1 else []:
                        if vc[0] == "email":
                            noc_contact = vc[3]
                            break
                    if noc_contact:
                        break
            if not noc_contact:
                for entity in data.get("entities", []):
                    roles = entity.get("roles", [])
                    if "administrative" in roles:
                        for vc in entity.get("vcardArray", [])[1] if len(entity.get("vcardArray", [])) > 1 else []:
                            if vc[0] in ("email", "tel"):
                                noc_contact = vc[3]
                                break
                        if noc_contact:
                            break
            if not noc_contact:
                for entity in data.get("entities", []):
                    roles = entity.get("roles", [])
                    if "technical" in roles or "administrative" in roles:
                        for vc in entity.get("vcardArray", [])[1] if len(entity.get("vcardArray", [])) > 1 else []:
                            if vc[0] == "tel":
                                noc_contact = vc[3]
                                break
                        if noc_contact:
                            break

            registry = _detect_registry(country) if country else rir_name

            return {
                "asn": "",
                "organization": network_name,
                "country": country,
                "registry": registry,
                "ip_range": ip_range,
                "start_ip": start_ip,
                "end_ip": end_ip,
                "abuse_contact": abuse_contact,
                "noc_contact": noc_contact,
                "rir": rir_name,
            }

        except Exception as exc:
            logger.debug("RDAP query failed for %s via %s: %s", ip, rir_name, exc)
            return None

    # Race all RIRs concurrently, accept first success (ignores failures)
    factories = [lambda t=tpl, n=name: _try_rir(t, n) for tpl, name in rdap_urls]
    result = await _first_successful(factories)
    if result is not None:
        _cache_rdap_ip[ip] = result
        return result
    return None


async def _query_rdap_asn(asn: str, client: httpx.AsyncClient) -> dict[str, Any] | None:
    """Query RDAP for ASN details, racing ARIN and APNIC concurrently."""
    cached = _cache_rdap_asn.get(asn)
    if cached is not None:
        return cached

    asn_num = asn.replace("AS", "")
    rdap_urls = [
        (_RDAP_ARIN_ASN, "ARIN"),
        (_RDAP_APNIC_ASN, "APNIC"),
    ]

    async def _try_rir(url_template: str, rir_name: str) -> dict[str, Any] | None:
        try:
            resp = await client.get(url_template.format(asn=asn_num))
            if resp.status_code != 200:
                return None
            data = resp.json()

            name = data.get("name", "")
            handle = data.get("handle", "")
            country = ""
            for remark in data.get("remarks", []):
                if remark.get("title") == "registration country":
                    descs = remark.get("description", [])
                    if isinstance(descs, list) and descs:
                        country = descs[0]
                    break

            return {
                "name": name,
                "handle": handle,
                "country": country,
                "rir": rir_name,
            }
        except Exception as exc:
            logger.debug("RDAP ASN query failed for %s via %s: %s", asn, rir_name, exc)
            return None

    factories = [lambda t=tpl, n=name: _try_rir(t, n) for tpl, name in rdap_urls]
    result = await _first_successful(factories)
    if result is not None:
        _cache_rdap_asn[asn] = result
        return result
    return None


async def _find_asn_from_org(org_name: str, ip_range: str, client: httpx.AsyncClient) -> str:
    """Find ASN by searching for the organization name.

    Uses bgpview search and RDAP lookups to find the ASN dynamically.
    Works for any ISP globally - no hardcoded mappings.
    """
    if not org_name:
        return ""

    org_lower = org_name.lower()
    org_words = [w for w in org_lower.split() if len(w) > 3]

    # Strategy 1: Search bgpview for ASN matching the organization name
    try:
        search_url = "https://api.bgpview.io/search"
        resp = await client.get(search_url, params={"query_term": org_name, "page_size": 20})
        resp.raise_for_status()
        results = resp.json().get("data", {}).get("asns", [])
        for r in results:
            asn_num = r.get("asn", "")
            r_desc = (r.get("description") or "").lower()
            r_name = (r.get("name") or "").lower()
            if any(w in r_desc or w in r_name for w in org_words):
                return f"AS{asn_num}"
    except Exception as exc:
        logger.debug("bgpview search failed: %s", exc)

    # Strategy 2: Try RDAP ASN lookup - race ARIN and APNIC concurrently
    if org_words:
        async def _try_rdap_search(url: str, label: str) -> str | None:
            try:
                resp = await client.get(url, params={"q": org_name})
                if resp.status_code == 200:
                    data = resp.json()
                    for entity in data.get("entities", []):
                        handle = entity.get("handle", "")
                        name = entity.get("name", "").lower()
                        if any(w in name or w in handle.lower() for w in org_words):
                            if handle.startswith("AS"):
                                return handle
            except Exception as exc:
                logger.debug("%s ASN search failed: %s", label, exc)
            return None

        search_factories = [
            lambda: _try_rdap_search("https://rdap.arin.net/registry/autnum", "ARIN"),
            lambda: _try_rdap_search("https://rdap.apnic.net/autnum", "APNIC"),
        ]
        result = await _first_successful(search_factories)
        if result:
            return result

    return ""


async def _query_ipinfo(ip: str, client: httpx.AsyncClient) -> dict[str, Any] | None:
    """Query ipinfo.io for ASN data."""
    cached = _cache_ipinfo.get(ip)
    if cached is not None:
        return cached

    try:
        resp = await client.get(_IPINFO_URL.format(ip=ip))
        resp.raise_for_status()
        data = resp.json()
        org_raw: str = data.get("org", "")
        match = re.match(r"(AS\d+)\s*(.*)", org_raw)
        if not match:
            return None
        result = {
            "asn": match.group(1),
            "organization": match.group(2).strip(),
            "country": data.get("country", ""),
            "registry": "",
            "ip_range": "",
        }
        _cache_ipinfo[ip] = result
        return result
    except Exception as exc:
        logger.debug("ipinfo.io query failed: %s", exc)
        return None


async def _query_bgpview_ip(ip: str, client: httpx.AsyncClient) -> dict[str, Any] | None:
    """Query bgpview.io for IP-to-ASN mapping."""
    cached = _cache_bgpview_ip.get(ip)
    if cached is not None:
        return cached

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
        result = {
            "asn": asn_str,
            "organization": first.get("name", ""),
            "country": first.get("country_code", ""),
            "registry": first.get("registry", ""),
            "ip_range": first.get("prefix", ""),
        }
        _cache_bgpview_ip[ip] = result
        return result
    except Exception as exc:
        logger.debug("bgpview.io IP query failed: %s", exc)
        return None


async def _query_bgpview_asn(asn: str, client: httpx.AsyncClient) -> list[str]:
    """Fetch IPv4/IPv6 prefixes announced by an ASN via bgpview.io."""
    cached = _cache_bgpview_asn.get(asn)
    if cached is not None:
        return cached

    asn_num = asn.replace("AS", "")
    try:
        resp = await client.get(_BGPVIEW_ASN_URL.format(asn=asn_num))
        resp.raise_for_status()
        data = resp.json().get("data", {})
        prefixes = data.get("ipv4_prefixes", []) + data.get("ipv6_prefixes", [])
        result = [p.get("prefix", "") for p in prefixes if p.get("prefix")]
        _cache_bgpview_asn[asn] = result
        return result
    except Exception as exc:
        logger.debug("bgpview.io ASN prefix query failed: %s", exc)
        return []


async def _query_bgpview_asn_meta(asn: str, client: httpx.AsyncClient) -> dict[str, Any] | None:
    """Fetch ASN metadata from bgpview.io."""
    cached = _cache_bgpview_asn_meta.get(asn)
    if cached is not None:
        return cached

    asn_num = asn.replace("AS", "")
    try:
        resp = await client.get(_BGPVIEW_ASN_URL2.format(asn=asn_num))
        resp.raise_for_status()
        result = resp.json().get("data", {})
        _cache_bgpview_asn_meta[asn] = result
        return result
    except Exception as exc:
        logger.debug("bgpview.io ASN meta failed for %s: %s", asn, exc)
        return None


async def _query_bgpview_peering(asn: str, client: httpx.AsyncClient) -> list[str]:
    """Fetch upstream + downstream peers concurrently."""
    cached = _cache_bgpview_peering.get(asn)
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
    _cache_bgpview_peering[asn] = unique
    return unique


async def _query_cymru(ip: str, client: httpx.AsyncClient) -> dict[str, Any] | None:
    """Query Team Cymru IP-to-ASN mapping using streaming line-by-line.

    Reads at most _CYMRU_MAX_LINES lines / _CYMRU_MAX_BYTES to prevent memory DoS.
    """
    cached = _cache_cymru.get(ip)
    if cached is not None:
        return cached

    try:
        bytes_read = 0
        lines_read = 0
        async with client.stream("GET", _CYMRU_URL, params={"ip": ip}) as resp:
            resp.raise_for_status()
            async for line in resp.aiter_lines():
                lines_read += 1
                bytes_read += len(line.encode("utf-8", errors="replace"))
                if lines_read > _CYMRU_MAX_LINES or bytes_read > _CYMRU_MAX_BYTES:
                    logger.debug("Team Cymru response truncated at %d lines / %d bytes", lines_read, bytes_read)
                    break
                if line.startswith("#") or not line.strip():
                    continue
                parsed = _parse_cymru_line(line)
                if parsed:
                    result = {
                        "asn": parsed["asn"],
                        "organization": "",
                        "country": "",
                        "registry": "",
                        "ip_range": parsed["ip_range"],
                    }
                    _cache_cymru[ip] = result
                    return result
    except Exception as exc:
        logger.debug("Team Cymru query failed: %s", exc)
    return None


async def _find_secondary_asns(
    ip: str, primary_asn: str, org_name: str, client: httpx.AsyncClient
) -> list[ASNEntry]:
    """Detect additional ASNs serving the same organization."""
    cache_key = f"{primary_asn}:{org_name}"
    cached = _cache_secondary.get(cache_key)
    if cached is not None:
        return cached

    try:
        search_url = "https://api.bgpview.io/search"
        resp = await client.get(search_url, params={"query_term": org_name, "page_size": 50})
        resp.raise_for_status()
        results = resp.json().get("data", {}).get("asns", [])
        secondary: list[ASNEntry] = []
        for r in results:
            asn_str = f"AS{r.get('asn', '')}"
            if asn_str == primary_asn:
                continue
            r_desc = (r.get("description") or "").lower()
            if org_name.lower()[:10] in r_desc or r_desc[:10] in org_name.lower():
                secondary.append(ASNEntry(
                    asn=asn_str,
                    organization=r.get("name") or r.get("description", ""),
                    country=r.get("country_code", ""),
                    registry=r.get("registry", ""),
                    is_primary=False,
                ))
        result = secondary[:5]
        _cache_secondary[cache_key] = result
        return result
    except Exception as exc:
        logger.debug("Secondary ASN detection failed: %s", exc)
        return []


async def resolve_asn(
    ip: str, client: httpx.AsyncClient | None = None
) -> tuple[list[ASNEntry], list[str], list[str], dict[str, Any]]:
    """Resolve ASN details and IP prefixes for a target IP.

    Args:
        ip: Target IP address.
        client: Optional shared httpx.AsyncClient. If None, a new client is created.

    Returns:
        (asn_entries, ip_prefixes, sources_queried, extra_data)
    """
    sources_queried: list[str] = []
    extra_data: dict[str, Any] = {}

    _own_client = client is None
    if _own_client:
        client = httpx.AsyncClient(timeout=_TIMEOUT, follow_redirects=True)
    try:
        # --- Primary: RDAP (authoritative for org, country, contacts) ---
        info = await _query_rdap(ip, client)
        if info:
            sources_queried.append("rdap")
            extra_data = info

            # ASN is not in RDAP IP objects — race bgpview + ipinfo concurrently
            if not info.get("asn"):
                async def _get_asn_from_bgp():
                    r = await _query_bgpview_ip(ip, client)
                    return ("bgpview.io", r) if r and r.get("asn") else None
                async def _get_asn_from_ipinfo():
                    r = await _query_ipinfo(ip, client)
                    return ("ipinfo.io", r) if r and r.get("asn") else None
                asn_factories = [_get_asn_from_bgp, _get_asn_from_ipinfo]
                asn_result = await _first_successful(asn_factories)
                if asn_result:
                    source_name, asn_data = asn_result
                    info["asn"] = asn_data["asn"]
                    sources_queried.append(source_name)
                if not info.get("asn") and info.get("organization"):
                    asn = await _find_asn_from_org(info["organization"], info.get("ip_range", ""), client)
                    if asn:
                        info["asn"] = asn
                        sources_queried.append("org_search")
        else:
            # Fallback: race ipinfo, bgpview, cymru concurrently
            async def _fb_ipinfo():
                r = await _query_ipinfo(ip, client)
                return ("ipinfo.io", r) if r else None
            async def _fb_bgp():
                r = await _query_bgpview_ip(ip, client)
                return ("bgpview.io", r) if r else None
            async def _fb_cymru():
                r = await _query_cymru(ip, client)
                return ("team-cymru", r) if r else None
            fb_factories = [_fb_ipinfo, _fb_bgp, _fb_cymru]
            fb_result = await _first_successful(fb_factories)
            if fb_result:
                source_name, fb_data = fb_result
                info = fb_data
                sources_queried.append(source_name)

        if not info:
            logger.warning("All ASN resolution providers failed for %s", ip)
            return [], [], sources_queried, {}

        # Build primary ASN entry
        primary_asn = ASNEntry(
            asn=info.get("asn", ""),
            organization=info.get("organization", ""),
            country=info.get("country", ""),
            registry=info.get("registry", "") or _detect_registry(info.get("country", "")),
            is_primary=True,
        )
        asn_entries = [primary_asn]

        # --- IP Prefix Enumeration + Peering + Multi-ASN: all run concurrently ---
        prefixes: list[str] = []
        if info.get("ip_range"):
            prefixes.append(info["ip_range"])

        async def _fetch_prefixes() -> list[str]:
            if primary_asn.asn:
                return await _query_bgpview_asn(primary_asn.asn, client)
            return []

        async def _fetch_peering_data() -> list[str]:
            if primary_asn.asn:
                return await _query_bgpview_peering(primary_asn.asn, client)
            return []

        async def _fetch_secondary() -> list[ASNEntry]:
            if primary_asn.organization:
                return await _find_secondary_asns(ip, primary_asn.asn, primary_asn.organization, client)
            return []

        prefix_result, peering_result, secondary_result = await asyncio.gather(
            _fetch_prefixes(),
            _fetch_peering_data(),
            _fetch_secondary(),
        )

        if prefix_result:
            sources_queried.append("bgpview.io/asn_prefixes")
            prefixes.extend(prefix_result)

        # Deduplicate prefixes
        seen: set[str] = set()
        unique: list[str] = []
        for p in prefixes:
            if p and p not in seen:
                seen.add(p)
                unique.append(p)
        if len(unique) > _MAX_PREFIXES:
            unique = unique[:_MAX_PREFIXES]

        peering = peering_result[:_MAX_PEERS] if peering_result else []
        if peering:
            sources_queried.append("bgpview.io/peering")

        if secondary_result:
            sources_queried.append("bgpview.io/secondary_asns")
            asn_entries.extend(secondary_result)

        return asn_entries, unique, sources_queried, extra_data
    finally:
        if _own_client:
            await client.aclose()
