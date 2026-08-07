"""ISP profile discovery and multi-ASN detection."""

from __future__ import annotations

import logging

import httpx
from .httpx_client import get_client

from .models import ASNEntry, ISPProfile

logger = logging.getLogger(__name__)

_TIMEOUT = httpx.Timeout(8.0, connect=5.0)

_BGPVIEW_ASN_URL = "https://api.bgpview.io/asn/{asn}"
_BGPVIEW_UPSTREAM_URL = "https://api.bgpview.io/asn/{asn}/upstreams"
_BGPVIEW_DOWNSTREAM_URL = "https://api.bgpview.io/asn/{asn}/downstreams"


async def _fetch_asn_meta(asn: str, client: httpx.AsyncClient) -> dict | None:
    """Fetch ASN metadata from bgpview.io."""
    asn_num = asn.replace("AS", "")
    try:
        resp = await client.get(_BGPVIEW_ASN_URL.format(asn=asn_num))
        resp.raise_for_status()
        return resp.json().get("data", {})
    except Exception as exc:
        logger.debug("bgpview.io ASN meta failed for %s: %s", asn, exc)
        return None


async def _fetch_peering(asn: str, client: httpx.AsyncClient) -> list[str]:
    """Fetch upstream + downstream peers for an ASN."""
    asn_num = asn.replace("AS", "")
    peers: list[str] = []
    for url_template in (_BGPVIEW_UPSTREAM_URL, _BGPVIEW_DOWNSTREAM_URL):
        try:
            resp = await client.get(url_template.format(asn=asn_num))
            resp.raise_for_status()
            data = resp.json().get("data", {})
            for entry in data:
                name = entry.get("name") or entry.get("asn", "")
                asn_id = entry.get("asn", "")
                peers.append(f"AS{asn_id} - {name}" if name else f"AS{asn_id}")
        except Exception as exc:
            logger.debug("Peering query failed for %s: %s", asn, exc)
    # Deduplicate
    seen: set[str] = set()
    unique: list[str] = []
    for p in peers:
        if p not in seen:
            seen.add(p)
            unique.append(p)
    return unique


async def _find_secondary_asns(
    ip: str, primary_asn: str, client: httpx.AsyncClient
) -> list[ASNEntry]:
    """Detect additional ASNs serving the same organization.

    Uses bgpview.io search by ASN description / organization to find related ASNs.
    """
    try:
        # Get the org name from the primary ASN metadata
        meta = await _fetch_asn_meta(primary_asn, client)
        if not meta:
            return []
        description = meta.get("description", "")
        if not description:
            return []

        # Search bgpview for other ASNs matching this org description (top 50)
        search_url = "https://api.bgpview.io/search"
        resp = await client.get(search_url, params={"query_term": description, "page_size": 50})
        resp.raise_for_status()
        results = resp.json().get("data", {}).get("asns", [])
        secondary: list[ASNEntry] = []
        for r in results:
            asn_str = f"AS{r.get('asn', '')}"
            if asn_str == primary_asn:
                continue
            # Only include if description matches the org broadly
            r_desc = (r.get("description") or "").lower()
            if description.lower()[:10] in r_desc or r_desc[:10] in description.lower():
                secondary.append(ASNEntry(
                    asn=asn_str,
                    organization=r.get("name") or r.get("description", ""),
                    country=r.get("country_code", ""),
                    registry=r.get("registry", ""),
                    is_primary=False,
                ))
        return secondary[:5]  # Limit to 5 secondary ASNs
    except Exception as exc:
        logger.debug("Secondary ASN detection failed: %s", exc)
        return []


async def build_isp_profile(
    ip: str, asn_entries: list[ASNEntry]
) -> tuple[ISPProfile, list[ASNEntry]]:
    """Build ISP profile and detect secondary ASNs.

    Returns:
        (isp_profile, secondary_asn_entries)
    """
    if not asn_entries:
        return ISPProfile(), []

    primary = asn_entries[0]
    sources_queried: list[str] = []

    client = get_client()
    # Fetch ASN metadata for ISP profile
    meta = await _fetch_asn_meta(primary.asn, client)

    noc_contact = ""
    abuse_contact = ""
    isp_name = primary.organization

    if meta:
        noc_contact = meta.get("email_fixed") or meta.get("phone_fixed") or ""
        abuse_contact = meta.get("abuse_fixed") or meta.get("email_fixed") or ""
        if not isp_name:
            isp_name = meta.get("name") or meta.get("description", "")

    # Fetch peering relationships
    peering = await _fetch_peering(primary.asn, client)

    # Detect secondary ASNs
    secondary = await _find_secondary_asns(ip, primary.asn, client)

    profile = ISPProfile(
        name=isp_name,
        noc_contact=noc_contact,
        abuse_contact=abuse_contact,
        peering_relationships=peering,
    )

    return profile, secondary
