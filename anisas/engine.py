"""Main ANISAS pipeline engine — orchestrates all submodules."""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import time

from .models import ASNIntelligenceReport, Provenance
from .asn_resolver import resolve_asn
from .isp_profile import build_isp_profile
from .risk_analyzer import analyze_risk
from .report_generator import generate_json, generate_pdf

logger = logging.getLogger(__name__)


def _validate_ip(ip_str: str) -> str:
    """Validate and normalise an IPv4/IPv6 address."""
    try:
        addr = ipaddress.ip_address(ip_str.strip())
        if addr.is_private:
            raise ValueError(f"Private IP addresses are not supported: {ip_str}")
        if addr.is_loopback:
            raise ValueError(f"Loopback addresses are not supported: {ip_str}")
        return str(addr)
    except ValueError:
        raise ValueError(f"Invalid IP address: {ip_str}")


async def run_engine(
    target_ip: str,
    *,
    pdf_output: str | None = None,
    json_output: str | None = None,
) -> ASNIntelligenceReport:
    """Execute the full Module 1 pipeline.

    Args:
        target_ip: A single public IPv4 or IPv6 address.
        pdf_output: Optional path to write the PDF report.
        json_output: Optional path to write the JSON report.

    Returns:
        Populated ASNIntelligenceReport.
    """
    start = time.monotonic()
    validated_ip = _validate_ip(target_ip)
    all_sources: list[str] = []

    # Step 1: ASN Resolution + Prefix Enumeration
    logger.info("[1/4] Resolving ASN for %s ...", validated_ip)
    asn_entries, ip_prefixes, src1 = await resolve_asn(validated_ip)
    all_sources.extend(src1)

    # Step 2: ISP Profile + Multi-ASN Detection
    logger.info("[2/4] Building ISP profile ...")
    isp_profile, secondary_asns = await build_isp_profile(validated_ip, asn_entries)
    all_sources.append("bgpview.io/isp_profile")
    asn_entries.extend(secondary_asns)

    # Step 3: AI/NLP Risk Analysis
    logger.info("[3/4] Running AI risk analysis ...")
    primary_asn = asn_entries[0] if asn_entries else None
    risk_summary = await analyze_risk(
        isp_name=isp_profile.name,
        organization=primary_asn.organization if primary_asn else "",
        country=primary_asn.country if primary_asn else "",
        asn=primary_asn.asn if primary_asn else "unknown",
        peering_count=len(isp_profile.peering_relationships),
    )

    elapsed = time.monotonic() - start

    report = ASNIntelligenceReport(
        target_ip=validated_ip,
        asn_details=asn_entries,
        ip_prefixes=ip_prefixes,
        isp_profile=isp_profile,
        ai_risk_summary=risk_summary,
        provenance=Provenance(
            sources_queried=list(set(all_sources)),
            execution_time_seconds=round(elapsed, 3),
        ),
    )

    # Step 4: Output Generation (offloaded to thread pool to avoid blocking event loop)
    logger.info("[4/4] Generating reports ...")
    if json_output:
        await asyncio.to_thread(generate_json, report, json_output)
    if pdf_output:
        await asyncio.to_thread(generate_pdf, report, pdf_output)

    total_elapsed = time.monotonic() - start
    logger.info("Pipeline completed in %.2f seconds.", total_elapsed)
    return report
