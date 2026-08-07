"""JSON and PDF report generation for ANISAS intelligence reports."""

from __future__ import annotations

import json
import logging
import os
import time
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from .models import ASNIntelligenceReport

logger = logging.getLogger(__name__)


def generate_json(report: ASNIntelligenceReport, output_path: str | None = None) -> str:
    """Generate a machine-readable JSON file from the report.

    Returns the JSON string.
    """
    start = time.monotonic()
    json_str = report.model_dump_json(indent=2)
    if output_path:
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(json_str)
        elapsed = time.monotonic() - start
        logger.info("JSON report written to %s (%.3f seconds)", output_path, elapsed)
    return json_str


def _build_pdf_styles() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    styles = {
        "Title": ParagraphStyle(
            "ReportTitle",
            parent=base["Title"],
            fontSize=18,
            spaceAfter=12,
            textColor=colors.HexColor("#1a1a2e"),
        ),
        "Heading": ParagraphStyle(
            "SectionHeading",
            parent=base["Heading2"],
            fontSize=13,
            spaceAfter=6,
            spaceBefore=14,
            textColor=colors.HexColor("#16213e"),
        ),
        "Body": ParagraphStyle(
            "BodyText",
            parent=base["BodyText"],
            fontSize=10,
            leading=14,
            spaceAfter=4,
        ),
        "Small": ParagraphStyle(
            "SmallText",
            parent=base["BodyText"],
            fontSize=8,
            leading=10,
            textColor=colors.grey,
        ),
        "RiskHigh": ParagraphStyle(
            "RiskHigh",
            parent=base["BodyText"],
            fontSize=12,
            textColor=colors.HexColor("#c0392b"),
            spaceBefore=4,
            spaceAfter=4,
        ),
        "RiskMedium": ParagraphStyle(
            "RiskMedium",
            parent=base["BodyText"],
            fontSize=12,
            textColor=colors.HexColor("#e67e22"),
            spaceBefore=4,
            spaceAfter=4,
        ),
        "RiskLow": ParagraphStyle(
            "RiskLow",
            parent=base["BodyText"],
            fontSize=12,
            textColor=colors.HexColor("#27ae60"),
            spaceBefore=4,
            spaceAfter=4,
        ),
    }
    return styles


def _risk_style(level: str, styles: dict[str, ParagraphStyle]) -> ParagraphStyle:
    mapping = {"High": "RiskHigh", "Medium": "RiskMedium", "Low": "RiskLow"}
    return styles.get(mapping.get(level, "RiskLow"), styles["Body"])


def generate_pdf(report: ASNIntelligenceReport, output_path: str) -> None:
    """Generate a professional PDF intelligence report."""
    start = time.monotonic()
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        leftMargin=0.75 * inch,
        rightMargin=0.75 * inch,
        topMargin=0.75 * inch,
        bottomMargin=0.75 * inch,
    )

    styles = _build_pdf_styles()
    story: list = []

    # --- Title ---
    story.append(Paragraph("ANISAS Intelligence Report", styles["Title"]))
    story.append(Spacer(1, 6))

    # --- Target Info ---
    story.append(Paragraph(
        f"<b>Target IP:</b> {report.target_ip} &nbsp;&nbsp;|&nbsp;&nbsp; "
        f"<b>Timestamp:</b> {report.timestamp}",
        styles["Body"],
    ))
    story.append(Spacer(1, 10))

    # --- ASN Details ---
    story.append(Paragraph("1. ASN Details", styles["Heading"]))
    if report.asn_details:
        asn_data = [["ASN", "Organization", "Country", "Registry", "Primary"]]
        for a in report.asn_details:
            asn_data.append([a.asn, a.organization, a.country, a.registry, str(a.is_primary)])
        table = Table(asn_data, repeatRows=1)
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a1a2e")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.whitesmoke, colors.white]),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(table)
    else:
        story.append(Paragraph("No ASN data available.", styles["Body"]))
    story.append(Spacer(1, 8))

    # --- IP Prefixes ---
    story.append(Paragraph("2. IP Prefixes", styles["Heading"]))
    if report.ip_prefixes:
        prefix_text = ", ".join(report.ip_prefixes[:30])
        if len(report.ip_prefixes) > 30:
            prefix_text += f" ... (+{len(report.ip_prefixes) - 30} more)"
        story.append(Paragraph(f"<font size='9'>{prefix_text}</font>", styles["Body"]))
    else:
        story.append(Paragraph("No prefix data available.", styles["Body"]))
    story.append(Spacer(1, 8))

    # --- ISP Profile ---
    story.append(Paragraph("3. ISP Profile", styles["Heading"]))
    isp = report.isp_profile
    isp_data = [
        ["Field", "Value"],
        ["Name", isp.name],
        ["NOC Contact", isp.noc_contact or "N/A"],
        ["Abuse Contact", isp.abuse_contact or "N/A"],
    ]
    if isp.peering_relationships:
        peers = isp.peering_relationships[:10]
        peer_str = ", ".join(peers)
        if len(isp.peering_relationships) > 10:
            peer_str += f" ... (+{len(isp.peering_relationships) - 10} more)"
        isp_data.append(["Peering Partners", peer_str])
    table2 = Table(isp_data, repeatRows=1)
    table2.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#16213e")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.whitesmoke, colors.white]),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(table2)
    story.append(Spacer(1, 8))

    # --- AI Risk Summary ---
    story.append(Paragraph("4. AI Risk Assessment", styles["Heading"]))
    risk = report.ai_risk_summary
    story.append(Paragraph(
        f"<b>Risk Level:</b> {risk.risk_level}",
        _risk_style(risk.risk_level, styles),
    ))
    summary_lines = risk.summary_text.split("\n")
    for line in summary_lines:
        if line.strip():
            story.append(Paragraph(line.strip(), styles["Body"]))
    story.append(Spacer(1, 8))

    # --- Provenance ---
    story.append(Paragraph("5. Data Provenance", styles["Heading"]))
    prov = report.provenance
    sources = ", ".join(prov.sources_queried) if prov.sources_queried else "None"
    story.append(Paragraph(f"<b>Sources Queried:</b> {sources}", styles["Body"]))
    story.append(Paragraph(
        f"<b>Execution Time:</b> {prov.execution_time_seconds:.2f} seconds",
        styles["Body"],
    ))
    story.append(Spacer(1, 12))

    # --- Footer ---
    story.append(Paragraph(
        f"Generated by ANISAS v1.0.0 — {datetime.utcnow().isoformat()}Z",
        styles["Small"],
    ))

    doc.build(story)
    elapsed = time.monotonic() - start
    logger.info("PDF report written to %s (%.3f seconds)", output_path, elapsed)
