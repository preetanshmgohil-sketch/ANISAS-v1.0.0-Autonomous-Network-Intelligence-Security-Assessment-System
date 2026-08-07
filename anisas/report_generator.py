"""JSON and PDF report generation for ANISAS intelligence reports."""

from __future__ import annotations

import json
import logging
import os
import re
from datetime import datetime
from xml.sax.saxutils import escape as _xml_escape

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

_MAX_TABLE_ROWS = 100
_MAX_PREFIX_DISPLAY = 30
_MAX_PEER_DISPLAY = 10
_MAX_ORG_DISPLAY = 50


def _safe_text(text: str, max_len: int = 500) -> str:
    """Escape XML/ReportLab markup and strip control characters."""
    if not text:
        return ""
    # Strip control characters (keep newline/tab)
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", text)
    # Collapse whitespace
    text = re.sub(r"[ \t]+", " ", text).strip()
    # Escape for ReportLab Paragraph (< > & " are dangerous)
    text = _xml_escape(text)
    if len(text) > max_len:
        text = text[:max_len] + "..."
    return text


def _sanitize_cell(text: str) -> str:
    """Sanitize a single table cell value."""
    return _safe_text(str(text), max_len=200)


def generate_json(report: ASNIntelligenceReport, output_path: str | None = None) -> str:
    """Generate a machine-readable JSON file from the report.

    Returns the JSON string.
    """
    json_str = report.model_dump_json(indent=2)
    if output_path:
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(json_str)
        logger.info("JSON report written to %s", output_path)
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
        f"<b>Target IP:</b> {_safe_text(report.target_ip)} &nbsp;&nbsp;|&nbsp;&nbsp; "
        f"<b>Timestamp:</b> {_safe_text(report.timestamp)}",
        styles["Body"],
    ))
    story.append(Spacer(1, 10))

    # --- ASN Details ---
    story.append(Paragraph("1. ASN Details", styles["Heading"]))
    if report.asn_details:
        asn_data = [["ASN", "Organization", "Country", "Registry", "Primary"]]
        for a in report.asn_details[:_MAX_TABLE_ROWS]:
            asn_data.append([
                _sanitize_cell(a.asn),
                _sanitize_cell(a.organization),
                _sanitize_cell(a.country),
                _sanitize_cell(a.registry),
                _sanitize_cell(str(a.is_primary)),
            ])
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
        display_prefixes = report.ip_prefixes[:_MAX_PREFIX_DISPLAY]
        prefix_text = ", ".join(_safe_text(p) for p in display_prefixes)
        if len(report.ip_prefixes) > _MAX_PREFIX_DISPLAY:
            prefix_text += f" ... (+{len(report.ip_prefixes) - _MAX_PREFIX_DISPLAY} more)"
        story.append(Paragraph(f"<font size='9'>{prefix_text}</font>", styles["Body"]))
    else:
        story.append(Paragraph("No prefix data available.", styles["Body"]))
    story.append(Spacer(1, 8))

    # --- ISP Profile ---
    story.append(Paragraph("3. ISP Profile", styles["Heading"]))
    isp = report.isp_profile
    isp_data = [
        ["Field", "Value"],
        ["Name", _sanitize_cell(isp.name)],
        ["NOC Contact", _sanitize_cell(isp.noc_contact or "N/A")],
        ["Abuse Contact", _sanitize_cell(isp.abuse_contact or "N/A")],
    ]
    if isp.peering_relationships:
        peers = isp.peering_relationships[:_MAX_PEER_DISPLAY]
        peer_str = ", ".join(_safe_text(p) for p in peers)
        if len(isp.peering_relationships) > _MAX_PEER_DISPLAY:
            peer_str += f" ... (+{len(isp.peering_relationships) - _MAX_PEER_DISPLAY} more)"
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
        f"<b>Risk Level:</b> {_safe_text(risk.risk_level)}",
        _risk_style(risk.risk_level, styles),
    ))
    summary_lines = risk.summary_text.split("\n")
    for line in summary_lines:
        line = line.strip()
        if line:
            story.append(Paragraph(_safe_text(line), styles["Body"]))
    story.append(Spacer(1, 8))

    # --- OS Distribution Summary ---
    story.append(Paragraph("5. OS Distribution Summary", styles["Heading"]))
    if report.asn_details:
        os_dist: dict[str, int] = {}
        for a in report.asn_details:
            org = a.organization or "Unknown"
            os_dist[org] = os_dist.get(org, 0) + 1
        if os_dist:
            os_data = [["Organization", "Count"]]
            sorted_orgs = sorted(os_dist.items(), key=lambda x: -x[1])[:_MAX_ORG_DISPLAY]
            for org, count in sorted_orgs:
                os_data.append([_sanitize_cell(org), str(count)])
            os_table = Table(os_data, repeatRows=1)
            os_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a1a2e")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.whitesmoke, colors.white]),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]))
            story.append(os_table)
        else:
            story.append(Paragraph("No organization data available for OS distribution.", styles["Body"]))
    else:
        story.append(Paragraph("No ASN data available for OS distribution.", styles["Body"]))
    story.append(Spacer(1, 8))

    # --- Provenance ---
    story.append(Paragraph("6. Data Provenance", styles["Heading"]))
    prov = report.provenance
    sources = ", ".join(_safe_text(s) for s in prov.sources_queried) if prov.sources_queried else "None"
    story.append(Paragraph(f"<b>Sources Queried:</b> {sources}", styles["Body"]))
    story.append(Paragraph(
        f"<b>Execution Time:</b> {prov.execution_time_seconds:.2f} seconds",
        styles["Body"],
    ))
    story.append(Spacer(1, 12))

    # --- Footer ---
    story.append(Paragraph(
        f"Generated by ANISAS v1.0.0 — {_safe_text(datetime.utcnow().isoformat())}Z",
        styles["Small"],
    ))

    doc.build(story)
    logger.info("PDF report written to %s", output_path)
