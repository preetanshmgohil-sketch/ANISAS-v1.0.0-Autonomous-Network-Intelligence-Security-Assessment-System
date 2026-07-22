"""PDF export engine for intelligence reports."""

from __future__ import annotations

import os
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

# ── Colour palette ──────────────────────────────────────────────────────
C_BG_DARK   = colors.HexColor("#1a1a2e")
C_BG_LIGHT  = colors.HexColor("#f0f4f8")
C_ACCENT    = colors.HexColor("#3b82f6")
C_RED       = colors.HexColor("#ef4444")
C_ORANGE    = colors.HexColor("#f97316")
C_YELLOW    = colors.HexColor("#eab308")
C_GREEN     = colors.HexColor("#22c55e")
C_PURPLE    = colors.HexColor("#a855f7")
C_GREY      = colors.HexColor("#64748b")
C_DARK_TEXT = colors.HexColor("#0f172a")
C_WHITE     = colors.white

_RISK_COLOUR = {"CRITICAL": C_RED, "HIGH": C_ORANGE, "MEDIUM": C_YELLOW, "LOW": C_GREEN}


def _styles():
    ss = getSampleStyleSheet()
    s = {}

    s["cover_title"] = ParagraphStyle("cover_title", parent=ss["Title"],
        fontSize=26, leading=30, textColor=C_ACCENT, spaceAfter=4,
        alignment=TA_CENTER, fontName="Helvetica-Bold")
    s["cover_sub"] = ParagraphStyle("cover_sub", parent=ss["Normal"],
        fontSize=11, leading=14, textColor=C_GREY, alignment=TA_CENTER,
        spaceAfter=2)
    s["cover_meta"] = ParagraphStyle("cover_meta", parent=ss["Normal"],
        fontSize=9, leading=12, textColor=C_GREY, alignment=TA_CENTER)

    s["section"] = ParagraphStyle("section", parent=ss["Heading1"],
        fontSize=15, leading=18, textColor=C_ACCENT, spaceBefore=18,
        spaceAfter=8, fontName="Helvetica-Bold",
        borderWidth=0, borderPadding=0)
    s["subsection"] = ParagraphStyle("subsection", parent=ss["Heading2"],
        fontSize=11, leading=14, textColor=C_DARK_TEXT, spaceBefore=10,
        spaceAfter=4, fontName="Helvetica-Bold")
    s["body"] = ParagraphStyle("body", parent=ss["BodyText"],
        fontSize=9, leading=12, textColor=C_DARK_TEXT)
    s["body_bold"] = ParagraphStyle("body_bold", parent=s["body"],
        fontName="Helvetica-Bold")
    s["small"] = ParagraphStyle("small", parent=ss["BodyText"],
        fontSize=7, leading=9, textColor=C_GREY)
    s["cell"] = ParagraphStyle("cell", parent=ss["BodyText"],
        fontSize=8, leading=10, textColor=C_DARK_TEXT)
    s["cell_bold"] = ParagraphStyle("cell_bold", parent=s["cell"],
        fontName="Helvetica-Bold")
    s["cell_header"] = ParagraphStyle("cell_header", parent=s["cell"],
        fontName="Helvetica-Bold", textColor=C_WHITE)
    s["bullet"] = ParagraphStyle("bullet", parent=s["body"], leftIndent=14,
        bulletIndent=4, spaceBefore=1)
    s["footer"] = ParagraphStyle("footer", parent=ss["Normal"],
        fontSize=7, textColor=C_GREY, alignment=TA_CENTER)
    return s


def _header_table_style(row_count: int) -> TableStyle:
    return TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0), C_BG_DARK),
        ("TEXTCOLOR",     (0, 0), (-1, 0), C_WHITE),
        ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1, 0), 8),
        ("FONTSIZE",      (0, 1), (-1, -1), 8),
        ("GRID",          (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5e1")),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [C_WHITE, C_BG_LIGHT]),
        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING",    (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING",   (0, 0), (-1, -1), 6),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 6),
    ])


def _make_table(headers: list[str], rows: list[list], col_widths=None) -> Table:
    data = [[Paragraph(h, _s["cell_header"]) for h in headers]]
    for row in rows:
        data.append([Paragraph(str(c), _s["cell"]) for c in row])
    t = Table(data, colWidths=col_widths, repeatRows=1)
    t.setStyle(_header_table_style(len(data)))
    return t


def _kv_table(pairs: list[tuple[str, str]], col_widths=None) -> Table:
    data = [[Paragraph(str(k), _s["cell_bold"]), Paragraph(str(v), _s["cell"])] for k, v in pairs if v]
    if not data:
        return Spacer(0, 0)
    t = Table(data, colWidths=col_widths or [2.2 * inch, 4.5 * inch])
    t.setStyle(TableStyle([
        ("GRID",          (0, 0), (-1, -1), 0.3, colors.HexColor("#e2e8f0")),
        ("ROWBACKGROUNDS",(0, 0), (-1, -1), [C_WHITE, C_BG_LIGHT]),
        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING",    (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("LEFTPADDING",   (0, 0), (-1, -1), 6),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 6),
    ]))
    return t


def _risk_badge(level: str) -> str:
    c = _RISK_COLOUR.get(level.upper(), C_GREY)
    hex_c = c.hexval() if hasattr(c, 'hexval') else str(c)
    return f'<font color="{hex_c}"><b>[{level.upper()}]</b></font>'


def _section(title: str) -> Paragraph:
    return Paragraph(title, _s["section"])


def _subsection(title: str) -> Paragraph:
    return Paragraph(title, _s["subsection"])


def _body(text: str) -> Paragraph:
    return Paragraph(text, _s["body"])


def _bullet(text: str) -> Paragraph:
    return Paragraph(f"•  {text}", _s["bullet"])


# ── Module renderers ────────────────────────────────────────────────────

def _render_cover(story, target_ip: str):
    story.append(Spacer(1, 1.5 * inch))
    story.append(Paragraph("ANISAS", _s["cover_title"]))
    story.append(Paragraph("Autonomous Network Intelligence<br/>&amp; Security Assessment System", _s["cover_sub"]))
    story.append(Spacer(1, 24))
    story.append(Paragraph("━" * 60, _s["cover_meta"]))
    story.append(Spacer(1, 12))
    story.append(Paragraph(f"<b>Intelligence Report — {target_ip}</b>", _s["cover_sub"]))
    story.append(Spacer(1, 6))
    story.append(Paragraph(f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC", _s["cover_meta"]))
    story.append(Paragraph("Classification: CONFIDENTIAL", _s["cover_meta"]))
    story.append(Spacer(1, 12))
    story.append(Paragraph("━" * 60, _s["cover_meta"]))
    story.append(Spacer(1, 30))

    toc = [
        ["Section", "Description"],
        ["1", "ASN & ISP Intelligence"],
        ["2", "Network Reconnaissance"],
        ["3", "Security Perimeter Detection"],
        ["4", "Surveillance & IoT Fingerprinting"],
        ["5", "Wireless Network Intelligence"],
        ["6", "AI/ML Analytics & Risk Scoring"],
    ]
    t = Table(toc, colWidths=[0.8 * inch, 5 * inch])
    t.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0), C_BG_DARK),
        ("TEXTCOLOR",     (0, 0), (-1, 0), C_WHITE),
        ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1, -1), 9),
        ("GRID",          (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5e1")),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [C_WHITE, C_BG_LIGHT]),
        ("TOPPADDING",    (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING",   (0, 0), (-1, -1), 8),
    ]))
    story.append(t)
    story.append(PageBreak())


def _render_module1(story, m1: dict):
    if not m1 or m1.get("error"):
        return
    story.append(_section("1. ASN & ISP Intelligence"))

    # ASN details table
    asns = m1.get("asn_details", [])
    if asns:
        story.append(_subsection("ASN Registrations"))
        rows = []
        for a in asns:
            rows.append([
                a.get("asn", "N/A"),
                a.get("organization", "N/A"),
                a.get("country", "N/A"),
                a.get("registry", "N/A"),
                "Primary" if a.get("is_primary") else "Secondary",
            ])
        story.append(_make_table(["ASN", "Organization", "Country", "Registry", "Role"],
                                 rows, [1.0*inch, 2.2*inch, 0.9*inch, 0.9*inch, 0.9*inch]))
        story.append(Spacer(1, 6))

    # IP prefixes
    prefixes = m1.get("ip_prefixes", [])
    if prefixes:
        story.append(_subsection("IP Prefixes"))
        story.append(_body(", ".join(prefixes)))
        story.append(Spacer(1, 6))

    # ISP profile
    isp = m1.get("isp_profile", {})
    if isp and isp.get("name"):
        story.append(_subsection("ISP Profile"))
        story.append(_kv_table([
            ("ISP Name", isp.get("name", "")),
            ("NOC Contact", isp.get("noc_contact", "")),
            ("Abuse Contact", isp.get("abuse_contact", "")),
            ("Peering Partners", ", ".join(isp.get("peering_relationships", [])[:10]) or "N/A"),
        ]))
        story.append(Spacer(1, 6))

    # AI risk
    risk = m1.get("ai_risk_summary", {})
    if risk and risk.get("summary_text"):
        story.append(_subsection("AI Risk Assessment"))
        rl = risk.get("risk_level", "Low")
        story.append(Paragraph(f"<b>Risk Level:</b> {_risk_badge(rl)}", _s["body"]))
        story.append(_body(risk["summary_text"]))
        story.append(Spacer(1, 6))

    # Provenance
    prov = m1.get("provenance", {})
    if prov:
        story.append(_subsection("Provenance"))
        story.append(_kv_table([
            ("Sources Queried", ", ".join(prov.get("sources_queried", [])) or "N/A"),
            ("Execution Time", f'{prov.get("execution_time_seconds", 0):.2f}s'),
        ]))
    story.append(Spacer(1, 10))


def _render_module2(story, m2: dict):
    if not m2 or m2.get("error"):
        return
    story.append(_section("2. Network Reconnaissance"))

    # Subnets
    subnets = m2.get("discovered_subnets", [])
    story.append(_subsection(f"Discovered Subnets ({len(subnets)})"))
    if subnets:
        rows = []
        for s in subnets:
            rows.append([
                s.get("cidr", ""),
                "Yes" if s.get("vlan_detected") else "No",
                str(s.get("estimated_vlan_id", "N/A")),
            ])
        story.append(_make_table(["CIDR", "VLAN Detected", "VLAN ID"],
                                 rows, [2.5*inch, 1.2*inch, 1.2*inch]))
    story.append(Spacer(1, 6))

    # Active hosts summary
    hosts = m2.get("active_hosts", [])
    story.append(_subsection(f"Active Hosts ({len(hosts)})"))
    if hosts:
        rows = []
        for h in hosts:
            fp = h.get("os_fingerprint", {})
            rows.append([
                h.get("ip_address", ""),
                h.get("mac_address", "N/A"),
                h.get("discovery_method", ""),
                fp.get("predicted_os", "Unknown"),
                str(fp.get("initial_ttl", "")),
                str(fp.get("tcp_window_size", "")),
                str(len(h.get("open_ports", []))),
            ])
        story.append(_make_table(
            ["IP Address", "MAC", "Method", "OS", "TTL", "Win Size", "Ports"],
            rows, [1.1*inch, 1.0*inch, 0.7*inch, 0.8*inch, 0.5*inch, 0.6*inch, 0.5*inch]))
        story.append(Spacer(1, 6))

        # Detailed host breakdown
        story.append(_subsection("Host Details"))
        for h in hosts:
            ip = h.get("ip_address", "")
            fp = h.get("os_fingerprint", {})
            ports = h.get("open_ports", [])
            pairs = [
                ("IP Address", ip),
                ("MAC Address", h.get("mac_address", "N/A")),
                ("Discovery", h.get("discovery_method", "")),
                ("OS", f'{fp.get("predicted_os", "Unknown")} (TTL={fp.get("initial_ttl", "?")}, WinSize={fp.get("tcp_window_size", "?")})'),
            ]
            if ports:
                port_strs = [f'{p.get("port")}/{p.get("protocol","tcp")}' for p in ports]
                pairs.append(("Open Ports", ", ".join(port_strs)))
            story.append(KeepTogether([
                Paragraph(f"<b>{ip}</b>", _s["body_bold"]),
                Spacer(1, 2),
                _kv_table(pairs, [1.5*inch, 5.2*inch]),
                Spacer(1, 6),
            ]))

        # Port breakdown table
        all_ports = []
        for h in hosts:
            for p in h.get("open_ports", []):
                all_ports.append((h.get("ip_address", ""), p))
        if all_ports:
            story.append(_subsection("Open Ports Summary"))
            rows = []
            for ip, p in all_ports:
                banner = p.get("banner", "") or ""
                if len(banner) > 60:
                    banner = banner[:60] + "…"
                rows.append([ip, str(p.get("port", "")),
                             p.get("protocol", "tcp"), p.get("service", ""), banner])
            story.append(_make_table(
                ["IP", "Port", "Proto", "Service", "Banner"],
                rows, [1.1*inch, 0.6*inch, 0.5*inch, 0.9*inch, 3.5*inch]))

    # Scan metadata
    meta = m2.get("scan_metadata", {})
    if meta:
        story.append(Spacer(1, 6))
        story.append(_subsection("Scan Metadata"))
        story.append(_kv_table([
            ("Stealth Mode", "Enabled" if meta.get("stealth_mode_enabled") else "Disabled"),
            ("Total Hosts", str(meta.get("total_hosts_found", 0))),
            ("Duration", f'{meta.get("scan_duration_seconds", 0):.2f}s'),
        ]))
    story.append(Spacer(1, 10))


def _render_module3(story, m3: dict):
    if not m3 or m3.get("error"):
        return
    story.append(_section("3. Security Perimeter Detection"))

    defs = m3.get("perimeter_defenses", {})

    # Firewall
    fw = defs.get("firewall", {})
    story.append(_subsection("Firewall"))
    story.append(_kv_table([
        ("Detected", "Yes" if fw.get("detected") else "No"),
        ("Type", fw.get("type", "N/A")),
        ("Filtering Behavior", fw.get("filtering_behavior", "N/A")),
    ]))
    story.append(Spacer(1, 4))

    # IDS/IPS
    ids = defs.get("ids_ips", {})
    story.append(_subsection("IDS/IPS"))
    story.append(_kv_table([
        ("Detected", "Yes" if ids.get("detected") else "No"),
        ("Action Observed", ids.get("action_observed", "N/A")),
    ]))
    story.append(Spacer(1, 4))

    # DMZ
    dmz = defs.get("dmz", {})
    story.append(_subsection("DMZ"))
    story.append(_kv_table([
        ("Detected", "Yes" if dmz.get("detected") else "No"),
        ("Exposure Boundary", dmz.get("exposure_boundary", "N/A")),
    ]))
    story.append(Spacer(1, 4))

    # WAF
    waf = defs.get("waf", {})
    story.append(_subsection("Web Application Firewall (WAF)"))
    sigs = waf.get("matched_signatures", [])
    story.append(_kv_table([
        ("Detected", "Yes" if waf.get("detected") else "No"),
        ("Vendor", waf.get("vendor", "Unknown")),
        ("Matched Signatures", ", ".join(sigs) if sigs else "None"),
    ]))
    story.append(Spacer(1, 4))

    # Evasion benchmarks
    ev = m3.get("evasion_benchmarks", {})
    if ev:
        story.append(_subsection("Evasion Benchmarks"))
        mechs = ev.get("documented_mechanisms", [])
        story.append(_kv_table([
            ("Fragmentation Tested", "Yes" if ev.get("fragmentation_tested") else "No"),
            ("Slow-Rate Timing", "Effective" if ev.get("slow_rate_timing_effective") else "Ineffective"),
            ("Mechanisms", ", ".join(mechs) if mechs else "None documented"),
        ]))
        story.append(Spacer(1, 4))

    # AI detection prediction
    ai_pred = m3.get("ai_detection_prediction", {})
    if ai_pred and ai_pred.get("probe_type_evaluated"):
        story.append(_subsection("AI Detection Prediction"))
        prob = ai_pred.get("predicted_detection_probability", 0)
        story.append(_kv_table([
            ("Probe Type", ai_pred.get("probe_type_evaluated", "")),
            ("Detection Probability", f"{prob*100:.1f}%"),
            ("Recommendation", ai_pred.get("recommendation", "")),
        ]))
        story.append(Spacer(1, 4))

    # Overall posture
    posture = m3.get("overall_security_posture", {})
    if posture:
        story.append(_subsection("Overall Security Posture"))
        rl = posture.get("risk_level", "Medium")
        story.append(Paragraph(f"<b>Risk Level:</b> {_risk_badge(rl)}", _s["body"]))
        story.append(_body(posture.get("summary", "")))
    story.append(Spacer(1, 10))


def _render_module4(story, m4: dict):
    if not m4 or m4.get("error"):
        return
    story.append(_section("4. Surveillance & IoT Fingerprinting"))

    devices = m4.get("surveillance_devices", [])
    story.append(_subsection(f"Detected Devices ({len(devices)})"))
    if devices:
        for dev in devices:
            cves = dev.get("cve_vulnerabilities", [])
            protos = dev.get("protocols_detected", [])
            pairs = [
                ("IP Address", dev.get("ip_address", "")),
                ("MAC Address", dev.get("mac_address", "N/A")),
                ("OUI Vendor", dev.get("oui_vendor", "Unknown")),
                ("Identified Vendor", dev.get("identified_vendor", "Unknown")),
                ("Classification", dev.get("classification", "")),
                ("Firmware", dev.get("firmware_version", "Unknown")),
                ("Protocols", ", ".join(protos) if protos else "N/A"),
                ("HTTP Title", dev.get("http_title") or "N/A"),
                ("Risk Rating", dev.get("risk_rating", "LOW")),
            ]
            story.append(KeepTogether([
                Paragraph(f"<b>{dev.get('ip_address', '')}</b> — {dev.get('classification', '')}", _s["body_bold"]),
                Spacer(1, 2),
                _kv_table(pairs, [1.6*inch, 5.1*inch]),
            ]))
            if cves:
                story.append(Paragraph("<b>CVE Vulnerabilities:</b>", _s["body_bold"]))
                cve_rows = [[c.get("cve_id", ""), c.get("severity", ""),
                             str(c.get("cvss_score", "")), c.get("description", "")[:80]]
                            for c in cves]
                story.append(_make_table(["CVE ID", "Severity", "CVSS", "Description"],
                                         cve_rows, [1.1*inch, 0.8*inch, 0.6*inch, 4.2*inch]))
            story.append(Spacer(1, 6))

    # Predicted IP ranges
    ranges = m4.get("predicted_ip_ranges", [])
    if ranges:
        story.append(_subsection("Predicted IoT IP Ranges"))
        rows = [[r.get("cidr_range", ""), f'{r.get("probability_score", 0)*100:.1f}%',
                 r.get("rationale", "")] for r in ranges]
        story.append(_make_table(["CIDR Range", "Probability", "Rationale"],
                                 rows, [1.5*inch, 1.0*inch, 4.0*inch]))
        story.append(Spacer(1, 4))

    # Summary
    summ = m4.get("summary", {})
    if summ:
        story.append(_subsection("IoT Summary"))
        story.append(_kv_table([
            ("Total IoT Devices", str(summ.get("total_iot_devices_found", 0))),
            ("Critical Risk", str(summ.get("critical_risk_count", 0))),
            ("High Risk", str(summ.get("high_risk_count", 0))),
        ]))
    story.append(Spacer(1, 10))


def _render_module5(story, m5: dict):
    if not m5 or m5.get("error"):
        return
    story.append(_section("5. Wireless Network Intelligence"))

    # Access points
    aps = m5.get("access_points", [])
    story.append(_subsection(f"Access Points ({len(aps)})"))
    if aps:
        rows = [[a.get("ssid", ""), a.get("bssid", ""), str(a.get("channel", "")),
                 f'{a.get("signal_rssi", 0)} dBm', a.get("encryption_type", ""),
                 a.get("vendor_oui", "")] for a in aps]
        story.append(_make_table(["SSID", "BSSID", "Ch", "RSSI", "Encryption", "Vendor"],
                                 rows, [1.4*inch, 1.3*inch, 0.4*inch, 0.7*inch, 0.9*inch, 1.2*inch]))
        story.append(Spacer(1, 6))

    # Enumerated clients
    clients = m5.get("enumerated_clients", [])
    story.append(_subsection(f"Enumerated Clients ({len(clients)})"))
    if clients:
        rows = [[c.get("mac_address", ""), c.get("assigned_ip", "N/A"),
                 c.get("status", ""), c.get("hostname") or "N/A",
                 c.get("last_seen_timestamp", "N/A")] for c in clients]
        story.append(_make_table(["MAC", "IP", "Status", "Hostname", "Last Seen"],
                                 rows, [1.3*inch, 1.0*inch, 0.7*inch, 1.2*inch, 1.5*inch]))
        story.append(Spacer(1, 6))

    # Authentication analysis
    auth = m5.get("authentication_analysis", {})
    if auth:
        story.append(_subsection("Authentication Analysis"))
        story.append(_kv_table([
            ("Primary Auth Method", auth.get("primary_auth_method", "N/A")),
            ("MAC Filtering", "Detected" if auth.get("mac_filtering_detected") else "Not Detected"),
            ("Vulnerability Assessment", auth.get("vulnerability_assessment", "N/A")),
        ]))
        story.append(Spacer(1, 4))

    # MAC cloning PoC
    mac_poc = m5.get("mac_cloning_proof_of_concept", {})
    if mac_poc and mac_poc.get("target_inactive_mac"):
        story.append(_subsection("MAC Cloning Proof of Concept"))
        story.append(_kv_table([
            ("Target Inactive MAC", mac_poc.get("target_inactive_mac", "")),
            ("Lab Interface", mac_poc.get("lab_interface_used", "")),
            ("Cloning Successful", "Yes" if mac_poc.get("cloning_successful") else "No"),
            ("Access Granted", "Yes" if mac_poc.get("access_granted_post_clone") else "No"),
        ]))
        story.append(Spacer(1, 4))

    # AI anomaly detection
    anomaly = m5.get("ai_anomaly_detection", {})
    if anomaly:
        story.append(_subsection("AI Anomaly Detection"))
        flagged = anomaly.get("anomalous_devices_flagged", [])
        story.append(_body(f"Total devices clustered: {anomaly.get('total_devices_clustered', 0)}"))
        if flagged:
            rows = [[f.get("mac_address", ""), f'{f.get("anomaly_score", 0)*100:.1f}%',
                     f.get("reason", "")] for f in flagged]
            story.append(_make_table(["MAC", "Anomaly Score", "Reason"],
                                     rows, [1.5*inch, 1.0*inch, 4.0*inch]))
        story.append(Spacer(1, 4))

    # Hardening recommendations
    recs = m5.get("hardening_recommendations", [])
    if recs:
        story.append(_subsection("Wireless Hardening Recommendations"))
        for r in recs:
            story.append(_bullet(r))
    story.append(Spacer(1, 10))


def _render_module6(story, m6: dict):
    if not m6 or m6.get("error"):
        return
    story.append(_section("6. AI/ML Analytics & Risk Scoring"))

    # Analytics summary
    summary = m6.get("ai_analytics_summary", {})
    if summary:
        story.append(_subsection("Analytics Overview"))
        hs = summary.get("network_health_score", 0)
        story.append(_kv_table([
            ("Total Devices Analyzed", str(summary.get("total_devices_analyzed", 0))),
            ("Anomalies Detected", str(summary.get("anomalies_detected_count", 0))),
            ("Network Health Score", f"{hs:.1f}/100"),
        ]))
        story.append(Spacer(1, 6))

    # Device classifications
    cls_list = m6.get("device_classifications", [])
    if cls_list:
        story.append(_subsection(f"Device Classifications ({len(cls_list)})"))
        rows = []
        for c in cls_list:
            rows.append([
                c.get("ip_address", ""),
                c.get("predicted_device_type", ""),
                f'{c.get("classifier_confidence", 0)*100:.0f}%',
                c.get("predicted_os", "Unknown"),
                f'{c.get("os_confidence", 0)*100:.0f}%',
                f'{c.get("calculated_risk_score", 0):.1f}',
                c.get("risk_category", "LOW"),
                "Yes" if c.get("is_anomalous") else "No",
            ])
        story.append(_make_table(
            ["IP", "Device Type", "Conf", "OS", "OS Conf", "Risk", "Category", "Anomaly"],
            rows, [0.9*inch, 1.1*inch, 0.45*inch, 0.85*inch, 0.45*inch, 0.4*inch, 0.6*inch, 0.5*inch]))
        story.append(Spacer(1, 6))

        # Detailed per-device breakdown
        story.append(_subsection("Per-Device Analysis"))
        for c in cls_list:
            reasons = c.get("anomaly_reasons", [])
            pairs = [
                ("IP Address", c.get("ip_address", "")),
                ("Device Type", c.get("predicted_device_type", "")),
                ("Classifier Confidence", f'{c.get("classifier_confidence", 0)*100:.1f}%'),
                ("Predicted OS", c.get("predicted_os", "Unknown")),
                ("OS Confidence", f'{c.get("os_confidence", 0)*100:.1f}%'),
                ("Risk Score", f'{c.get("calculated_risk_score", 0):.1f}/10.0'),
                ("Risk Category", c.get("risk_category", "LOW")),
                ("Anomalous", "Yes" if c.get("is_anomalous") else "No"),
            ]
            if reasons:
                pairs.append(("Anomaly Reasons", ", ".join(reasons)))
            story.append(KeepTogether([
                Paragraph(f"<b>{c.get('ip_address', '')}</b>", _s["body_bold"]),
                Spacer(1, 2),
                _kv_table(pairs, [1.8*inch, 4.9*inch]),
                Spacer(1, 4),
            ]))

    # Inferred topology
    topo = m6.get("inferred_topology", {})
    topo_nodes = topo.get("nodes", [])
    topo_links = topo.get("links", [])
    if topo_nodes:
        story.append(_subsection(f"Inferred Topology ({len(topo_nodes)} nodes, {len(topo_links)} links)"))
        rows = [[n.get("id", ""), n.get("label", ""), n.get("type", "")] for n in topo_nodes]
        story.append(_make_table(["Node ID", "Label", "Type"],
                                 rows, [2.0*inch, 2.5*inch, 1.2*inch]))
        if topo_links:
            story.append(Spacer(1, 4))
            story.append(Paragraph("<b>Topology Links:</b>", _s["body_bold"]))
            link_rows = [[l.get("source", ""), l.get("target", ""), str(l.get("weight", 1.0))]
                         for l in topo_links]
            story.append(_make_table(["Source", "Target", "Weight"],
                                     link_rows, [2.5*inch, 2.5*inch, 1.0*inch]))
        story.append(Spacer(1, 6))

    # Executive NL summary
    nl = m6.get("executive_nl_summary", {})
    if nl:
        story.append(_subsection("Executive Summary"))
        overview = nl.get("overview_paragraph", "")
        if overview:
            story.append(_body(overview))
            story.append(Spacer(1, 4))

        threats = nl.get("key_threats_identified", [])
        if threats:
            story.append(Paragraph("<b>Key Threats Identified:</b>", _s["body_bold"]))
            for t in threats:
                story.append(_bullet(t))
            story.append(Spacer(1, 4))

        mitigations = nl.get("recommended_mitigations", [])
        if mitigations:
            story.append(Paragraph("<b>Recommended Mitigations:</b>", _s["body_bold"]))
            for m in mitigations:
                story.append(_bullet(m))
    story.append(Spacer(1, 10))


def _render_footer(story, target_ip: str):
    story.append(Spacer(1, 30))
    story.append(Paragraph("━" * 70, _s["footer"]))
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        f"ANISAS v1.0.0 — Autonomous Network Intelligence &amp; Security Assessment System",
        _s["footer"]))
    story.append(Paragraph(
        f"Report generated {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC for target {target_ip}",
        _s["footer"]))
    story.append(Paragraph(
        "This report is generated autonomously. Verify critical findings manually.",
        _s["footer"]))


# ── Page number callback ────────────────────────────────────────────────

def _add_page_number(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(C_GREY)
    page_num = canvas.getPageNumber()
    text = f"ANISAS Report — Page {page_num}"
    canvas.drawCentredString(A4[0] / 2, 0.4 * inch, text)
    canvas.restoreState()


# ── Public API ──────────────────────────────────────────────────────────

def generate_pdf_report(results: dict, target_ip: str, output_path: str) -> str:
    """Generate a multi-page PDF intelligence report from combined scan results."""
    global _s
    _s = _styles()

    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    doc = SimpleDocTemplate(
        output_path, pagesize=A4,
        leftMargin=0.6 * inch, rightMargin=0.6 * inch,
        topMargin=0.7 * inch, bottomMargin=0.7 * inch,
    )

    story = []
    _render_cover(story, target_ip)
    _render_module1(story, results.get("module1", {}))
    _render_module2(story, results.get("module2", {}))
    _render_module3(story, results.get("module3", {}))
    _render_module4(story, results.get("module4", {}))
    _render_module5(story, results.get("module5", {}))
    _render_module6(story, results.get("module6", {}))
    _render_footer(story, target_ip)

    doc.build(story, onFirstPage=_add_page_number, onLaterPages=_add_page_number)
    return output_path
