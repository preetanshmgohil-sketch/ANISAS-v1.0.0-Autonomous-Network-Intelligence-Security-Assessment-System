"""Natural language report generation with LLM fallback to rule-based templates."""

from __future__ import annotations

import logging
import os

logger = logging.getLogger(__name__)

# Rule-based template for fallback
_OVERVIEW_TEMPLATE = (
    "Network security assessment of {total_devices} devices across {total_subnets} subnets. "
    "The analysis identified {critical_count} critical, {high_count} high, {medium_count} medium, "
    "and {low_count} low risk devices. {anomaly_text} {perimeter_text}"
)

_THREAT_TEMPLATES = {
    "open_ports": "Device {ip} exposes {count} open ports including high-risk services ({ports}).",
    "cve": "Device {ip} is affected by {count} known CVE(s) with max CVSS score of {max_cvss}.",
    "anomaly": "Anomalous device {ip} detected: {reason}.",
    "firmware": "Device {ip} runs unknown/outdated firmware version '{firmware}'.",
    "unencrypted": "Device {ip} provides services over unencrypted protocols ({ports}).",
}

_MITIGATION_TEMPLATES = [
    "Deploy WPA3-Enterprise with 802.1X certificate-based authentication for wireless networks.",
    "Enable network segmentation to isolate critical assets from general-purpose subnets.",
    "Apply firmware updates to all devices with known CVE vulnerabilities.",
    "Disable unnecessary open ports and services on all discovered devices.",
    "Implement intrusion detection/prevention systems (IDS/IPS) for real-time monitoring.",
    "Replace Telnet and FTP with SSH and SFTP for secure remote management.",
    "Enable encryption on all management interfaces (HTTPS, SSH, RTSPS).",
    "Deploy MAC address filtering as supplementary (not primary) access control.",
    "Regularly audit network device inventory and remove unauthorized hardware.",
    "Configure automated CVE scanning and patch management workflows.",
]


def generate_nl_summary(
    classifications: list[dict],
    anomalies: list[dict],
    topology: dict,
    perimeter: dict | None = None,
) -> dict:
    """Generate natural language executive summary.

    Uses rule-based templates (LLM API integration point).
    Returns dict with overview_paragraph, key_threats_identified, recommended_mitigations.
    """
    total = len(classifications)
    critical = sum(1 for d in classifications if d.get("risk_category") == "CRITICAL")
    high = sum(1 for d in classifications if d.get("risk_category") == "HIGH")
    medium = sum(1 for d in classifications if d.get("risk_category") == "MEDIUM")
    low = sum(1 for d in classifications if d.get("risk_category") == "LOW")
    total_subnets = len(topology.get("nodes", []))

    # Anomaly text
    if anomalies:
        anomaly_text = f"{len(anomalies)} anomalous device(s) were flagged requiring immediate investigation."
    else:
        anomaly_text = "No anomalous devices were detected."

    # Perimeter text
    perimeter_text = ""
    if perimeter:
        defs = perimeter.get("perimeter_defenses", {})
        fw = defs.get("firewall", {}).get("detected", False)
        ids = defs.get("ids_ips", {}).get("detected", False)
        waf = defs.get("waf", {}).get("detected", False)
        perimeter_text = (
            f"Perimeter defenses: Firewall={'Active' if fw else 'Not Detected'}, "
            f"IDS/IPS={'Active' if ids else 'Not Detected'}, "
            f"WAF={'Active' if waf else 'Not Detected'}."
        )

    overview = _OVERVIEW_TEMPLATE.format(
        total_devices=total,
        total_subnets=total_subnets,
        critical_count=critical,
        high_count=high,
        medium_count=medium,
        low_count=low,
        anomaly_text=anomaly_text,
        perimeter_text=perimeter_text,
    )

    # Key threats
    threats: list[str] = []
    for dev in classifications:
        ip = dev.get("ip_address", "")
        open_ports = dev.get("open_ports", [])
        cves = dev.get("cve_vulnerabilities", [])
        anomaly = dev.get("is_anomalous", False)

        if len(open_ports) > 10:
            threats.append(_THREAT_TEMPLATES["open_ports"].format(
                ip=ip, count=len(open_ports),
                ports=", ".join(str(p.get("port", "")) for p in open_ports[:5])
            ))

        if cves:
            max_cvss = max(c.get("cvss_score", 0) for c in cves)
            threats.append(_THREAT_TEMPLATES["cve"].format(
                ip=ip, count=len(cves), max_cvss=max_cvss
            ))

        if anomaly:
            reasons = dev.get("anomaly_reasons", ["unknown behavioral pattern"])
            threats.append(_THREAT_TEMPLATES["anomaly"].format(
                ip=ip, reason=reasons[0] if reasons else "unknown"
            ))

    # Select top mitigations based on findings
    mitigations: list[str] = []
    if critical > 0 or high > 0:
        mitigations.append(_MITIGATION_TEMPLATES[2])  # Firmware updates
        mitigations.append(_MITIGATION_TEMPLATES[3])  # Disable ports
    if anomalies:
        mitigations.append(_MITIGATION_TEMPLATES[8])  # Audit inventory
    if any(d.get("is_anomalous") for d in classifications):
        mitigations.append(_MITIGATION_TEMPLATES[6])  # Enable encryption
    mitigations.extend(_MITIGATION_TEMPLATES[:2])  # Always include top 2

    # Deduplicate
    seen: set[str] = set()
    unique_mitigations: list[str] = []
    for m in mitigations:
        if m not in seen:
            seen.add(m)
            unique_mitigations.append(m)

    return {
        "overview_paragraph": overview,
        "key_threats_identified": threats[:10],
        "recommended_mitigations": unique_mitigations[:8],
    }
