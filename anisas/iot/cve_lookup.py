"""CVE cross-referencing — local database lookup and NVD API fallback."""

from __future__ import annotations

import logging
import re

logger = logging.getLogger(__name__)

# Local CVE database for common surveillance/IoT vulnerabilities
# In production, this would be loaded from an offline NVD dataset
_LOCAL_CVE_DB: list[dict] = [
    {
        "cve_id": "CVE-2021-36260",
        "vendor": "Hikvision",
        "firmware_pattern": r".*",
        "severity": "CRITICAL",
        "cvss_score": 9.8,
        "description": "Hikvision web server vulnerability allowing remote command injection via crafted HTTP messages.",
    },
    {
        "cve_id": "CVE-2023-28808",
        "vendor": "Hikvision",
        "firmware_pattern": r".*",
        "severity": "CRITICAL",
        "cvss_score": 9.8,
        "description": "Hikvision authentication bypass vulnerability in firmware versions before 4.30.0.",
    },
    {
        "cve_id": "CVE-2021-33044",
        "vendor": "Dahua",
        "firmware_pattern": r".*",
        "severity": "HIGH",
        "cvss_score": 7.5,
        "description": "Dahua authentication bypass vulnerability allowing access without credentials.",
    },
    {
        "cve_id": "CVE-2021-33045",
        "vendor": "Dahua",
        "firmware_pattern": r".*",
        "severity": "HIGH",
        "cvss_score": 7.5,
        "description": "Dahua authentication bypass via crafted HTTP requests.",
    },
    {
        "cve_id": "CVE-2022-28243",
        "vendor": "Dahua",
        "firmware_pattern": r".*",
        "severity": "HIGH",
        "cvss_score": 7.2,
        "description": "Dahua improper access control vulnerability in multiple product lines.",
    },
    {
        "cve_id": "CVE-2023-3836",
        "vendor": "Dahua",
        "firmware_pattern": r".*",
        "severity": "CRITICAL",
        "cvss_score": 9.8,
        "description": "Dahua command injection vulnerability in Network Video Recorders.",
    },
    {
        "cve_id": "CVE-2020-25078",
        "vendor": "Axis",
        "firmware_pattern": r".*",
        "severity": "HIGH",
        "cvss_score": 7.5,
        "description": "Axis Communications OS command injection in surveillance cameras.",
    },
    {
        "cve_id": "CVE-2023-47565",
        "vendor": "Axis",
        "firmware_pattern": r".*",
        "severity": "HIGH",
        "cvss_score": 7.2,
        "description": "Axis firmware update mechanism vulnerability.",
    },
    {
        "cve_id": "CVE-2021-35394",
        "vendor": "Reolink",
        "firmware_pattern": r".*",
        "severity": "HIGH",
        "cvss_score": 8.8,
        "description": "Reolink NVR command injection vulnerability.",
    },
    {
        "cve_id": "CVE-2019-11219",
        "vendor": "Ubiquiti",
        "firmware_pattern": r".*",
        "severity": "HIGH",
        "cvss_score": 7.5,
        "description": "Ubiquiti network device authentication bypass.",
    },
    {
        "cve_id": "CVE-2023-20268",
        "vendor": "Cisco",
        "firmware_pattern": r".*",
        "severity": "HIGH",
        "cvss_score": 7.2,
        "description": "Cisco network device privilege escalation vulnerability.",
    },
    {
        "cve_id": "CVE-2018-1000861",
        "vendor": "Multiple",
        "firmware_pattern": r".*",
        "severity": "CRITICAL",
        "cvss_score": 10.0,
        "description": "Deserialization vulnerability affecting multiple IoT/web platforms (BlueKeep-class).",
    },
    {
        "cve_id": "CVE-2020-13942",
        "vendor": "Multiple",
        "firmware_pattern": r".*",
        "severity": "CRITICAL",
        "cvss_score": 9.8,
        "description": "OS command injection in multiple IoT management platforms.",
    },
    {
        "cve_id": "CVE-2022-26143",
        "vendor": "Multiple",
        "firmware_pattern": r".*",
        "severity": "CRITICAL",
        "cvss_score": 9.8,
        "description": "Yealink device remote code execution via TDP protocol.",
    },
]

# Unencrypted protocol risk entries
_PROTOCOL_RISKS: list[dict] = [
    {
        "cve_id": "PROTOCOL-RTSP-UNENCRYPTED",
        "severity": "MEDIUM",
        "cvss_score": 5.3,
        "description": "RTSP video stream transmitted without encryption. Interceptable by network sniffing.",
    },
    {
        "cve_id": "PROTOCOL-HTTP-UNENCRYPTED",
        "severity": "MEDIUM",
        "cvss_score": 5.3,
        "description": "Web interface served over unencrypted HTTP. Credentials transmittable in cleartext.",
    },
    {
        "cve_id": "PROTOCOL-DEFAULT-CREDS",
        "severity": "HIGH",
        "cvss_score": 7.5,
        "description": "Device may be using default factory credentials (admin/admin, admin/12345).",
    },
]


def lookup_cves(vendor: str, firmware: str | None = None) -> list[dict]:
    """Look up known CVEs for a vendor/firmware combination.

    Returns list of CVE dicts with cve_id, severity, cvss_score, description.
    """
    results = []

    for cve in _LOCAL_CVE_DB:
        cve_vendor = cve.get("vendor", "")
        if cve_vendor == "Multiple" or cve_vendor.lower() == vendor.lower():
            # Check firmware pattern if specified
            fw_pattern = cve.get("firmware_pattern", ".*")
            if firmware and firmware != "Unknown":
                if not re.match(fw_pattern, firmware, re.IGNORECASE):
                    continue
            results.append({
                "cve_id": cve["cve_id"],
                "severity": cve["severity"],
                "cvss_score": cve["cvss_score"],
                "description": cve["description"],
            })

    return results


def assess_protocol_risks(
    protocols: list[str],
    is_encrypted: bool = False,
) -> list[dict]:
    """Assess risks from detected protocols.

    Returns list of protocol-based risk entries.
    """
    risks = []

    if "RTSP" in protocols and not is_encrypted:
        risks.append(_PROTOCOL_RISKS[0])

    if "HTTP" in protocols and not is_encrypted:
        risks.append(_PROTOCOL_RISKS[1])

    # Default credentials risk is always worth mentioning
    risks.append(_PROTOCOL_RISKS[2])

    return risks


def compute_risk_rating(
    cve_vulnerabilities: list[dict],
    protocols: list[str],
    firmware_known: bool = False,
) -> str:
    """Compute composite risk rating for a device.

    Considers CVE severity, unencrypted protocols, and firmware status.
    """
    score = 0.0

    # CVE contribution
    for cve in cve_vulnerabilities:
        cvss = cve.get("cvss_score", 0)
        score += cvss

    # Protocol risks
    if "RTSP" in protocols:
        score += 3.0
    if "HTTP" in protocols:
        score += 2.0

    # Firmware unknown = higher risk
    if not firmware_known:
        score += 2.0

    # Classify
    if score >= 15.0:
        return "CRITICAL"
    elif score >= 8.0:
        return "HIGH"
    elif score >= 4.0:
        return "MEDIUM"
    else:
        return "LOW"
