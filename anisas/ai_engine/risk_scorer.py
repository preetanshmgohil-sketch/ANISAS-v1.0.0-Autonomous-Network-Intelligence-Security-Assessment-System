"""Deterministic and ML-driven risk scoring engine."""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

# Risk weights
_W_CVE = 0.35
_W_PORT = 0.30
_W_FIRMWARE = 0.20
_W_ANOMALY = 0.15

# High-risk ports and their individual risk contribution
_PORT_RISK: dict[int, float] = {
    21: 0.6, 23: 0.8, 25: 0.3, 53: 0.2, 80: 0.3,
    110: 0.3, 135: 0.7, 139: 0.7, 143: 0.3, 443: 0.2,
    445: 0.7, 554: 0.4, 8080: 0.4, 8443: 0.3, 3306: 0.5,
    3389: 0.6, 5432: 0.5, 5900: 0.6, 8000: 0.4, 8888: 0.5,
    9090: 0.4, 27017: 0.5, 3702: 0.3,
}


def _cve_score(cve_vulns: list[dict]) -> float:
    """Compute risk from CVE vulnerabilities (0.0 - 1.0)."""
    if not cve_vulns:
        return 0.0

    max_cvss = 0.0
    for cve in cve_vulns:
        cvss = cve.get("cvss_score", 0)
        severity = cve.get("severity", "LOW")
        if severity == "CRITICAL":
            cvss = max(cvss, 9.0)
        elif severity == "HIGH":
            cvss = max(cvss, 7.0)
        max_cvss = max(max_cvss, cvss)

    return min(max_cvss / 10.0, 1.0)


def _port_risk_score(open_ports: list[dict]) -> float:
    """Compute risk from open ports (0.0 - 1.0)."""
    if not open_ports:
        return 0.0

    risk_ports = 0
    total_risk = 0.0
    for p_info in open_ports:
        port = p_info.get("port", 0)
        if port in _PORT_RISK:
            risk_ports += 1
            total_risk += _PORT_RISK[port]

    if risk_ports == 0:
        return 0.0

    return min(total_risk / risk_ports, 1.0)


def _firmware_risk(firmware: str) -> float:
    """Compute risk from firmware version (0.0 - 1.0)."""
    if not firmware or firmware == "Unknown":
        return 0.5  # Unknown firmware = moderate risk

    # Heuristic: older version numbers = higher risk
    import re
    versions = re.findall(r"(\d+)", firmware)
    if not versions:
        return 0.3

    # If major version is very low, higher risk
    major = int(versions[0]) if versions else 0
    if major <= 1:
        return 0.7
    elif major <= 3:
        return 0.4
    else:
        return 0.2


def compute_risk_score(
    cve_vulns: list[dict] | None = None,
    open_ports: list[dict] | None = None,
    firmware: str | None = None,
    is_anomalous: bool = False,
    anomaly_score: float = 0.0,
) -> tuple[float, str]:
    """Compute composite risk score for a device.

    Returns (risk_score 0.0-10.0, risk_category).
    """
    cve = _cve_score(cve_vulns or [])
    port = _port_risk_score(open_ports or [])
    fw = _firmware_risk(firmware or "Unknown")
    anomaly = anomaly_score if is_anomalous else 0.0

    raw_score = (
        _W_CVE * cve +
        _W_PORT * port +
        _W_FIRMWARE * fw +
        _W_ANOMALY * anomaly
    )

    # Scale to 0.0 - 10.0
    risk_score = round(raw_score * 10.0, 2)
    risk_score = max(0.0, min(10.0, risk_score))

    # Categorize
    if risk_score >= 8.0:
        category = "CRITICAL"
    elif risk_score >= 6.0:
        category = "HIGH"
    elif risk_score >= 3.0:
        category = "MEDIUM"
    else:
        category = "LOW"

    return risk_score, category


def score_all_devices(
    classifications: list[dict],
    anomaly_data: list[dict],
) -> list[dict]:
    """Score risk for all classified devices.

    Enriches classification dicts with calculated_risk_score and risk_category.
    """
    # Index anomalies by IP
    anomaly_map: dict[str, dict] = {}
    for a in anomaly_data:
        ip = a.get("ip_address", "")
        if ip:
            anomaly_map[ip] = a

    for dev in classifications:
        ip = dev.get("ip_address", "")
        anomaly = anomaly_map.get(ip, {})

        risk_score, risk_category = compute_risk_score(
            cve_vulns=dev.get("cve_vulnerabilities", []),
            open_ports=dev.get("open_ports", []),
            firmware=dev.get("firmware_version"),
            is_anomalous=anomaly.get("anomaly_score", 0) > 0.5,
            anomaly_score=anomaly.get("anomaly_score", 0),
        )

        dev["calculated_risk_score"] = risk_score
        dev["risk_category"] = risk_category
        dev["is_anomalous"] = anomaly.get("anomaly_score", 0) > 0.5
        dev["anomaly_reasons"] = [anomaly.get("reason", "")] if anomaly.get("reason") else []

    return classifications
