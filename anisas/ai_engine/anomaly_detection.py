"""Unsupervised anomaly detection using isolation-based scoring."""

from __future__ import annotations

import logging
import random

logger = logging.getLogger(__name__)

# Normal behavior baseline (mean, stddev) for features
# Features: open_port_count, has_risk_port, ttl_deviation, unique_services
_BASELINE = {
    "open_port_count": {"mean": 5.0, "std": 3.0},
    "has_risk_port": {"mean": 0.2, "std": 0.3},
    "ttl_deviation": {"mean": 10.0, "std": 15.0},
    "unique_services": {"mean": 3.0, "std": 2.0},
}

# High-risk ports
_RISK_PORTS = {21, 23, 135, 139, 445, 1433, 3389, 5900}


def _extract_anomaly_features(host: dict) -> list[float]:
    """Extract features for anomaly detection."""
    open_ports = host.get("open_ports", [])
    port_count = len(open_ports)

    # Count risk ports
    risk_count = 0
    services = set()
    for p_info in open_ports:
        port = p_info.get("port", 0)
        if port in _RISK_PORTS:
            risk_count += 1
        svc = p_info.get("service", "")
        if svc:
            services.add(svc)

    has_risk = 1.0 if risk_count > 0 else 0.0

    # TTL deviation (how far from expected)
    os_fp = host.get("os_fingerprint", {})
    ttl = os_fp.get("initial_ttl", 64)
    ttl_dev = abs(ttl - 64) / 255.0  # Normalized deviation

    return [
        float(port_count),
        has_risk,
        ttl_dev,
        float(len(services)),
    ]


def _z_score(value: float, mean: float, std: float) -> float:
    if std == 0:
        return 0.0
    return abs(value - mean) / max(std, 0.001)


def _isolation_score(features: list[float]) -> float:
    """Compute an isolation-based anomaly score (0.0 = normal, 1.0 = very anomalous)."""
    feature_names = list(_BASELINE.keys())
    total_score = 0.0

    for i, name in enumerate(feature_names):
        if i < len(features):
            baseline = _BASELINE[name]
            z = _z_score(features[i], baseline["mean"], baseline["std"])
            total_score += min(z / 3.0, 1.0)  # Cap at 1.0 per feature

    return min(total_score / len(feature_names), 1.0)


def detect_anomalies(
    hosts: list[dict],
    threshold: float = 0.6,
) -> list[dict]:
    """Detect anomalous devices using unsupervised isolation scoring.

    Returns list of anomaly dicts with mac_address (or ip), anomaly_score, reason.
    """
    results = []

    for host in hosts:
        features = _extract_anomaly_features(host)
        score = _isolation_score(features)

        if score >= threshold:
            reasons = []
            if features[0] > 15:
                reasons.append("unusually high number of open ports")
            if features[1] > 0:
                reasons.append("exposes high-risk management services")
            if features[2] > 0.5:
                reasons.append("abnormal TTL value for expected OS class")
            if features[3] > 6:
                reasons.append("excessive variety of running services")

            results.append({
                "ip_address": host.get("ip_address", host.get("ip", "")),
                "mac_address": host.get("mac_address"),
                "anomaly_score": round(score, 3),
                "reason": "; ".join(reasons) if reasons else "behavioral deviation from baseline",
            })

    return results


def compute_health_score(hosts: list[dict], anomalies: list[dict]) -> float:
    """Compute overall network health score (0-100).

    100 = perfectly healthy, 0 = critical.
    """
    if not hosts:
        return 100.0

    anomaly_ratio = len(anomalies) / len(hosts) if hosts else 0
    base_score = 100.0 * (1.0 - anomaly_ratio * 2)  # Anomalies heavily penalize
    return max(0.0, min(100.0, round(base_score, 1)))
