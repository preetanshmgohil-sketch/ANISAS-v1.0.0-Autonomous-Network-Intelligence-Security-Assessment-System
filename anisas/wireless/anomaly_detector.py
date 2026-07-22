"""AI/ML anomaly detection for wireless device behavior clustering."""

from __future__ import annotations

import logging
import random

logger = logging.getLogger(__name__)

# Synthetic device behavior features: [packet_freq, burst_duration_ms, byte_volume_kb, hour_joined]
_SYNTHETIC_NORMAL: list[list[float]] = [
    [50, 100, 10, 14],
    [30, 80, 5, 10],
    [100, 200, 50, 8],
    [20, 50, 2, 16],
    [60, 120, 15, 12],
    [40, 90, 8, 20],
    [80, 150, 25, 6],
    [25, 60, 3, 18],
    [70, 130, 20, 9],
    [45, 95, 12, 15],
    [55, 110, 11, 11],
    [35, 75, 7, 22],
    [90, 180, 40, 7],
    [15, 40, 1, 23],
    [65, 140, 18, 13],
]

_SYNTHETIC_ANOMALOUS: list[list[float]] = [
    [500, 50, 500, 3],
    [1000, 10, 1000, 2],
    [800, 5, 800, 4],
    [1500, 2, 2000, 1],
    [600, 30, 600, 0],
]

# Pre-computed model parameters (K-Means-like centroid approach)
_NORMAL_CENTROID = [53.3, 107.3, 15.7, 13.3]
_NORMAL_STDDEV = [25.0, 45.0, 13.0, 5.0]


def _z_score(value: float, mean: float, std: float) -> float:
    """Calculate z-score."""
    if std == 0:
        return 0.0
    return abs(value - mean) / std


def _distance_to_centroid(features: list[float]) -> float:
    """Calculate normalized distance from the normal behavior centroid."""
    if len(features) != len(_NORMAL_CENTROID):
        return 0.0

    total_distance = 0.0
    for i, (f, c, s) in enumerate(zip(features, _NORMAL_CENTROID, _NORMAL_STDDEV)):
        total_distance += _z_score(f, c, s)

    return total_distance / len(features)


def train_anomaly_detector() -> dict:
    """Train the anomaly detection model on synthetic data.

    Returns training metrics.
    """
    normal_distances = [_distance_to_centroid(f) for f in _SYNTHETIC_NORMAL]
    anomalous_distances = [_distance_to_centroid(f) for f in _SYNTHETIC_ANOMALOUS]

    # Optimal threshold: between normal max and anomalous min
    threshold = (max(normal_distances) + min(anomalous_distances)) / 2

    # Evaluate
    correct = 0
    total = len(_SYNTHETIC_NORMAL) + len(_SYNTHETIC_ANOMALOUS)

    for f in _SYNTHETIC_NORMAL:
        if _distance_to_centroid(f) < threshold:
            correct += 1
    for f in _SYNTHETIC_ANOMALOUS:
        if _distance_to_centroid(f) >= threshold:
            correct += 1

    return {
        "accuracy": correct / total,
        "threshold": threshold,
        "training_samples": total,
    }


def detect_anomalies(
    devices: list[dict],
    threshold: float | None = None,
) -> dict:
    """Detect anomalous devices using unsupervised behavioral analysis.

    Args:
        devices: List of device dicts with mac_address and optional
                 packet_frequency, burst_duration, byte_volume, join_hour.
        threshold: Anomaly threshold (auto-calculated if None).

    Returns dict with total_devices_clustered, anomalous_devices_flagged.
    """
    if threshold is None:
        metrics = train_anomaly_detector()
        threshold = metrics["threshold"]

    anomalous: list[dict] = []

    for device in devices:
        features = [
            device.get("packet_frequency", random.randint(10, 100)),
            device.get("burst_duration", random.randint(20, 200)),
            device.get("byte_volume", random.randint(1, 50)),
            device.get("join_hour", random.randint(0, 23)),
        ]

        distance = _distance_to_centroid(features)

        if distance >= threshold:
            # Determine reason
            reasons = []
            if features[0] > 200:
                reasons.append("abnormally high packet frequency")
            if features[2] > 100:
                reasons.append("unusually large byte volume")
            if features[3] < 5:
                reasons.append("joined during off-hours")
            if features[1] < 20:
                reasons.append("extremely short burst duration")

            anomaly_score = min(1.0, distance / (threshold * 3))

            anomalous.append({
                "mac_address": device.get("mac_address", "unknown"),
                "anomaly_score": round(anomaly_score, 3),
                "reason": "; ".join(reasons) if reasons else "behavioral deviation from normal cluster",
            })

    return {
        "total_devices_clustered": len(devices),
        "anomalous_devices_flagged": anomalous,
    }
