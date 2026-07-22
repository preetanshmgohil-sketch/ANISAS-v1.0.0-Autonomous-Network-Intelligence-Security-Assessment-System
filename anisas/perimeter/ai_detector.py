"""AI/ML scan detection classifier — predicts whether a scan will trigger alerts."""

from __future__ import annotations

import logging
import random

logger = logging.getLogger(__name__)

# Feature definitions for the classifier
_FEATURE_NAMES = [
    "probe_type_encoded",       # TCP-SYN=0, ACK=1, ICMP=2, UDP=3
    "burst_rate",               # Packets per second
    "timing_interval_ms",      # Average delay between probes
    "target_port_count",       # Number of ports scanned
    "fragmentation_enabled",   # 0 or 1
    "decoy_count",             # Number of decoy IPs used
]

# Synthetic training data (scan_config -> detected: 0/1)
# Format: (probe_type, burst_rate, timing_ms, port_count, frag, decoys, detected)
_SYNTHETIC_DATA: list[tuple] = [
    (0, 100, 10, 100, 0, 0, 1),     # Fast SYN scan, no evasion -> detected
    (0, 10, 100, 100, 0, 0, 0),     # Slow SYN scan -> not detected
    (0, 100, 10, 100, 1, 5, 0),     # Fast with frag + decoys -> not detected
    (1, 50, 50, 50, 0, 0, 1),       # ACK scan moderate -> detected
    (1, 5, 200, 50, 0, 0, 0),       # Slow ACK scan -> not detected
    (2, 200, 5, 256, 0, 0, 1),      # Fast ping sweep -> detected
    (2, 20, 50, 256, 0, 0, 0),      # Slow ping sweep -> not detected
    (3, 100, 10, 100, 0, 0, 1),     # Fast UDP scan -> detected
    (3, 5, 200, 30, 0, 0, 0),       # Slow UDP scan -> not detected
    (0, 200, 5, 1000, 0, 0, 1),     # Very fast SYN -> definitely detected
    (0, 1, 500, 100, 0, 10, 0),     # Ultra slow + decoys -> not detected
    (0, 100, 10, 100, 1, 10, 0),    # Fast but frag + decoys -> evades
    (1, 100, 10, 100, 0, 0, 1),     # Fast ACK -> detected
    (1, 100, 10, 100, 1, 5, 0),     # Fast ACK + evasion -> evades
    (2, 500, 2, 1000, 0, 0, 1),     # Hyper-fast ping -> detected
    (2, 5, 200, 100, 0, 0, 0),      # Slow ping -> not detected
    (0, 50, 50, 200, 0, 0, 0),      # Moderate SYN -> borderline
    (0, 50, 50, 200, 1, 3, 0),      # Moderate + evasion -> not detected
    (3, 50, 50, 200, 0, 0, 1),      # Moderate UDP -> detected
    (3, 10, 100, 50, 1, 0, 0),      # Slow UDP + frag -> not detected
]

# Simple logistic regression weights (pre-trained on synthetic data)
# In production, this would be a proper scikit-learn model
_WEIGHTS = [0.35, 0.28, -0.22, 0.15, -0.30, -0.18]
_BIAS = -0.10


def _sigmoid(x: float) -> float:
    """Sigmoid activation function with overflow protection."""
    x = max(-500.0, min(500.0, x))
    return 1.0 / (1.0 + 2.718281828 ** (-x))


def _extract_features(
    probe_type: str,
    burst_rate: float,
    timing_ms: float,
    port_count: int,
    fragmentation: bool,
    decoy_count: int,
) -> list[float]:
    """Convert scan parameters to feature vector."""
    probe_map = {"TCP-SYN": 0, "ACK": 1, "ICMP": 2, "UDP": 3}
    encoded = probe_map.get(probe_type, 0)

    return [
        float(encoded),
        float(burst_rate),
        float(timing_ms),
        float(port_count),
        1.0 if fragmentation else 0.0,
        float(decoy_count),
    ]


def train_classifier() -> dict:
    """Train the scan detection classifier on synthetic data.

    Uses a simple logistic regression with gradient descent.
    Returns training metrics.
    """
    global _WEIGHTS, _BIAS

    lr = 0.01
    epochs = 200

    for _ in range(epochs):
        for sample in _SYNTHETIC_DATA:
            features = [float(s) for s in sample[:6]]
            label = float(sample[6])

            # Forward pass
            z = sum(w * f for w, f in zip(_WEIGHTS, features)) + _BIAS
            pred = _sigmoid(z)

            # Backward pass
            error = pred - label
            for i in range(len(_WEIGHTS)):
                _WEIGHTS[i] -= lr * error * features[i]
            _BIAS -= lr * error

    # Evaluate on training data
    correct = 0
    for sample in _SYNTHETIC_DATA:
        features = [float(s) for s in sample[:6]]
        label = float(sample[6])
        z = sum(w * f for w, f in zip(_WEIGHTS, features)) + _BIAS
        pred = _sigmoid(z)
        predicted_label = 1 if pred >= 0.5 else 0
        if predicted_label == int(label):
            correct += 1

    accuracy = correct / len(_SYNTHETIC_DATA)

    return {
        "accuracy": accuracy,
        "training_samples": len(_SYNTHETIC_DATA),
        "weights": _WEIGHTS.copy(),
        "bias": _BIAS,
    }


def predict_detection(
    probe_type: str = "TCP-SYN",
    burst_rate: float = 50.0,
    timing_ms: float = 50.0,
    port_count: int = 100,
    fragmentation: bool = False,
    decoy_count: int = 0,
) -> dict:
    """Predict whether a scan configuration will be detected.

    Returns dict with predicted_detection_probability and recommendation.
    """
    features = _extract_features(probe_type, burst_rate, timing_ms, port_count, fragmentation, decoy_count)

    z = sum(w * f for w, f in zip(_WEIGHTS, features)) + _BIAS
    probability = _sigmoid(z)

    # Generate recommendation
    if probability >= 0.7:
        recommendation = (
            f"High detection risk ({probability:.0%}). "
            "Recommend: reduce burst rate below 10 pps, enable fragmentation, "
            "add 5+ decoy IPs, and increase inter-packet delay to >200ms."
        )
    elif probability >= 0.4:
        recommendation = (
            f"Moderate detection risk ({probability:.0%}). "
            "Consider enabling fragmentation and adding decoy sources to reduce exposure."
        )
    else:
        recommendation = (
            f"Low detection risk ({probability:.0%}). "
            "Current scan parameters are likely to evade standard IDS/IPS detection."
        )

    return {
        "probe_type_evaluated": probe_type,
        "predicted_detection_probability": round(probability, 4),
        "recommendation": recommendation,
    }
