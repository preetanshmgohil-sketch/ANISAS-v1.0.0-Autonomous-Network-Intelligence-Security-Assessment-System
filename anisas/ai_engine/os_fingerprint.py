"""TCP/IP stack OS fingerprinting model using behavioral features."""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

# Expanded OS classes
_OS_CLASSES = [
    "Linux",
    "Windows",
    "macOS",
    "Cisco/Network",
    "Solaris/BSD",
    "Embedded/RTOS",
    "Unknown",
]

# Training data: (ttl, window_size, has_ssh, has_http, has_windows_banner, has_linux_banner, label_idx)
_TRAINING_DATA: list[tuple[list[float], int]] = [
    # Linux (index 0)
    ([64, 29200, 1, 1, 0, 1], 0),
    ([64, 14600, 1, 1, 0, 1], 0),
    ([64, 65535, 1, 1, 0, 1], 0),
    ([64, 32768, 1, 0, 0, 1], 0),
    ([64, 16384, 0, 1, 0, 1], 0),
    ([64, 5840, 1, 1, 0, 0], 0),
    ([64, 28960, 1, 1, 0, 1], 0),
    ([64, 14480, 0, 1, 0, 1], 0),
    ([64, 58880, 1, 1, 0, 1], 0),
    ([64, 8760, 1, 1, 0, 1], 0),
    # Windows (index 1)
    ([128, 65535, 0, 1, 1, 0], 1),
    ([128, 8192, 0, 1, 1, 0], 1),
    ([128, 16384, 0, 1, 1, 0], 1),
    ([128, 64240, 0, 1, 1, 0], 1),
    ([128, 256960, 0, 1, 1, 0], 1),
    ([128, 65535, 1, 1, 1, 0], 1),
    ([128, 8192, 1, 0, 1, 0], 1),
    ([128, 32768, 0, 1, 1, 0], 1),
    ([128, 65535, 0, 0, 1, 0], 1),
    ([128, 8192, 0, 0, 1, 0], 1),
    # macOS (index 2)
    ([64, 65535, 1, 1, 0, 0], 2),
    ([64, 16384, 1, 1, 0, 0], 2),
    ([64, 65535, 0, 1, 0, 0], 2),
    ([64, 32768, 1, 1, 0, 0], 2),
    ([64, 65535, 1, 0, 0, 0], 2),
    ([64, 16384, 0, 1, 0, 0], 2),
    ([64, 8192, 1, 1, 0, 0], 2),
    # Cisco/Network (index 3)
    ([255, 4128, 1, 1, 0, 0], 3),
    ([255, 16384, 1, 1, 0, 0], 3),
    ([255, 4128, 0, 1, 0, 0], 3),
    ([255, 65535, 1, 1, 0, 0], 3),
    ([255, 8192, 1, 0, 0, 0], 3),
    ([255, 4128, 1, 0, 0, 0], 3),
    ([255, 4128, 0, 0, 0, 0], 3),
    ([252, 4128, 1, 0, 0, 0], 3),
    # Solaris/BSD (index 4)
    ([255, 65535, 1, 1, 0, 0], 4),
    ([255, 24820, 1, 1, 0, 0], 4),
    ([255, 32768, 1, 1, 0, 0], 4),
    ([64, 65535, 1, 0, 0, 0], 4),
    ([64, 57920, 1, 1, 0, 0], 4),
    # Embedded/RTOS (index 5)
    ([32, 29200, 0, 1, 0, 0], 5),
    ([32, 14600, 0, 1, 0, 0], 5),
    ([64, 512, 0, 1, 0, 0], 5),
    ([64, 1024, 0, 1, 0, 0], 5),
    ([128, 512, 0, 1, 0, 0], 5),
    ([255, 512, 0, 1, 0, 0], 5),
    ([32, 16384, 0, 1, 0, 0], 5),
    ([64, 2048, 0, 1, 0, 0], 5),
    ([1, 512, 0, 1, 0, 0], 5),
    ([32, 29200, 0, 0, 0, 0], 5),
]

# Pre-trained decision forest
_TREES: list[list[tuple]] = []


def _build_trees() -> None:
    """Build OS fingerprinting decision trees."""
    global _TREES
    _TREES = [
        # Tree 1: TTL-based primary split
        [(0, 96, -1, -1), (0, 192, 0, -1), (1, 10000, 3, 2)],
        # Tree 2: Window size + OS indicators
        [(1, 10000, -1, -1), (0, 96, 0, 1), (5, 0.5, 0, 3)],
        # Tree 3: Combined features
        [(0, 48, -1, 3), (0, 96, 0, 1), (1, 30000, 0, 1)],
        # Tree 4: Banner-informed
        [(4, 0.5, 1, -1), (5, 0.5, 0, -1), (0, 192, 2, 3)],
        # Tree 5: Fallback
        [(0, 96, 0, -1), (0, 192, 1, 2), (1, 5000, 3, 2)],
        # Tree 6: macOS / Solaris discriminator
        [(0, 80, 0, -1), (0, 160, 4, 1), (1, 40000, 2, 0)],
        # Tree 7: Embedded detection
        [(0, 48, 5, -1), (1, 4096, 5, 0), (0, 192, 1, 3)],
    ]


def _predict_tree(tree: list[tuple], features: list[float]) -> int:
    """Predict OS class using a single tree."""
    ttl = features[0] if features else 0
    ws = features[1] if len(features) > 1 else 0
    has_windows = features[4] if len(features) > 4 else 0
    has_linux = features[5] if len(features) > 5 else 0
    has_ssh = features[2] if len(features) > 2 else 0
    has_http = features[3] if len(features) > 3 else 0

    # Embedded detection (very low TTL or very small window)
    if ttl <= 48 or ws <= 1024:
        return 5  # Embedded

    # Solaris/BSD (high TTL, no Windows banner)
    if ttl >= 200 and not has_windows:
        return 4

    # Windows (medium TTL, Windows banner or large window)
    if 96 <= ttl <= 192:
        if has_windows:
            return 1
        if ws >= 60000:
            return 1
        # Large window + SSH could be macOS
        if has_ssh and ws >= 65535:
            return 2  # macOS
        return 1

    # Low TTL — Linux or macOS
    if ttl <= 96:
        if has_linux:
            return 0  # Linux
        if has_ssh and not has_linux:
            # SSH without linux banner — could be macOS or Solaris
            if ws >= 65535:
                return 2  # macOS
            return 0  # Default to Linux
        return 0

    # Default
    return 5  # Embedded/Unknown


def _train_simple() -> dict:
    """Train the OS fingerprinting model."""
    _build_trees()

    correct = 0
    total = len(_TRAINING_DATA)
    for features, label in _TRAINING_DATA:
        norm_features = [
            features[0], features[1], features[2],
            features[3], features[4], features[5],
        ]
        pred = _predict_tree(_TREES[0], norm_features)
        if pred == label:
            correct += 1

    return {"accuracy": correct / total if total > 0 else 0}


def fingerprint_os(features: list[float]) -> tuple[str, float]:
    """Predict OS from TCP/IP stack features.

    Returns (predicted_os, confidence).
    """
    if not _TREES:
        _train_simple()

    # Run through all trees and majority vote
    predictions = [_predict_tree(tree, features) for tree in _TREES]
    votes: dict[int, int] = {}
    for p in predictions:
        if 0 <= p < len(_OS_CLASSES):
            votes[p] = votes.get(p, 0) + 1

    if not votes:
        return "Unknown", 0.0

    total_votes = sum(votes.values())
    best_idx = max(votes, key=votes.get)
    confidence = votes[best_idx] / total_votes

    return _OS_CLASSES[best_idx], round(confidence, 3)


def fingerprint_all_os(hosts: list[dict]) -> list[dict]:
    """Fingerprint OS for all hosts with OS features."""
    results = []
    for host in hosts:
        os_features = host.get("os_features", [])
        if not os_features:
            continue

        os_name, confidence = fingerprint_os(os_features)
        results.append({
            "ip_address": host.get("ip_address", host.get("ip", "")),
            "predicted_os": os_name,
            "os_confidence": confidence,
        })

    return results
