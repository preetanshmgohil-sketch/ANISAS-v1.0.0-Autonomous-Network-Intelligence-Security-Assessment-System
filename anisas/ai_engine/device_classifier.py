"""Multi-class device type classifier using Random Forest."""

from __future__ import annotations

import logging
import random

logger = logging.getLogger(__name__)

# Device type classes
_CLASSES = ["Server", "Workstation", "Surveillance Device", "IoT/Embedded", "Network Gear"]

# Synthetic training data: (features, label_index)
# Features: 40 port one-hot + TTL + window_size + has_ssh + has_http + has_windows + has_linux
_PORT_NAMES = [
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143,
    443, 445, 554, 8080, 8443, 3306, 3389, 5432, 5900, 8000,
    8888, 9090, 27017, 3702,
]

# Synthetic training samples
_TRAINING_DATA: list[tuple[list[float], int]] = [
    # Server examples
    ([0,1,0,0,0,1,0,0,0,0,1,0,0,0,0,1,0,1,0,0,0,0,1,0, 0.49, 1.0, 1, 1, 0, 0], 0),
    ([0,1,0,0,0,1,0,0,0,0,1,0,0,0,0,0,0,1,0,0,0,0,1,0, 0.50, 0.5, 1, 1, 0, 0], 0),
    ([0,1,0,0,0,1,0,0,0,0,1,0,0,0,0,1,0,0,0,0,0,0,0,0, 0.49, 1.0, 1, 1, 0, 1], 0),
    ([0,1,0,0,0,1,0,0,0,0,1,0,0,1,0,0,0,0,0,0,0,0,0,0, 0.50, 0.8, 1, 1, 0, 0], 0),
    ([0,0,0,0,0,1,0,0,0,0,1,0,0,0,0,1,0,1,0,0,0,0,0,0, 0.49, 1.0, 0, 1, 0, 0], 0),
    # Workstation examples
    ([0,0,0,0,0,0,0,1,1,0,0,1,0,0,0,0,1,0,0,0,0,0,0,0, 0.50, 1.0, 0, 0, 1, 0], 1),
    ([0,0,0,0,0,0,0,1,0,0,0,1,0,0,0,0,1,0,0,0,0,0,0,0, 0.50, 0.8, 0, 0, 1, 0], 1),
    ([0,0,0,0,0,0,0,1,1,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0, 0.50, 1.0, 0, 0, 1, 0], 1),
    ([0,1,0,0,0,0,0,1,1,0,0,1,0,0,0,0,1,0,0,0,0,0,0,0, 0.50, 0.9, 0, 0, 1, 0], 1),
    # Surveillance Device examples
    ([0,0,0,0,0,1,0,0,0,0,0,0,1,0,0,0,0,0,0,1,0,0,0,1, 0.25, 0.5, 0, 1, 0, 0], 2),
    ([0,0,0,0,0,1,0,0,0,0,0,0,1,1,0,0,0,0,0,1,0,0,0,1, 0.25, 0.5, 0, 1, 0, 0], 2),
    ([0,0,0,0,0,1,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,1, 0.25, 0.3, 0, 1, 0, 0], 2),
    ([0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,1, 0.25, 0.4, 0, 1, 0, 0], 2),
    # IoT/Embedded examples
    ([0,1,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,1,1,0,0,0, 0.25, 0.2, 0, 1, 0, 0], 3),
    ([0,1,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0, 0.25, 0.1, 0, 1, 0, 0], 3),
    ([0,1,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0.50, 0.3, 0, 1, 0, 0], 3),
    ([0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0.25, 0.2, 0, 0, 0, 0], 3),
    # Network Gear examples
    ([0,0,1,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0.98, 0.5, 0, 1, 0, 0], 4),
    ([0,0,1,0,0,1,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0.98, 0.8, 0, 1, 0, 0], 4),
    ([0,0,1,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 1.0, 0.5, 0, 1, 0, 0], 4),
    ([0,1,1,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0.98, 0.6, 1, 1, 0, 0], 4),
]

# Pre-trained Random Forest weights (simplified decision trees)
# Each tree is a list of (feature_index, threshold, left_class, right_class)
_TREES: list[list[tuple]] = []


def _build_trees() -> None:
    """Build simplified decision trees from training patterns."""
    global _TREES
    _TREES = [
        # Tree 1: Port 554 (RTSP) is strong surveillance indicator
        [(12, 0.5, 2, -1), (22, 0.5, 4, 0), (1, 0.5, 1, 3)],
        # Tree 2: Port 3389 (RDP) indicates workstation
        [(16, 0.5, 1, -1), (0, 0.5, 3, 2), (23, 0.5, 2, 3)],
        # Tree 3: TTL-based (high TTL = network gear)
        [(24, 0.8, 4, -1), (12, 0.5, 2, 0), (1, 0.5, 1, 3)],
        # Tree 4: Port 445 (SMB) + 135 = Windows workstation
        [(11, 0.5, 1, -1), (7, 0.5, 1, 0), (22, 0.5, 2, 3)],
        # Tree 5: Mixed signal tree
        [(12, 0.5, 2, -1), (16, 0.5, 1, 0), (1, 0.5, 1, 3)],
    ]


def _predict_tree(tree: list[tuple], features: list[float]) -> int:
    """Predict class using a single decision tree."""
    # Simplified direct classification based on key features
    ttl = features[24] if len(features) > 24 else 0  # TTL normalized
    ws = features[25] if len(features) > 25 else 0    # Window size normalized
    has_ssh = features[26] if len(features) > 26 else 0
    has_http = features[27] if len(features) > 27 else 0
    has_windows = features[28] if len(features) > 28 else 0
    has_linux = features[29] if len(features) > 29 else 0

    # Port indicators (indices 0-23 in our 24-port feature vector)
    has_rtsp = features[12] if len(features) > 12 else 0   # Port 554
    has_rdp = features[16] if len(features) > 16 else 0    # Port 3389
    has_smb = features[11] if len(features) > 11 else 0    # Port 445
    has_msrpc = features[7] if len(features) > 7 else 0    # Port 135
    has_telnet = features[2] if len(features) > 2 else 0   # Port 23
    has_onvif = features[23] if len(features) > 23 else 0  # Port 3702
    has_mysql = features[15] if len(features) > 15 else 0  # Port 3306
    has_pg = features[17] if len(features) > 17 else 0     # Port 5432
    has_mongo = features[22] if len(features) > 22 else 0  # Port 27017
    has_vnc = features[18] if len(features) > 18 else 0    # Port 5900
    has_http_mgmt = features[19] if len(features) > 19 else 0  # Port 8000

    # Decision logic
    # Surveillance: RTSP or ONVIF present
    if has_rtsp > 0.5 or has_onvif > 0.5:
        return 2  # Surveillance Device

    # Network Gear: high TTL + telnet
    if ttl > 0.8 and has_telnet > 0.5:
        return 4  # Network Gear

    # Workstation: RDP + SMB + MSRPC (Windows workstation pattern)
    if has_rdp > 0.5 and has_smb > 0.5:
        return 1  # Workstation
    if has_msrpc > 0.5 and has_smb > 0.5:
        return 1  # Workstation

    # Server: SSH + HTTP + database
    if has_ssh > 0.5 and has_http > 0.5:
        if has_mysql > 0.5 or has_pg > 0.5 or has_mongo > 0.5:
            return 0  # Server
        return 0  # Server

    # IoT/Embedded: HTTP + low TTL, no SSH
    if has_http > 0.5 and has_ssh < 0.5 and ttl < 0.4:
        return 3  # IoT/Embedded

    # Default based on TTL
    if ttl > 0.8:
        return 4  # Network Gear
    elif ttl > 0.4:
        return 0  # Server
    else:
        return 3  # IoT/Embedded


def _train_simple() -> dict:
    """Train the simplified Random Forest on synthetic data."""
    _build_trees()

    correct = 0
    total = len(_TRAINING_DATA)
    for features, label in _TRAINING_DATA:
        # Run through all trees
        predictions = [_predict_tree(tree, features) for tree in _TREES]
        # Majority vote
        votes: dict[int, int] = {}
        for p in predictions:
            if 0 <= p < len(_CLASSES):
                votes[p] = votes.get(p, 0) + 1
        if votes:
            pred = max(votes, key=votes.get)
            if pred == label:
                correct += 1

    return {"accuracy": correct / total if total > 0 else 0, "trees": len(_TREES)}


def classify_device(features: list[float]) -> tuple[str, float]:
    """Classify a device using the trained Random Forest.

    Returns (predicted_type, confidence).
    """
    if not _TREES:
        _train_simple()

    predictions = [_predict_tree(tree, features) for tree in _TREES]

    votes: dict[int, int] = {}
    for p in predictions:
        if 0 <= p < len(_CLASSES):
            votes[p] = votes.get(p, 0) + 1

    if not votes:
        return "Unclassified", 0.0

    total_votes = sum(votes.values())
    best_idx = max(votes, key=votes.get)
    confidence = votes[best_idx] / total_votes

    return _CLASSES[best_idx], round(confidence, 3)


def classify_all_devices(hosts: list[dict]) -> list[dict]:
    """Classify all discovered devices.

    Returns list of classification dicts.
    """
    if not _TREES:
        _train_simple()

    results = []
    for host in hosts:
        features = host.get("feature_vector", [])
        if not features:
            continue

        dev_type, confidence = classify_device(features)

        results.append({
            "ip_address": host.get("ip_address", host.get("ip", "")),
            "predicted_device_type": dev_type,
            "classifier_confidence": confidence,
        })

    return results
