"""AI text classifier for device type identification from banners and titles."""

from __future__ import annotations

import logging
import re

logger = logging.getLogger(__name__)

# Feature keywords for classification
_CAMERA_KEYWORDS = [
    "camera", "ipc", "cctv", "dome", "bullet", "ptz", "hikvision",
    "dahua", "axis", "reolink", "uniview", "cp plus", "nvr", "dvr",
    "video", "stream", "rtsp", "live", "view", "onvif",
]

_NVR_KEYWORDS = [
    "nvr", "network video recorder", "recorder", "storage",
    "hdd", "disk", "channel", "record",
]

_DVR_KEYWORDS = [
    "dvr", "digital video recorder", "recorder", "analog",
    "bnc", "coaxial", "legacy",
]

_IOT_KEYWORDS = [
    "sensor", "thermostat", "hub", "gateway", "smart",
    "wifi", "bluetooth", "zigbee", "z-wave", "mqtt",
]

# Synthetic training data: (text, label)
_TRAINING_DATA: list[tuple[str, str]] = [
    ("Hikvision IPC Camera Login", "CCTV Camera"),
    ("Dahua Web Login - Network Camera", "CCTV Camera"),
    ("Axis Communications Network Camera", "CCTV Camera"),
    ("Reolink RLN8-410 NVR Interface", "NVR"),
    ("Hikvision DS-7600 Series NVR", "NVR"),
    ("Dahua NVR Web Interface", "NVR"),
    ("DVR Login Page - Admin", "DVR"),
    ("XVR Hybrid Video Recorder", "XVR"),
    ("CP Plus XVR Login", "XVR"),
    ("Smart Home Hub - Control Panel", "Generic IoT"),
    ("ESP32-CAM Live Stream", "CCTV Camera"),
    ("Network Video Recorder 16 Channel", "NVR"),
    ("DVR 4 Channel Analog Recorder", "DVR"),
    ("IP Camera System - Live View", "CCTV Camera"),
    ("Uniview NVR Web Interface", "NVR"),
    ("Dahua XVR 5-in-1 Recorder", "XVR"),
    ("Hikvision DS-2CD Series Camera", "CCTV Camera"),
    ("Ubiquiti UniFi Video Camera", "CCTV Camera"),
    ("Bosch IP Camera Configuration", "CCTV Camera"),
    ("Motion Sensor Gateway", "Generic IoT"),
]

# Pre-computed keyword frequency model (no sklearn dependency needed)
_KEYWORD_MODEL: dict[str, dict[str, int]] = {}


def _build_keyword_model() -> None:
    """Build a simple keyword frequency model from training data."""
    global _KEYWORD_MODEL
    labels = ["CCTV Camera", "NVR", "DVR", "XVR", "Generic IoT"]
    for label in labels:
        _KEYWORD_MODEL[label] = {"count": 0}

    for text, label in _TRAINING_DATA:
        words = re.findall(r"[a-z0-9]+", text.lower())
        for word in words:
            _KEYWORD_MODEL.setdefault(label, {})
            _KEYWORD_MODEL[label][word] = _KEYWORD_MODEL[label].get(word, 0) + 1
        _KEYWORD_MODEL[label]["count"] = _KEYWORD_MODEL[label].get("count", 0) + 1


_build_keyword_model()


def _tokenize(text: str) -> list[str]:
    return re.findall(r"[a-z0-9]+", text.lower())


def classify_text(text: str) -> dict:
    """Classify text (banner/title) into device category.

    Uses a simple Naive Bayes approach with keyword probabilities.

    Returns dict with classification, confidence, scores.
    """
    if not text:
        return {"classification": "Generic IoT", "confidence": 0.0, "scores": {}}

    tokens = _tokenize(text)
    if not tokens:
        return {"classification": "Generic IoT", "confidence": 0.0, "scores": {}}

    scores: dict[str, float] = {}
    total_samples = sum(_KEYWORD_MODEL.get(l, {}).get("count", 0) for l in _KEYWORD_MODEL)

    for label, word_counts in _KEYWORD_MODEL.items():
        label_count = word_counts.get("count", 0)
        if label_count == 0:
            scores[label] = 0.0
            continue

        log_prob = 0.0
        vocab_size = max(len(word_counts) - 1, 1)

        for token in tokens:
            token_count = word_counts.get(token, 0)
            # Laplace smoothing
            prob = (token_count + 1) / (label_count + vocab_size)
            log_prob += prob

        scores[label] = log_prob

    # Normalize to probabilities
    max_score = max(scores.values()) if scores else 0
    if max_score > 0:
        total = sum(max(0, s) for s in scores.values())
        if total > 0:
            scores = {k: round(max(0, v) / total, 3) for k, v in scores.items()}

    best_label = max(scores, key=lambda k: scores.get(k, 0))
    confidence = scores.get(best_label, 0)

    return {
        "classification": best_label,
        "confidence": round(confidence, 3),
        "scores": scores,
    }


def classify_device_ai(
    title: str | None,
    rtsp_banner: str | None,
    http_server: str | None,
    oui_vendor: str | None,
) -> dict:
    """AI-powered device classification from all available text signals.

    Returns dict with classification, confidence, rationale.
    """
    texts = []
    if title:
        texts.append(title)
    if rtsp_banner:
        texts.append(rtsp_banner)
    if http_server:
        texts.append(http_server)
    if oui_vendor and oui_vendor != "Unknown":
        texts.append(oui_vendor)

    combined_text = " ".join(texts)

    # Direct keyword matching first
    combined_lower = combined_text.lower()
    if any(kw in combined_lower for kw in ["nvr", "network video recorder"]):
        return {"classification": "NVR", "confidence": 0.9, "rationale": "NVR keyword detected in text."}
    if any(kw in combined_lower for kw in ["dvr", "digital video recorder"]):
        return {"classification": "DVR", "confidence": 0.85, "rationale": "DVR keyword detected in text."}
    if any(kw in combined_lower for kw in ["xvr", "hybrid recorder"]):
        return {"classification": "XVR", "confidence": 0.85, "rationale": "XVR keyword detected in text."}

    # ML classification
    result = classify_text(combined_text)

    rationale = f"AI classifier analyzed '{combined_text[:80]}...' with {result['confidence']:.0%} confidence."

    return {
        "classification": result["classification"],
        "confidence": result["confidence"],
        "rationale": rationale,
    }
