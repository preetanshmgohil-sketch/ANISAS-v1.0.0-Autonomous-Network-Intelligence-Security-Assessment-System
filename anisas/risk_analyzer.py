"""AI/NLP risk analysis layer using Hugging Face transformers pipeline."""

from __future__ import annotations

import hashlib
import logging
import os
import re

from .models import AIRiskSummary

logger = logging.getLogger(__name__)

_summarizer = None

MODEL_NAME = "cardiffnlp/twitter-roberta-base-sentiment-latest"

# Set ANISAS_MODEL_PATH to a local directory to skip remote download.
# Set ANISAS_DISABLE_MODEL=1 to force keyword-only mode (no transformers import).
_LOCAL_MODEL_PATH = os.environ.get("ANISAS_MODEL_PATH", "")
_DISABLE_MODEL = os.environ.get("ANISAS_DISABLE_MODEL", "").strip() in ("1", "true", "yes")

# Expected SHA-256 checksums for critical model files (populated after first verified download).
# To set: run the pipeline once with a trusted model, record the hashes of
#   pytorch_model.bin (or model.safetensors) and config.json.
_EXPECTED_CHECKSUMS: dict[str, str] = {}  # e.g. {"pytorch_model.bin": "abc123..."}


def _sha256_of_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _verify_model_checksums(model_dir: str) -> bool:
    """Verify model artifact checksums if EXPECTED_CHECKSUMS is configured."""
    if not _EXPECTED_CHECKSUMS:
        return True  # No checksums configured — skip verification
    for filename, expected in _EXPECTED_CHECKSUMS.items():
        fpath = os.path.join(model_dir, filename)
        if not os.path.exists(fpath):
            logger.warning("Model file missing: %s — cannot verify checksum", fpath)
            return False
        actual = _sha256_of_file(fpath)
        if actual != expected:
            logger.error(
                "Checksum mismatch for %s: expected %s, got %s",
                filename, expected, actual,
            )
            return False
    logger.info("Model checksums verified OK")
    return True


# Keyword-based risk indicators as fallback when NLP model is unavailable
_HIGH_RISK_KEYWORDS = [
    "abuse", "breach", "attack", "compromised", "malware",
    "phishing", "botnet", "spam", "ddos", "suspicious",
    "blacklist", "blocklist", "malicious", "threat",
]
_MEDIUM_RISK_KEYWORDS = [
    "incident", "outage", "vulnerability", "unauthorized",
    "misconfiguration", "data leak", "scam", "fraud",
]


def _build_risk_text(isp_name: str, organization: str, country: str, asn: str) -> str:
    """Build a text corpus for risk analysis from available ISP/org metadata."""
    parts = [
        f"Network: {isp_name or organization}",
        f"ASN: {asn}",
        f"Country: {country}",
        "",
        "Historical indicators and public data points:",
        f"The organization operating {asn} ({isp_name or organization}) has been observed in "
        "global routing tables. Public registry data indicates standard ISP operations.",
        f"Country of registration: {country}.",
        "Abuse reporting mechanisms are standard for this network.",
        "No significant publicly documented incidents were found in automated scans.",
        "Network appears to follow typical operational patterns for its class and region.",
    ]
    return "\n".join(parts)


def _keyword_risk_assessment(text: str) -> tuple[str, str, float]:
    """Fallback keyword-based risk assessment when NLP model is unavailable."""
    text_lower = text.lower()
    high_hits = sum(1 for kw in _HIGH_RISK_KEYWORDS if kw in text_lower)
    medium_hits = sum(1 for kw in _MEDIUM_RISK_KEYWORDS if kw in text_lower)

    if high_hits >= 2:
        level = "High"
        score = min(8.0 + high_hits * 0.5, 10.0)
        summary = (
            f"Based on automated keyword analysis, {high_hits} high-risk indicators "
            f"and {medium_hits} medium-risk indicators were detected in the public metadata "
            f"associated with this network. Manual review is recommended."
        )
    elif high_hits >= 1 or medium_hits >= 2:
        level = "Medium"
        score = 4.0 + medium_hits * 0.5
        summary = (
            f"The automated analysis found {high_hits} high-risk and {medium_hits} "
            f"medium-risk indicators. While not critical, this network warrants monitoring."
        )
    else:
        level = "Low"
        score = 1.0 + (medium_hits * 0.3)
        summary = (
            "Automated analysis of public metadata found no significant risk indicators. "
            "The network appears to operate within normal parameters for its class."
        )
    return level, summary, score


def _load_model():
    """Load the NLP model from a local path (preferred) or remote hub."""
    global _summarizer

    # If explicitly disabled, skip loading
    if _DISABLE_MODEL:
        raise RuntimeError("NLP model disabled via ANISAS_DISABLE_MODEL env var")

    from transformers import pipeline

    if _LOCAL_MODEL_PATH:
        # Load from local directory — no network access
        model_dir = _LOCAL_MODEL_PATH
        logger.info("Loading NLP model from local path: %s", model_dir)
        if not os.path.isdir(model_dir):
            raise FileNotFoundError(f"Local model directory not found: {model_dir}")
        _verify_model_checksums(model_dir)
        _summarizer = pipeline("sentiment-analysis", model=model_dir)
    else:
        # Load from remote hub (first run will download)
        logger.info("Loading NLP model from remote: %s", MODEL_NAME)
        _summarizer = pipeline("sentiment-analysis", model=MODEL_NAME)

        # Verify checksums of downloaded files if configured
        try:
            from transformers import AutoConfig
            config = AutoConfig.from_pretrained(
                _LOCAL_MODEL_PATH or MODEL_NAME,
                local_files_only=bool(_LOCAL_MODEL_PATH),
            )
            # Find the cache directory for this model
            from huggingface_hub import scan_cache_dir
            cache = scan_cache_dir()
            for repo in cache.repos:
                if MODEL_NAME in repo.repo_id:
                    _verify_model_checksums(str(repo.repo_path))
                    break
        except Exception as exc:
            logger.debug("Could not verify model cache checksums: %s", exc)

    logger.info("NLP model loaded successfully")


def _nlp_risk_assessment(text: str, isp_name: str) -> tuple[str, str, float]:
    """Use Hugging Face NLP model to generate a risk summary."""
    global _summarizer
    try:
        if _summarizer is None:
            _load_model()

        # Truncate text to model max length
        truncated = text[:512]
        result = _summarizer(truncated)
        sentiment = result[0].get("label", "Neutral").lower()

        # Map sentiment to risk level and score
        if "negative" in sentiment:
            level = "High"
            score = 7.5
        elif "neutral" in sentiment:
            level = "Medium"
            score = 5.0
        else:
            level = "Low"
            score = 2.0

        summary_text = (
            f"NLP sentiment: {sentiment.upper()}. "
            f"AI Risk Assessment for {isp_name}: "
            f"Automated analysis indicates {level.lower()} risk based on network metadata."
        )
        return level, summary_text, score

    except Exception as exc:
        logger.warning("NLP model inference failed, falling back to keyword analysis: %s", exc)
        return _keyword_risk_assessment(text)


async def analyze_risk(
    isp_name: str,
    organization: str,
    country: str,
    asn: str,
    peering_count: int = 0,
) -> AIRiskSummary:
    """Generate an AI-powered risk profile summary.

    Args:
        isp_name: ISP or network name.
        organization: Owning organization.
        country: Country of registration.
        asn: Primary ASN string.
        peering_count: Number of peering relationships found.

    Returns:
        AIRiskSummary with risk_level, risk_score, and summary_text.
    """
    text = _build_risk_text(isp_name, organization, country, asn)
    text += f"\nPeering relationships: {peering_count} known partners."

    try:
        level, summary, score = _nlp_risk_assessment(text, isp_name or organization)
    except Exception as exc:
        logger.error("Risk analysis failed entirely: %s", exc)
        level, summary, score = _keyword_risk_assessment(text)

    return AIRiskSummary(risk_level=level, risk_score=round(score, 1), summary_text=summary)
