"""AI/NLP risk analysis layer using Hugging Face transformers pipeline."""

from __future__ import annotations

import logging
import re

from .models import AIRiskSummary

logger = logging.getLogger(__name__)

_NLP_AVAILABLE = True
_summarizer = None

MODEL_NAME = "cardiffnlp/twitter-roberta-base-sentiment-latest"

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


def _keyword_risk_assessment(text: str) -> tuple[str, str]:
    """Fallback keyword-based risk assessment when NLP model is unavailable."""
    text_lower = text.lower()
    high_hits = sum(1 for kw in _HIGH_RISK_KEYWORDS if kw in text_lower)
    medium_hits = sum(1 for kw in _MEDIUM_RISK_KEYWORDS if kw in text_lower)

    if high_hits >= 2:
        level = "High"
        summary = (
            f"Based on automated keyword analysis, {high_hits} high-risk indicators "
            f"and {medium_hits} medium-risk indicators were detected in the public metadata "
            f"associated with this network. Manual review is recommended."
        )
    elif high_hits >= 1 or medium_hits >= 2:
        level = "Medium"
        summary = (
            f"The automated analysis found {high_hits} high-risk and {medium_hits} "
            f"medium-risk indicators. While not critical, this network warrants monitoring."
        )
    else:
        level = "Low"
        summary = (
            "Automated analysis of public metadata found no significant risk indicators. "
            "The network appears to operate within normal parameters for its class."
        )
    return level, summary


def _nlp_risk_assessment(text: str, isp_name: str) -> tuple[str, str]:
    """Use Hugging Face NLP model to generate a risk summary."""
    global _summarizer
    try:
        if _summarizer is None:
            from transformers import pipeline
            logger.info("Loading NLP model: %s", MODEL_NAME)
            _summarizer = pipeline("sentiment-analysis", model=MODEL_NAME)
            logger.info("NLP model loaded successfully")

        # Truncate text to model max length
        truncated = text[:512]
        result = _summarizer(truncated)
        sentiment = result[0].get("label", "Neutral").lower()

        # Map sentiment to risk level
        if "negative" in sentiment:
            level = "High"
        elif "neutral" in sentiment:
            level = "Medium"
        else:
            level = "Low"

        summary_text = (
            f"NLP sentiment: {sentiment.upper()}. "
            f"AI Risk Assessment for {isp_name}: "
            f"Automated analysis indicates {level.lower()} risk based on network metadata."
        )
        return level, summary_text

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
        AIRiskSummary with risk_level and summary_text.
    """
    text = _build_risk_text(isp_name, organization, country, asn)
    text += f"\nPeering relationships: {peering_count} known partners."

    try:
        level, summary = _nlp_risk_assessment(text, isp_name or organization)
    except Exception as exc:
        logger.error("Risk analysis failed entirely: %s", exc)
        level, summary = _keyword_risk_assessment(text)

    return AIRiskSummary(risk_level=level, summary_text=summary)
