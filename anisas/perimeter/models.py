"""Pydantic data models for Security Perimeter Detection output."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field


class FirewallInfo(BaseModel):
    detected: bool = False
    type: Literal["Stateful", "Stateless", "None"] = "None"
    filtering_behavior: Literal["Filtered", "Unfiltered", "Open-Filtered"] = "Unfiltered"


class IDSIPSInfo(BaseModel):
    detected: bool = False
    action_observed: Literal["TCP-RST", "Drop", "ICMP-Unreachable", "None"] = "None"


class DMZInfo(BaseModel):
    detected: bool = False
    exposure_boundary: Literal["Public-DMZ", "Internal-Only", "Hybrid"] = "Internal-Only"


class WAFInfo(BaseModel):
    detected: bool = False
    vendor: str = Field(default="Unknown", description="Identified WAF vendor")
    matched_signatures: list[str] = Field(default_factory=list)


class EvasionBenchmarks(BaseModel):
    fragmentation_tested: bool = False
    slow_rate_timing_effective: bool = False
    documented_mechanisms: list[str] = Field(default_factory=list)


class AIDetectionPrediction(BaseModel):
    probe_type_evaluated: str = ""
    predicted_detection_probability: float = Field(default=0.0, ge=0.0, le=1.0)
    recommendation: str = ""


class OverallPosture(BaseModel):
    risk_level: Literal["Low", "Medium", "High"] = "Medium"
    summary: str = ""


class PerimeterReport(BaseModel):
    target_ip: str
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    perimeter_defenses: dict = Field(default_factory=lambda: {
        "firewall": FirewallInfo().model_dump(),
        "ids_ips": IDSIPSInfo().model_dump(),
        "dmz": DMZInfo().model_dump(),
        "waf": WAFInfo().model_dump(),
    })
    evasion_benchmarks: EvasionBenchmarks = Field(default_factory=EvasionBenchmarks)
    ai_detection_prediction: AIDetectionPrediction = Field(default_factory=AIDetectionPrediction)
    overall_security_posture: OverallPosture = Field(default_factory=OverallPosture)
