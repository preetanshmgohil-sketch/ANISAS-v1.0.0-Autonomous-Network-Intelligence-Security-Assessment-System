"""Pydantic data models for Surveillance & IoT Device Fingerprinting output."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field


class CVEEntry(BaseModel):
    cve_id: str
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"] = "LOW"
    cvss_score: float = Field(default=0.0, ge=0.0, le=10.0)
    description: str = ""


class SurveillanceDevice(BaseModel):
    ip_address: str
    mac_address: str | None = None
    oui_vendor: str = Field(default="Unknown", description="OUI vendor from MAC prefix")
    classification: Literal["CCTV Camera", "NVR", "DVR", "XVR", "Generic IoT"] = "Generic IoT"
    identified_vendor: str = Field(default="Unknown")
    firmware_version: str = Field(default="Unknown")
    protocols_detected: list[str] = Field(default_factory=list)
    http_title: str | None = None
    cve_vulnerabilities: list[CVEEntry] = Field(default_factory=list)
    risk_rating: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"] = "LOW"


class PredictedIPRange(BaseModel):
    cidr_range: str
    probability_score: float = Field(default=0.0, ge=0.0, le=1.0)
    rationale: str = ""


class IoTSummary(BaseModel):
    total_iot_devices_found: int = 0
    critical_risk_count: int = 0
    high_risk_count: int = 0


class IoTReport(BaseModel):
    target_subnet: str
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    surveillance_devices: list[SurveillanceDevice] = Field(default_factory=list)
    predicted_ip_ranges: list[PredictedIPRange] = Field(default_factory=list)
    summary: IoTSummary = Field(default_factory=IoTSummary)
