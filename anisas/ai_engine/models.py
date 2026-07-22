"""Pydantic data models for AI/ML Classification & Anomaly Detection output."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field


class DeviceClassification(BaseModel):
    ip_address: str
    predicted_device_type: Literal["Server", "Workstation", "Surveillance Device", "IoT/Embedded", "Network Gear", "Unclassified"] = "Unclassified"
    classifier_confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    predicted_os: str = "Unknown"
    os_confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    calculated_risk_score: float = Field(default=0.0, ge=0.0, le=10.0)
    risk_category: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"] = "LOW"
    is_anomalous: bool = False
    anomaly_reasons: list[str] = Field(default_factory=list)


class TopoNode(BaseModel):
    id: str
    label: str = ""
    type: Literal["subnet", "device", "gateway"] = "device"


class TopoLink(BaseModel):
    source: str
    target: str
    weight: float = 1.0


class InferredTopology(BaseModel):
    nodes: list[TopoNode] = Field(default_factory=list)
    links: list[TopoLink] = Field(default_factory=list)


class ExecutiveNLSummary(BaseModel):
    overview_paragraph: str = ""
    key_threats_identified: list[str] = Field(default_factory=list)
    recommended_mitigations: list[str] = Field(default_factory=list)


class AIAnalyticsSummary(BaseModel):
    total_devices_analyzed: int = 0
    anomalies_detected_count: int = 0
    network_health_score: float = Field(default=100.0, ge=0.0, le=100.0)


class AIEngineReport(BaseModel):
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    ai_analytics_summary: AIAnalyticsSummary = Field(default_factory=AIAnalyticsSummary)
    device_classifications: list[DeviceClassification] = Field(default_factory=list)
    inferred_topology: InferredTopology = Field(default_factory=InferredTopology)
    executive_nl_summary: ExecutiveNLSummary = Field(default_factory=ExecutiveNLSummary)
