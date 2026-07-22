"""Pydantic data models for Wireless Network Intelligence output."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field


class AccessPoint(BaseModel):
    ssid: str = ""
    bssid: str = ""
    channel: int = 0
    signal_rssi: int = Field(default=0, description="Signal strength in dBm")
    encryption_type: Literal["OPEN", "WPA2-PSK", "WPA3-SAE", "802.1X", "WPA-PSK", "Unknown"] = "Unknown"
    vendor_oui: str = Field(default="Unknown", description="Vendor from OUI lookup")


class EnumeratedClient(BaseModel):
    mac_address: str
    assigned_ip: str | None = None
    status: Literal["ACTIVE", "INACTIVE"] = "ACTIVE"
    last_seen_timestamp: str | None = None
    hostname: str | None = None


class AuthAnalysis(BaseModel):
    primary_auth_method: str = ""
    mac_filtering_detected: bool = False
    vulnerability_assessment: str = ""


class MACCloningPoC(BaseModel):
    target_inactive_mac: str | None = None
    lab_interface_used: str = ""
    cloning_successful: bool = False
    access_granted_post_clone: bool = False


class AnomalousDevice(BaseModel):
    mac_address: str
    anomaly_score: float = Field(default=0.0, ge=0.0, le=1.0)
    reason: str = ""


class AIAnomalyDetection(BaseModel):
    total_devices_clustered: int = 0
    anomalous_devices_flagged: list[AnomalousDevice] = Field(default_factory=list)


class WirelessReport(BaseModel):
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    access_points: list[AccessPoint] = Field(default_factory=list)
    enumerated_clients: list[EnumeratedClient] = Field(default_factory=list)
    authentication_analysis: AuthAnalysis = Field(default_factory=AuthAnalysis)
    mac_cloning_proof_of_concept: MACCloningPoC = Field(default_factory=MACCloningPoC)
    ai_anomaly_detection: AIAnomalyDetection = Field(default_factory=AIAnomalyDetection)
    hardening_recommendations: list[str] = Field(default_factory=list)
