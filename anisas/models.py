"""Pydantic data models for the ANISAS intelligence report."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field


class ASNEntry(BaseModel):
    asn: str = Field(..., description="ASN identifier, e.g. AS15169")
    organization: str = Field(default="", description="Owning organization name")
    country: str = Field(default="", description="Country of registration")
    registry: str = Field(default="", description="Regional Internet Registry (ARIN, RIPE, APNIC, etc.)")
    is_primary: bool = Field(default=False, description="True if primary ASN for target")


class ISPProfile(BaseModel):
    name: str = Field(default="", description="ISP / network name")
    noc_contact: str = Field(default="", description="NOC contact info (email/phone)")
    abuse_contact: str = Field(default="", description="Abuse reporting email/phone")
    peering_relationships: list[str] = Field(default_factory=list, description="Known peering partners")


class AIRiskSummary(BaseModel):
    risk_level: Literal["Low", "Medium", "High"] = Field(default="Low")
    risk_score: float = Field(default=0.0, ge=0.0, le=10.0, description="Numerical risk score 0-10")
    summary_text: str = Field(default="", description="NLP-generated risk summary")


class Provenance(BaseModel):
    sources_queried: list[str] = Field(default_factory=list)
    execution_time_seconds: float = Field(default=0.0)


class ASNIntelligenceReport(BaseModel):
    target_ip: str
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    asn_details: list[ASNEntry] = Field(default_factory=list)
    ip_prefixes: list[str] = Field(default_factory=list)
    isp_profile: ISPProfile = Field(default_factory=ISPProfile)
    ai_risk_summary: AIRiskSummary = Field(default_factory=AIRiskSummary)
    provenance: Provenance = Field(default_factory=Provenance)
