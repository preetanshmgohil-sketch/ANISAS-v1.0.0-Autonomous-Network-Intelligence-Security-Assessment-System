"""Pydantic data models for the Network Reconnaissance Engine output."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field


class DiscoveredSubnet(BaseModel):
    cidr: str = Field(..., description="CIDR notation of discovered subnet")
    vlan_detected: bool = Field(default=False)
    estimated_vlan_id: int | None = None


class OSFingerprint(BaseModel):
    predicted_os: Literal["Linux", "Windows", "Embedded/Network", "Unknown"] = "Unknown"
    initial_ttl: int = Field(default=0)
    tcp_window_size: int | None = None


class OpenPort(BaseModel):
    port: int
    protocol: Literal["tcp", "udp"] = "tcp"
    service: str = Field(default="", description="Service name (HTTP, SSH, etc.)")
    banner: str | None = None


class ActiveHost(BaseModel):
    ip_address: str
    mac_address: str | None = None
    status: Literal["up"] = "up"
    discovery_method: Literal["ARP", "ICMP", "TCP-SYN"] = "ICMP"
    os_fingerprint: OSFingerprint = Field(default_factory=OSFingerprint)
    open_ports: list[OpenPort] = Field(default_factory=list)


class TopoNode(BaseModel):
    id: str
    type: Literal["subnet", "gateway", "host"]


class TopoEdge(BaseModel):
    source: str
    target: str


class TopologyGraph(BaseModel):
    nodes: list[TopoNode] = Field(default_factory=list)
    edges: list[TopoEdge] = Field(default_factory=list)


class ScanMetadata(BaseModel):
    stealth_mode_enabled: bool = True
    total_hosts_found: int = 0
    scan_duration_seconds: float = 0.0


class ReconReport(BaseModel):
    target_prefix: str
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    discovered_subnets: list[DiscoveredSubnet] = Field(default_factory=list)
    active_hosts: list[ActiveHost] = Field(default_factory=list)
    topology_graph: TopologyGraph = Field(default_factory=TopologyGraph)
    scan_metadata: ScanMetadata = Field(default_factory=ScanMetadata)
