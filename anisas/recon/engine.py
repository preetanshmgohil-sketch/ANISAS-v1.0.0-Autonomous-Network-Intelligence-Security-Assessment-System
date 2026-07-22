"""Main Network Reconnaissance Engine — orchestrates all recon submodules."""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import time

from .models import ReconReport
from .subnet_enum import enumerate_subnets, generate_host_ips
from .host_discovery import discover_hosts_in_subnet
from .port_scan import scan_all_hosts_ports
from .fingerprint import fingerprint_all_hosts
from .topology import build_topology
from .stealth import StealthConfig

logger = logging.getLogger(__name__)


class NetworkReconEngine:
    """Automated network reconnaissance engine for ANISAS Module 2.

    Usage:
        engine = NetworkReconEngine()
        report = engine.run("10.0.0.0/24")
        print(report.model_dump_json(indent=2))
    """

    def __init__(
        self,
        max_prefix_len: int = 28,
        stealth: StealthConfig | None = None,
    ):
        self.max_prefix_len = max_prefix_len
        self.stealth = stealth or StealthConfig()

    def run(
        self,
        target: str,
        *,
        json_output: str | None = None,
        pdf_output: str | None = None,
    ) -> ReconReport:
        """Execute the full reconnaissance pipeline.

        Args:
            target: A CIDR prefix (e.g., "10.0.0.0/24") or comma-separated
                    list of prefixes. If a Module 1 JSON file path is given,
                    prefixes are extracted from it.
            json_output: Optional path to write the JSON report.

        Returns:
            Populated ReconReport.
        """
        start = time.monotonic()

        # Parse input — could be CIDR(s) or a JSON file path
        prefixes = self._parse_input(target)

        if not prefixes:
            raise ValueError(f"No valid CIDR prefixes found in input: {target}")

        # Use the first prefix as the target for the report
        target_prefix = prefixes[0] if len(prefixes) == 1 else self._aggregate_prefix(prefixes)

        # Step 1: Subnet Enumeration
        logger.info("[1/5] Enumerating subnets from %d prefixes ...", len(prefixes))
        subnets = enumerate_subnets(prefixes, self.max_prefix_len)

        # Step 2: Host Discovery
        logger.info("[2/5] Discovering hosts across %d subnets ...", len(subnets))
        all_hosts: list[dict] = []
        for subnet in subnets:
            hosts = discover_hosts_in_subnet(subnet, self.stealth)
            all_hosts.extend(hosts)
            logger.debug("  %s: %d hosts found", subnet, len(hosts))

        # Step 3: Port Scanning
        logger.info("[3/5] Scanning ports on %d active hosts ...", len(all_hosts))
        host_ips = [h["ip"] for h in all_hosts]
        port_results = scan_all_hosts_ports(host_ips, self.stealth)

        # Step 4: OS/Device Fingerprinting
        logger.info("[4/5] Fingerprinting devices ...")
        enriched_hosts = fingerprint_all_hosts(all_hosts, port_results)

        # Step 5: Topology Generation
        logger.info("[5/5] Building topology graph ...")
        topology = build_topology(target_prefix, subnets, enriched_hosts)

        elapsed = time.monotonic() - start

        # Build report
        from .models import DiscoveredSubnet, ActiveHost, OSFingerprint, OpenPort, TopoNode, TopoEdge, ScanMetadata

        subnet_models = [
            DiscoveredSubnet(cidr=s, vlan_detected=False, estimated_vlan_id=None)
            for s in subnets
        ]

        host_models = []
        for h in enriched_hosts:
            os_data = h.get("os_fingerprint", {})
            ports_data = [
                OpenPort(
                    port=p["port"],
                    protocol=p.get("protocol", "tcp"),
                    service=p.get("service", ""),
                    banner=p.get("banner"),
                )
                for p in h.get("open_ports", [])
            ]
            host_models.append(ActiveHost(
                ip_address=h["ip_address"],
                mac_address=h.get("mac_address"),
                status="up",
                discovery_method=h.get("discovery_method", "ICMP"),
                os_fingerprint=OSFingerprint(
                    predicted_os=os_data.get("predicted_os", "Unknown"),
                    initial_ttl=os_data.get("initial_ttl", 0),
                    tcp_window_size=os_data.get("tcp_window_size"),
                ),
                open_ports=ports_data,
            ))

        topo_nodes = [TopoNode(id=n["id"], type=n["type"]) for n in topology.get("nodes", [])]
        topo_edges = [TopoEdge(source=e["source"], target=e["target"]) for e in topology.get("edges", [])]

        report = ReconReport(
            target_prefix=target_prefix,
            discovered_subnets=subnet_models,
            active_hosts=host_models,
            topology_graph={"nodes": topo_nodes, "edges": topo_edges},
            scan_metadata=ScanMetadata(
                stealth_mode_enabled=self.stealth.enabled,
                total_hosts_found=len(host_models),
                scan_duration_seconds=round(elapsed, 3),
            ),
        )

        # Output
        if json_output:
            os.makedirs(os.path.dirname(json_output) or ".", exist_ok=True)
            with open(json_output, "w", encoding="utf-8") as f:
                f.write(report.model_dump_json(indent=2))
            logger.info("JSON report written to %s", json_output)

        logger.info("Recon pipeline completed in %.2f seconds.", elapsed)
        return report

    def _parse_input(self, target: str) -> list[str]:
        """Parse input — CIDR string, comma-separated CIDRs, or JSON file path."""
        target = target.strip()

        # Check if it's a file path
        if os.path.isfile(target):
            return self._load_prefixes_from_json(target)

        # Check if comma-separated
        if "," in target:
            parts = [p.strip() for p in target.split(",")]
            return [p for p in parts if self._is_valid_cidr(p)]

        # Single CIDR
        if self._is_valid_cidr(target):
            return [target]

        return []

    def _load_prefixes_from_json(self, path: str) -> list[str]:
        """Extract ip_prefixes from a Module 1 JSON report."""
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            prefixes = data.get("ip_prefixes", [])
            return [p for p in prefixes if self._is_valid_cidr(p)]
        except (json.JSONDecodeError, FileNotFoundError) as exc:
            logger.error("Failed to load JSON: %s", exc)
            return []

    @staticmethod
    def _is_valid_cidr(s: str) -> bool:
        try:
            ipaddress.ip_network(s, strict=False)
            return True
        except ValueError:
            return False

    @staticmethod
    def _aggregate_prefix(prefixes: list[str]) -> str:
        """Return the first prefix as the target identifier."""
        return prefixes[0]
