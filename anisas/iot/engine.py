"""Main IoT Surveillance Engine — orchestrates all fingerprinting submodules."""

from __future__ import annotations

import json
import logging
import os
import time

from .models import IoTReport, SurveillanceDevice, CVEEntry, PredictedIPRange, IoTSummary
from .protocol_scan import scan_hosts_protocols
from .fingerprint import fingerprint_device
from .cve_lookup import lookup_cves, assess_protocol_risks, compute_risk_rating
from .ip_predictor import analyze_ip_clusters
from .ai_classifier import classify_device_ai

logger = logging.getLogger(__name__)


class IoTSurveillanceEngine:
    """Automated surveillance & IoT device fingerprinting engine for ANISAS Module 4.

    Usage:
        engine = IoTSurveillanceEngine()
        report = engine.run("192.168.1.0/24")
        print(report.model_dump_json(indent=2))
    """

    def __init__(self, timeout: float = 2.0):
        self.timeout = timeout

    def run(
        self,
        target: str,
        *,
        json_output: str | None = None,
        module2_data: dict | None = None,
    ) -> IoTReport:
        """Execute the full IoT fingerprinting pipeline.

        Args:
            target: Target subnet CIDR, IP, or Module 2 JSON path.
            json_output: Optional path to write the JSON report.
            module2_data: Pre-parsed Module 2 data dict (optional).

        Returns:
            Populated IoTReport.
        """
        start = time.monotonic()

        # Parse input
        target_subnet, hosts, subnets = self._parse_input(target, module2_data)

        if not hosts:
            raise ValueError(f"No active hosts found for target: {target}")

        logger.info("Scanning %d hosts across %s for surveillance protocols ...", len(hosts), target_subnet)

        # Step 1: Protocol Scanning
        logger.info("[1/4] Running protocol scans (RTSP/HTTP/ONVIF) ...")
        protocol_results = scan_hosts_protocols(hosts, self.timeout)

        # Step 2: Device Fingerprinting
        logger.info("[2/4] Fingerprinting devices ...")
        devices: list[dict] = []
        for proto_data in protocol_results:
            ip = proto_data.get("ip", "")
            if not proto_data.get("protocols_detected"):
                continue  # Skip hosts with no surveillance protocols

            # Find MAC from module2 data if available
            mac = None
            if module2_data:
                for h in module2_data.get("active_hosts", []):
                    if h.get("ip_address") == ip:
                        mac = h.get("mac_address")
                        break

            device = fingerprint_device(ip, mac, proto_data)
            devices.append(device)

        logger.info("Found %d potential surveillance/IoT devices.", len(devices))

        # Step 3: CVE Cross-Referencing
        logger.info("[3/4] Cross-referencing CVEs ...")
        enriched_devices: list[SurveillanceDevice] = []
        for dev in devices:
            # Lookup CVEs
            cves = lookup_cves(dev["identified_vendor"], dev["firmware_version"])

            # Protocol-based risks
            proto_risks = assess_protocol_risks(dev["protocols_detected"])
            cves.extend(proto_risks)

            # AI classification
            ai_result = classify_device_ai(
                dev.get("http_title"),
                dev.get("rtsp_banner"),
                dev.get("headers", {}).get("server"),
                dev["oui_vendor"],
            )

            # Use AI classification if fingerprinting was uncertain
            classification = dev["classification"]
            if classification == "Generic IoT" and ai_result["classification"] != "Generic IoT":
                classification = ai_result["classification"]

            # Compute risk rating
            risk = compute_risk_rating(
                cves,
                dev["protocols_detected"],
                dev["firmware_version"] != "Unknown",
            )

            cve_models = [
                CVEEntry(
                    cve_id=c["cve_id"],
                    severity=c["severity"],
                    cvss_score=c["cvss_score"],
                    description=c["description"],
                )
                for c in cves
            ]

            enriched_devices.append(SurveillanceDevice(
                ip_address=dev["ip_address"],
                mac_address=dev["mac_address"],
                oui_vendor=dev["oui_vendor"],
                classification=classification,
                identified_vendor=dev["identified_vendor"],
                firmware_version=dev["firmware_version"],
                protocols_detected=dev["protocols_detected"],
                http_title=dev.get("http_title"),
                cve_vulnerabilities=cve_models,
                risk_rating=risk,
            ))

        # Step 4: IP Range Prediction
        logger.info("[4/4] Predicting IP ranges ...")
        device_ips = [d.ip_address for d in enriched_devices]
        predicted_ranges = analyze_ip_clusters(device_ips, subnets)
        predicted_models = [
            PredictedIPRange(
                cidr_range=p["cidr_range"],
                probability_score=p["probability_score"],
                rationale=p["rationale"],
            )
            for p in predicted_ranges
        ]

        # Build summary
        critical_count = sum(1 for d in enriched_devices if d.risk_rating == "CRITICAL")
        high_count = sum(1 for d in enriched_devices if d.risk_rating == "HIGH")

        report = IoTReport(
            target_subnet=target_subnet,
            surveillance_devices=enriched_devices,
            predicted_ip_ranges=predicted_models,
            summary=IoTSummary(
                total_iot_devices_found=len(enriched_devices),
                critical_risk_count=critical_count,
                high_risk_count=high_count,
            ),
        )

        # Output
        if json_output:
            os.makedirs(os.path.dirname(json_output) or ".", exist_ok=True)
            with open(json_output, "w", encoding="utf-8") as f:
                f.write(report.model_dump_json(indent=2))
            logger.info("JSON report written to %s", json_output)

        elapsed = time.monotonic() - start
        logger.info("IoT fingerprinting completed in %.2f seconds.", elapsed)

        return report

    def _parse_input(
        self,
        target: str,
        module2_data: dict | None = None,
    ) -> tuple[str, list[str], list[str]]:
        """Parse input to extract target subnet, hosts, and subnets."""
        target = target.strip()

        # Module 2 data provided directly
        if module2_data:
            hosts = [h["ip_address"] for h in module2_data.get("active_hosts", []) if h.get("ip_address")]
            subnets = [s["cidr"] for s in module2_data.get("discovered_subnets", [])]
            target_subnet = module2_data.get("target_prefix", subnets[0] if subnets else "")
            return target_subnet, hosts, subnets

        # File path
        if os.path.isfile(target):
            try:
                with open(target, "r", encoding="utf-8") as f:
                    data = json.load(f)
                if "active_hosts" in data:
                    return self._parse_input(target, data)
                # Module 1 output — limited data
                return data.get("target_ip", target), [], []
            except (json.JSONDecodeError, FileNotFoundError):
                pass

        # CIDR or IP
        import ipaddress
        try:
            net = ipaddress.ip_network(target, strict=False)
            # Generate a small set of IPs for scanning
            hosts = [str(ip) for ip in list(net.hosts())[:20]]
            return str(net), hosts, [str(net)]
        except ValueError:
            # Single IP
            return target, [target], []
