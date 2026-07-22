"""Main Wireless Intelligence Engine — orchestrates all wireless submodules."""

from __future__ import annotations

import logging
import os
import time

from .models import (
    WirelessReport, AccessPoint, EnumeratedClient, AuthAnalysis,
    MACCloningPoC, AIAnomalyDetection, AnomalousDevice,
)
from .ap_enum import enumerate_aps
from .vendor_fingerprint import lookup_ap_vendor
from .client_enum import enumerate_clients
from .auth_analysis import analyze_authentication
from .mac_cloning import clone_mac
from .anomaly_detector import detect_anomalies

logger = logging.getLogger(__name__)


class WirelessIntelligenceEngine:
    """Automated wireless security assessment engine for ANISAS Module 5.

    Usage:
        engine = WirelessIntelligenceEngine()
        report = engine.run()
        print(report.model_dump_json(indent=2))
    """

    def __init__(
        self,
        interface: str | None = None,
        dry_run: bool = True,
        target_bssid: str | None = None,
    ):
        self.interface = interface
        self.dry_run = dry_run
        self.target_bssid = target_bssid

    def run(
        self,
        *,
        json_output: str | None = None,
        module2_data: dict | None = None,
    ) -> WirelessReport:
        """Execute the full wireless intelligence pipeline.

        Args:
            json_output: Optional path to write the JSON report.
            module2_data: Optional Module 2 data for supplemental info.

        Returns:
            Populated WirelessReport.
        """
        start = time.monotonic()

        # Step 1: AP Enumeration
        logger.info("[1/6] Enumerating Access Points ...")
        raw_aps = enumerate_aps()

        # Enrich APs with vendor info
        ap_models: list[AccessPoint] = []
        for ap in raw_aps:
            vendor = lookup_ap_vendor(ap.get("bssid", ""))
            ap_models.append(AccessPoint(
                ssid=ap.get("ssid", ""),
                bssid=ap.get("bssid", ""),
                channel=ap.get("channel", 0),
                signal_rssi=ap.get("signal_rssi", 0),
                encryption_type=ap.get("encryption_type", "Unknown"),
                vendor_oui=vendor,
            ))

        logger.info("Found %d Access Points.", len(ap_models))

        # Step 2: Client Enumeration
        logger.info("[2/6] Enumerating clients (ARP/DHCP) ...")
        raw_clients = enumerate_clients()

        # Merge with Module 2 host data if available
        if module2_data:
            for host in module2_data.get("active_hosts", []):
                mac = host.get("mac_address")
                ip = host.get("ip_address")
                if mac:
                    raw_clients.append({
                        "mac_address": mac,
                        "assigned_ip": ip,
                        "status": "ACTIVE",
                        "hostname": None,
                    })

        # Deduplicate
        seen_macs: set[str] = set()
        unique_clients: list[dict] = []
        for c in raw_clients:
            key = c.get("mac_address", "").lower()
            if key and key not in seen_macs:
                seen_macs.add(key)
                unique_clients.append(c)

        client_models = [
            EnumeratedClient(
                mac_address=c["mac_address"],
                assigned_ip=c.get("assigned_ip"),
                status=c.get("status", "ACTIVE"),
                last_seen_timestamp=c.get("last_seen_timestamp"),
                hostname=c.get("hostname"),
            )
            for c in unique_clients
        ]

        logger.info("Enumerated %d clients.", len(client_models))

        # Step 3: Authentication Analysis
        logger.info("[3/6] Analyzing authentication mechanisms ...")
        auth_result = analyze_authentication(raw_aps, unique_clients)

        # Step 4: MAC Cloning PoC
        logger.info("[4/6] MAC cloning proof-of-concept ...")
        inactive_clients = [c for c in unique_clients if c.get("status") == "INACTIVE"]
        target_mac = inactive_clients[0]["mac_address"] if inactive_clients else None

        clone_result = {}
        if target_mac:
            clone_result = clone_mac(
                target_mac,
                interface=self.interface,
                dry_run=self.dry_run,
            )
        else:
            clone_result = {
                "target_inactive_mac": None,
                "lab_interface_used": self.interface or "auto-detected",
                "cloning_successful": False,
                "access_granted_post_clone": False,
                "details": "No inactive clients found for cloning demonstration.",
            }

        # Step 5: AI Anomaly Detection
        logger.info("[5/6] Running AI anomaly detection ...")
        anomaly_result = detect_anomalies(unique_clients)

        # Step 6: Build Hardening Recommendations
        logger.info("[6/6] Generating recommendations ...")
        recommendations = self._generate_recommendations(
            ap_models, auth_result, anomaly_result
        )

        # Build report
        mac_poc = MACCloningPoC(
            target_inactive_mac=clone_result.get("target_inactive_mac"),
            lab_interface_used=clone_result.get("lab_interface_used", ""),
            cloning_successful=clone_result.get("cloning_successful", False),
            access_granted_post_clone=clone_result.get("access_granted_post_clone", False),
        )

        anomaly_models = [
            AnomalousDevice(
                mac_address=a["mac_address"],
                anomaly_score=a["anomaly_score"],
                reason=a["reason"],
            )
            for a in anomaly_result.get("anomalous_devices_flagged", [])
        ]

        ai_detection = AIAnomalyDetection(
            total_devices_clustered=anomaly_result.get("total_devices_clustered", 0),
            anomalous_devices_flagged=anomaly_models,
        )

        report = WirelessReport(
            access_points=ap_models,
            enumerated_clients=client_models,
            authentication_analysis=AuthAnalysis(**auth_result),
            mac_cloning_proof_of_concept=mac_poc,
            ai_anomaly_detection=ai_detection,
            hardening_recommendations=recommendations,
        )

        # Output
        if json_output:
            os.makedirs(os.path.dirname(json_output) or ".", exist_ok=True)
            with open(json_output, "w", encoding="utf-8") as f:
                f.write(report.model_dump_json(indent=2))
            logger.info("JSON report written to %s", json_output)

        elapsed = time.monotonic() - start
        logger.info("Wireless intelligence completed in %.2f seconds.", elapsed)

        return report

    @staticmethod
    def _generate_recommendations(
        aps: list[AccessPoint],
        auth: dict,
        anomalies: dict,
    ) -> list[str]:
        """Generate hardening recommendations based on findings."""
        recs: list[str] = []

        # Encryption recommendations
        open_aps = [a for a in aps if a.encryption_type == "OPEN"]
        if open_aps:
            recs.append(
                f"CRITICAL: {len(open_aps)} open (unencrypted) APs detected. "
                "Immediately enable WPA3-SAE or WPA2-PSK with strong passphrases."
            )

        wpa1_aps = [a for a in aps if a.encryption_type == "WPA-PSK"]
        if wpa1_aps:
            recs.append(
                f"HIGH: {len(wpa1_aps)} APs using WPA-PSK (deprecated). "
                "Upgrade to WPA3-SAE or WPA2-PSK minimum."
            )

        # MAC filtering
        if auth.get("mac_filtering_detected"):
            recs.append(
                "HIGH: MAC address filtering detected as primary access control. "
                "MAC addresses are easily spoofed. Deploy 802.1X instead."
            )

        # Anomalous devices
        anomalous = anomalies.get("anomalous_devices_flagged", [])
        if anomalous:
            recs.append(
                f"MEDIUM: {len(anomalous)} anomalous device(s) detected via behavioral analysis. "
                "Investigate MAC addresses: "
                + ", ".join(a["mac_address"] for a in anomalous[:5])
            )

        # General best practices
        recs.extend([
            "Deploy WPA3-Enterprise with 802.1X EAP-TLS certificate-based authentication.",
            "Enable wireless intrusion detection/prevention system (WIDS/WIPS).",
            "Implement network segmentation isolating wireless from critical infrastructure.",
            "Disable SSID broadcasting for sensitive networks (security through obscurity, supplementary only).",
            "Enable MAC address randomization awareness — legitimate clients may rotate MACs.",
            "Regularly rotate PSK passphrases and audit RADIUS server logs.",
        ])

        return recs
