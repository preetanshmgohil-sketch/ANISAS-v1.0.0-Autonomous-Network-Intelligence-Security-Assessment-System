"""Main Security Perimeter Detection Engine — orchestrates all perimeter submodules."""

from __future__ import annotations

import json
import logging
import os
import time

from .models import PerimeterReport
from .firewall import detect_firewall
from .ids_ips import detect_ids_ips
from .dmz import detect_dmz
from .waf import detect_waf
from .evasion import test_evasion_methods
from .ai_detector import train_classifier, predict_detection

logger = logging.getLogger(__name__)


class SecurityPerimeterEngine:
    """Automated security perimeter detection engine for ANISAS Module 3.

    Usage:
        engine = SecurityPerimeterEngine()
        report = engine.run(module2_json_or_ip)
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
    ) -> PerimeterReport:
        """Execute the full perimeter detection pipeline.

        Args:
            target: Target IP address or path to Module 2 JSON report.
            json_output: Optional path to write the JSON report.
            module2_data: Pre-parsed Module 2 data dict (optional).

        Returns:
            Populated PerimeterReport.
        """
        start = time.monotonic()

        # Parse input
        target_ip, discovered_ports = self._parse_input(target, module2_data)

        if not target_ip:
            raise ValueError(f"Could not determine target IP from input: {target}")

        # Step 1: Firewall Detection
        logger.info("[1/5] Detecting firewall on %s ...", target_ip)
        firewall_result = detect_firewall(target_ip, timeout=self.timeout)

        # Step 2: IDS/IPS Detection
        logger.info("[2/5] Detecting IDS/IPS ...")
        ids_result = detect_ids_ips(target_ip, timeout=self.timeout)

        # Step 3: DMZ Detection
        logger.info("[3/5] Detecting DMZ architecture ...")
        dmz_result = detect_dmz(target_ip, discovered_ports, self.timeout)

        # Step 4: WAF Detection
        logger.info("[4/5] Detecting WAF ...")
        waf_result = detect_waf(target_ip, timeout=self.timeout)

        # Step 5: Evasion Benchmarks
        logger.info("[5/5] Running evasion benchmarks ...")
        evasion_result = test_evasion_methods(target_ip, discovered_ports, self.timeout)

        # Train AI classifier
        logger.info("Training AI detection classifier ...")
        training_metrics = train_classifier()

        # Generate AI prediction for standard scan
        ai_prediction = predict_detection(
            probe_type="TCP-SYN",
            burst_rate=50.0,
            timing_ms=50.0,
            port_count=len(discovered_ports) if discovered_ports else 100,
            fragmentation=False,
            decoy_count=0,
        )

        # Determine overall posture
        risk_level, summary = self._assess_posture(
            firewall_result, ids_result, dmz_result, waf_result
        )

        elapsed = time.monotonic() - start

        # Build report
        report = PerimeterReport(
            target_ip=target_ip,
            perimeter_defenses={
                "firewall": {
                    "detected": firewall_result["detected"],
                    "type": firewall_result["type"],
                    "filtering_behavior": firewall_result["filtering_behavior"],
                },
                "ids_ips": {
                    "detected": ids_result["detected"],
                    "action_observed": ids_result["action_observed"],
                },
                "dmz": {
                    "detected": dmz_result["detected"],
                    "exposure_boundary": dmz_result["exposure_boundary"],
                },
                "waf": {
                    "detected": waf_result["detected"],
                    "vendor": waf_result["vendor"],
                    "matched_signatures": waf_result["matched_signatures"],
                },
            },
            evasion_benchmarks={
                "fragmentation_tested": evasion_result["fragmentation_tested"],
                "slow_rate_timing_effective": evasion_result["slow_rate_timing_effective"],
                "documented_mechanisms": evasion_result["documented_mechanisms"],
            },
            ai_detection_prediction=ai_prediction,
            overall_security_posture={
                "risk_level": risk_level,
                "summary": summary,
            },
        )

        # Output
        if json_output:
            os.makedirs(os.path.dirname(json_output) or ".", exist_ok=True)
            with open(json_output, "w", encoding="utf-8") as f:
                f.write(report.model_dump_json(indent=2))
            logger.info("JSON report written to %s", json_output)

        logger.info("Perimeter detection completed in %.2f seconds.", elapsed)
        return report

    def _parse_input(
        self,
        target: str,
        module2_data: dict | None = None,
    ) -> tuple[str, list[int]]:
        """Parse input to extract target IP and discovered ports."""
        target = target.strip()

        # If Module 2 data is provided directly
        if module2_data:
            ip = module2_data.get("active_hosts", [{}])[0].get("ip_address", "")
            ports = []
            for host in module2_data.get("active_hosts", []):
                for p in host.get("open_ports", []):
                    ports.append(p.get("port", 0))
            return ip, list(set(ports))

        # If it's a file path
        if os.path.isfile(target):
            try:
                with open(target, "r", encoding="utf-8") as f:
                    data = json.load(f)
                # Check if it's Module 2 format
                if "active_hosts" in data:
                    return self._parse_input(target, data)
                # Module 1 format — just extract IP
                return data.get("target_ip", ""), []
            except (json.JSONDecodeError, FileNotFoundError):
                pass

        # Assume it's a bare IP address
        import ipaddress
        try:
            ipaddress.ip_address(target)
            return target, []
        except ValueError:
            return "", []

    @staticmethod
    def _assess_posture(
        firewall: dict,
        ids: dict,
        dmz: dict,
        waf: dict,
    ) -> tuple[str, str]:
        """Assess overall security posture from detection results."""
        defenses = sum([
            firewall.get("detected", False),
            ids.get("detected", False),
            dmz.get("detected", False),
            waf.get("detected", False),
        ])

        if defenses >= 3:
            level = "Low"
            summary = (
                "Strong perimeter defense detected. Multiple security controls active "
                f"(Firewall: {firewall['detected']}, IDS/IPS: {ids['detected']}, "
                f"DMZ: {dmz['detected']}, WAF: {waf['detected']}). "
                "Evasion would require sophisticated multi-vector approach."
            )
        elif defenses >= 2:
            level = "Medium"
            summary = (
                f"Moderate security posture with {defenses} active defenses. "
                f"Firewall: {firewall['detected']}, IDS/IPS: {ids['detected']}, "
                f"DMZ: {dmz['detected']}, WAF: {waf['detected']}. "
                "Targeted evasion techniques may succeed against unprotected vectors."
            )
        elif defenses >= 1:
            level = "Medium"
            summary = (
                f"Limited security posture with {defenses} active defense(s). "
                "Additional hardening recommended. Evasion of remaining controls "
                "may be achievable with standard techniques."
            )
        else:
            level = "High"
            summary = (
                "Minimal or no perimeter defenses detected. "
                "Network appears exposed with no firewall, IDS/IPS, DMZ, or WAF. "
                "Immediate security hardening is strongly recommended."
            )

        return level, summary
