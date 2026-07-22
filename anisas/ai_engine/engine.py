"""Main AIMLEngine — orchestrates all AI/ML submodules."""

from __future__ import annotations

import json
import logging
import os
import time

from .models import (
    AIEngineReport, DeviceClassification, InferredTopology,
    TopoNode, TopoLink, ExecutiveNLSummary, AIAnalyticsSummary,
)
from .data_ingestion import ingest_modules, extract_feature_vector, extract_os_features
from .device_classifier import classify_all_devices, _train_simple as train_classifier
from .os_fingerprint import fingerprint_all_os, _train_simple as train_os_model
from .topology_inference import infer_topology
from .anomaly_detection import detect_anomalies, compute_health_score
from .risk_scorer import score_all_devices
from .nl_generator import generate_nl_summary

logger = logging.getLogger(__name__)


class AIMLEngine:
    """Core AI/ML intelligence engine for ANISAS Module 6.

    Usage:
        engine = AIMLEngine()
        report = engine.run({
            "module1": "path/to/mod1.json",
            "module2": "path/to/mod2.json",
            ...
        })
        print(report.model_dump_json(indent=2))
    """

    def __init__(self):
        pass

    def run(
        self,
        module_paths: dict[str, str] | None = None,
        *,
        json_output: str | None = None,
        module_data: dict[str, dict] | None = None,
    ) -> AIEngineReport:
        """Execute the full AI/ML pipeline.

        Args:
            module_paths: Dict mapping module names to JSON file paths.
            json_output: Optional path to write the JSON report.
            module_data: Pre-loaded module data dicts.

        Returns:
            Populated AIEngineReport.
        """
        start = time.monotonic()

        # Step 1: Data Ingestion
        logger.info("[1/6] Ingesting data from Modules 1-5 ...")
        if module_data:
            unified = ingest_modules(
                module1_data=module_data.get("module1"),
                module2_data=module_data.get("module2"),
                module3_data=module_data.get("module3"),
                module4_data=module_data.get("module4"),
                module5_data=module_data.get("module5"),
            )
        else:
            unified = ingest_modules(module_paths or {})

        hosts = unified.get("active_hosts", [])
        subnets = unified.get("discovered_subnets", [])
        subnet_cids = [s.get("cidr", "") for s in subnets if s.get("cidr")]

        # Enrich hosts with feature vectors
        for host in hosts:
            host["feature_vector"] = extract_feature_vector(host)
            host["os_features"] = extract_os_features(host)

        # Add surveillance devices as hosts if not already present
        existing_ips = {h.get("ip_address", h.get("ip", "")) for h in hosts}
        for dev in unified.get("surveillance_devices", []):
            ip = dev.get("ip_address", "")
            if ip and ip not in existing_ips:
                hosts.append({
                    "ip_address": ip,
                    "mac_address": dev.get("mac_address"),
                    "open_ports": [{"port": 554, "service": "RTSP"}, {"port": 80, "service": "HTTP"}],
                    "os_fingerprint": {"initial_ttl": 64, "tcp_window_size": 29200},
                    "feature_vector": [],
                    "os_features": [64.0, 29200.0, 0.0, 1.0, 0.0, 0.0],
                })

        logger.info("Ingested %d hosts, %d subnets.", len(hosts), len(subnet_cids))

        # Step 2: Device Classification
        logger.info("[2/6] Training device classifier ...")
        clf_metrics = train_classifier()
        logger.info("Classifier accuracy: %.0f%%", clf_metrics["accuracy"] * 100)

        logger.info("Classifying devices ...")
        classifications_raw = classify_all_devices(hosts)

        # Merge host data into classifications
        host_by_ip = {h.get("ip_address", h.get("ip", "")): h for h in hosts}
        for cls in classifications_raw:
            ip = cls.get("ip_address", "")
            host = host_by_ip.get(ip, {})
            cls["open_ports"] = host.get("open_ports", [])
            cls["os_fingerprint"] = host.get("os_fingerprint", {})
            cls["firmware_version"] = host.get("firmware_version", "Unknown")
            cls["cve_vulnerabilities"] = host.get("cve_vulnerabilities", [])

        # Step 3: OS Fingerprinting
        logger.info("[3/6] Training OS fingerprinting model ...")
        os_metrics = train_os_model()
        logger.info("OS model accuracy: %.0f%%", os_metrics["accuracy"] * 100)

        os_results = fingerprint_all_os(hosts)
        os_map = {r["ip_address"]: r for r in os_results}
        for cls in classifications_raw:
            os_data = os_map.get(cls["ip_address"], {})
            if os_data:
                cls["predicted_os"] = os_data["predicted_os"]
                cls["os_confidence"] = os_data["os_confidence"]

        # Step 4: Topology Inference
        logger.info("[4/6] Inferring network topology ...")
        topology = infer_topology(subnet_cids, hosts)

        # Step 5: Anomaly Detection
        logger.info("[5/6] Running anomaly detection ...")
        anomalies = detect_anomalies(hosts)
        health_score = compute_health_score(hosts, anomalies)

        # Merge anomaly data into classifications
        anomaly_map = {a["ip_address"]: a for a in anomalies}
        for cls in classifications_raw:
            anom = anomaly_map.get(cls["ip_address"], {})
            cls["is_anomalous"] = anom.get("anomaly_score", 0) > 0.5
            cls["anomaly_reasons"] = [anom["reason"]] if anom.get("reason") else []

        # Step 6: Risk Scoring
        logger.info("[6/6] Computing risk scores ...")
        classifications_final = score_all_devices(classifications_raw, anomalies)

        # NL Summary
        nl_summary = generate_nl_summary(
            classifications_final, anomalies, topology, unified.get("perimeter_defenses")
        )

        # Build report
        critical_count = sum(1 for d in classifications_final if d.get("risk_category") == "CRITICAL")
        high_count = sum(1 for d in classifications_final if d.get("risk_category") == "HIGH")

        device_models = [
            DeviceClassification(
                ip_address=d.get("ip_address", ""),
                predicted_device_type=d.get("predicted_device_type", "Unclassified"),
                classifier_confidence=d.get("classifier_confidence", 0),
                predicted_os=d.get("predicted_os", "Unknown"),
                os_confidence=d.get("os_confidence", 0),
                calculated_risk_score=d.get("calculated_risk_score", 0),
                risk_category=d.get("risk_category", "LOW"),
                is_anomalous=d.get("is_anomalous", False),
                anomaly_reasons=d.get("anomaly_reasons", []),
            )
            for d in classifications_final
        ]

        topo_nodes = [TopoNode(**n) for n in topology.get("nodes", [])]
        topo_links = [TopoLink(**l) for l in topology.get("links", [])]

        report = AIEngineReport(
            ai_analytics_summary=AIAnalyticsSummary(
                total_devices_analyzed=len(hosts),
                anomalies_detected_count=len(anomalies),
                network_health_score=health_score,
            ),
            device_classifications=device_models,
            inferred_topology=InferredTopology(nodes=topo_nodes, links=topo_links),
            executive_nl_summary=ExecutiveNLSummary(**nl_summary),
        )

        # Output
        if json_output:
            os.makedirs(os.path.dirname(json_output) or ".", exist_ok=True)
            with open(json_output, "w", encoding="utf-8") as f:
                f.write(report.model_dump_json(indent=2))
            logger.info("JSON report written to %s", json_output)

        elapsed = time.monotonic() - start
        logger.info("AI/ML pipeline completed in %.2f seconds.", elapsed)

        return report
