"""Master pipeline orchestrator — executes Modules 1-6 sequentially with status streaming."""

from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid
from datetime import datetime
from typing import AsyncGenerator

logger = logging.getLogger(__name__)

# Scan state storage (in-memory, single-user lab use)
_scans: dict[str, dict] = {}


def create_scan(target_ip: str) -> str:
    """Create a new scan and return its ID."""
    scan_id = str(uuid.uuid4())
    _scans[scan_id] = {
        "scan_id": scan_id,
        "target_ip": target_ip,
        "status": "CREATED",
        "current_module": None,
        "modules": {
            "module1": {"status": "PENDING", "progress": 0},
            "module2": {"status": "PENDING", "progress": 0},
            "module3": {"status": "PENDING", "progress": 0},
            "module4": {"status": "PENDING", "progress": 0},
            "module5": {"status": "PENDING", "progress": 0},
            "module6": {"status": "PENDING", "progress": 0},
        },
        "results": {},
        "logs": [],
        "created_at": datetime.utcnow().isoformat() + "Z",
    }
    return scan_id


def get_scan(scan_id: str) -> dict | None:
    return _scans.get(scan_id)


def _add_log(scan_id: str, module: str, status: str, message: str) -> None:
    entry = {
        "module": module,
        "status": status,
        "log_message": message,
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }
    if scan_id in _scans:
        _scans[scan_id]["logs"].append(entry)


async def run_pipeline(scan_id: str) -> dict:
    """Execute the full Module 1-6 pipeline asynchronously.

    Returns combined results dict.
    """
    scan = _scans.get(scan_id)
    if not scan:
        return {"error": "Scan not found"}

    target = scan["target_ip"]
    scan["status"] = "RUNNING"

    _add_log(scan_id, "Orchestrator", "STARTED", f"Pipeline started for target: {target}")

    # Module 1: ASN & ISP Intelligence (RDAP-only, fast)
    await _run_module(scan_id, "module1", "Module-01", _run_module1, target, timeout=60.0)

    # Module 2: Network Reconnaissance (with timeout)
    m1_results = scan["results"].get("module1", {})
    prefixes = m1_results.get("ip_prefixes", [])
    # Use original target IP for Module 2, fall back to prefix if needed
    target_for_m2 = target
    await _run_module(scan_id, "module2", "Module-02", _run_module2, target_for_m2, m1_results, timeout=90.0)

    # Module 3: Security Perimeter (shorter timeout for external IPs)
    m2_results = scan["results"].get("module2", {})
    hosts_for_m3 = m2_results.get("active_hosts", [])
    target_m3 = target  # Default to original target
    if hosts_for_m3:
        ip = hosts_for_m3[0].get("ip_address", "")
        if ip:
            target_m3 = ip
    await _run_module(scan_id, "module3", "Module-03", _run_module3, target_m3, m2_results, timeout=30.0)

    # Module 4: IoT/Surveillance (shorter timeout for external IPs)
    await _run_module(scan_id, "module4", "Module-04", _run_module4, target, m2_results, timeout=45.0)

    # Module 5: Wireless (shorter timeout)
    await _run_module(scan_id, "module5", "Module-05", _run_module5, m2_results, timeout=30.0)

    # Module 6: AI/ML Analytics
    all_results = scan["results"]
    await _run_module(scan_id, "module6", "Module-06", _run_module6, all_results, timeout=60.0)

    scan["status"] = "COMPLETE"
    _add_log(scan_id, "Orchestrator", "COMPLETE", "All modules finished successfully.")

    return scan["results"]


async def _run_module(
    scan_id: str,
    module_key: str,
    module_name: str,
    func,
    *args,
    timeout: float = 120.0,
) -> None:
    """Run a single module with status tracking and timeout."""
    scan = _scans.get(scan_id)
    if not scan:
        return

    scan["modules"][module_key]["status"] = "RUNNING"
    scan["current_module"] = module_name
    _add_log(scan_id, module_name, "RUNNING", f"Starting {module_name} ...")

    loop = asyncio.get_event_loop()

    def _run():
        return func(*args)

    try:
        future = loop.run_in_executor(None, _run)
        result = await asyncio.wait_for(future, timeout=timeout)
        scan["results"][module_key] = result if isinstance(result, dict) else {}
        scan["modules"][module_key]["status"] = "COMPLETE"
        scan["modules"][module_key]["progress"] = 100
        _add_log(scan_id, module_name, "COMPLETE", f"{module_name} finished successfully.")
    except asyncio.TimeoutError:
        scan["modules"][module_key]["status"] = "FAILED"
        _add_log(scan_id, module_name, "FAILED", f"{module_name} timed out after {timeout}s")
        scan["results"][module_key] = {"error": f"Module timed out after {timeout}s"}
        logger.error("Module %s timed out after %s seconds", module_name, timeout)
    except Exception as exc:
        scan["modules"][module_key]["status"] = "FAILED"
        _add_log(scan_id, module_name, "FAILED", f"{module_name} failed: {exc}")
        scan["results"][module_key] = {"error": str(exc)}
        logger.error("Module %s failed: %s", module_name, exc)


def _run_module1(target_ip: str) -> dict:
    """Execute Module 1 — ASN & ISP Intelligence."""
    try:
        from anisas.engine import run_engine
        import asyncio
        # Create a new event loop for this thread
        loop = asyncio.new_event_loop()
        try:
            report = loop.run_until_complete(run_engine(target_ip))
            return report.model_dump()
        finally:
            loop.close()
    except Exception as e:
        return {"error": str(e), "target_ip": target_ip, "ip_prefixes": []}


def _run_module2(target_prefix: str, module1_data: dict) -> dict:
    """Execute Module 2 — Network Reconnaissance."""
    try:
        from anisas.recon.engine import NetworkReconEngine
        engine = NetworkReconEngine()
        report = engine.run(target_prefix)
        return report.model_dump()
    except Exception as e:
        return {"error": str(e), "active_hosts": [], "discovered_subnets": []}


def _run_module3(target_ip: str, module2_data: dict) -> dict:
    """Execute Module 3 — Security Perimeter Detection."""
    try:
        from anisas.perimeter.engine import SecurityPerimeterEngine
        engine = SecurityPerimeterEngine()
        report = engine.run(target_ip, module2_data=module2_data)
        return report.model_dump()
    except Exception as e:
        return {"error": str(e), "perimeter_defenses": {}}


def _run_module4(target_subnet: str, module2_data: dict) -> dict:
    """Execute Module 4 — IoT/Surveillance Fingerprinting."""
    try:
        from anisas.iot.engine import IoTSurveillanceEngine
        engine = IoTSurveillanceEngine()
        report = engine.run(target_subnet, module2_data=module2_data)
        return report.model_dump()
    except Exception as e:
        return {"error": str(e), "surveillance_devices": []}


def _run_module5(module2_data: dict) -> dict:
    """Execute Module 5 — Wireless Intelligence."""
    try:
        from anisas.wireless.engine import WirelessIntelligenceEngine
        engine = WirelessIntelligenceEngine()
        report = engine.run(module2_data=module2_data)
        return report.model_dump()
    except Exception as e:
        return {"error": str(e), "access_points": []}


def _run_module6(all_results: dict) -> dict:
    """Execute Module 6 — AI/ML Analytics."""
    try:
        from anisas.ai_engine.engine import AIMLEngine
        engine = AIMLEngine()
        report = engine.run(module_data=all_results)
        return report.model_dump()
    except Exception as e:
        return {"error": str(e), "device_classifications": []}
