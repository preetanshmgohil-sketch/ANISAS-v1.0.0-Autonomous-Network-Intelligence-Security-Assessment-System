"""DMZ architecture detection via multi-hop traceroute and service exposure analysis."""

from __future__ import annotations

import logging
import platform
import subprocess
import socket

logger = logging.getLogger(__name__)

# Services typically exposed in DMZ
_DMZ_SERVICES = {80, 443, 25, 53, 8080, 8443, 993, 995, 587}

# Services typically internal-only
_INTERNAL_SERVICES = {135, 139, 445, 3389, 5900, 22, 23, 3306, 5432, 1433}


def _traceroute(target: str, max_hops: int = 15, timeout: float = 2.0) -> list[dict]:
    """Perform a traceroute to identify network hops."""
    hops = []
    param = "-d" if platform.system().lower() == "windows" else "-n"
    try:
        result = subprocess.run(
            ["tracert" if platform.system().lower() == "windows" else "traceroute",
             param, "-m", str(max_hops), "-w", str(int(timeout * 1000)), target],
            capture_output=True,
            text=True,
            timeout=timeout * max_hops + 5,
        )
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line or line.startswith("Tracing") or line.startswith("Over"):
                continue
            parts = line.split()
            # Find IP addresses in the line
            for part in parts:
                try:
                    socket.inet_aton(part)
                    hops.append({"hop_ip": part, "ttl": len(hops) + 1})
                    break
                except (socket.error, ValueError):
                    continue
    except (subprocess.TimeoutExpired, FileNotFoundError):
        logger.debug("Traceroute failed for %s", target)
    return hops


def _check_service_exposure(ip: str, port: int, timeout: float = 1.0) -> bool:
    """Check if a port is reachable."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except (socket.timeout, OSError):
        return False


def detect_dmz(
    ip: str,
    discovered_ports: list[int] | None = None,
    timeout: float = 2.0,
) -> dict:
    """Detect DMZ architecture by analyzing traceroute hops and service exposure.

    Returns dict with detected, exposure_boundary, details.
    """
    # Perform traceroute
    hops = _traceroute(ip, timeout=timeout)
    hop_count = len(hops)

    # Check service exposure
    dmz_services_found = []
    internal_services_found = []

    ports_to_check = discovered_ports or list(_DMZ_SERVICES | _INTERNAL_SERVICES)
    for port in ports_to_check[:20]:
        if _check_service_exposure(ip, port, min(timeout, 1.0)):
            if port in _DMZ_SERVICES:
                dmz_services_found.append(port)
            elif port in _INTERNAL_SERVICES:
                internal_services_found.append(port)

    # DMZ detection logic
    detected = False
    boundary = "Internal-Only"

    if dmz_services_found and internal_services_found:
        # Both public and internal services exposed
        detected = True
        boundary = "Hybrid"
    elif dmz_services_found and not internal_services_found:
        # Only public-facing services = likely DMZ
        detected = True
        boundary = "Public-DMZ"
    elif hop_count > 3:
        # Multiple hops suggest network segmentation
        detected = True
        boundary = "Public-DMZ"

    return {
        "detected": detected,
        "exposure_boundary": boundary,
        "details": {
            "traceroute_hops": hops,
            "hop_count": hop_count,
            "dmz_services": dmz_services_found,
            "internal_services": internal_services_found,
        },
    }
