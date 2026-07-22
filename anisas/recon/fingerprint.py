"""OS and device fingerprinting via TTL, TCP window size, and banner analysis."""

from __future__ import annotations

import logging

from .stealth import classify_os_by_ttl

logger = logging.getLogger(__name__)

# Banner-based OS hints
_BANNER_OS_HINTS: list[tuple[str, str]] = [
    ("openssh", "Linux"),
    ("ubuntu", "Linux"),
    ("debian", "Linux"),
    ("centos", "Linux"),
    ("red hat", "Linux"),
    ("microsoft", "Windows"),
    ("iis", "Windows"),
    ("microsoft-ds", "Windows"),
    ("cisco", "Embedded/Network"),
    ("juniper", "Embedded/Network"),
    ("mikrotik", "Embedded/Network"),
    ("routeros", "Embedded/Network"),
    ("apache", "Linux"),
    ("nginx", "Linux"),
    ("lighttpd", "Linux"),
]

# Banner-based service refinements
_BANNER_SERVICE_HINTS: list[tuple[str, str]] = [
    ("ssh", "SSH"),
    ("openssh", "SSH"),
    ("http", "HTTP"),
    ("https", "HTTPS"),
    ("ssl", "HTTPS"),
    ("ftp", "FTP"),
    ("proftpd", "FTP"),
    ("vsftpd", "FTP"),
    ("smtp", "SMTP"),
    ("postfix", "SMTP"),
    ("sendmail", "SMTP"),
    ("rtsp", "RTSP"),
    ("live555", "RTSP"),
    ("mysql", "MySQL"),
    ("mariadb", "MySQL"),
    ("postgresql", "PostgreSQL"),
    ("redis", "Redis"),
    ("mongodb", "MongoDB"),
    ("microsoft-ds", "SMB"),
    ("netbios", "NetBIOS"),
    ("rdp", "RDP"),
    ("vnc", "VNC"),
    ("telnet", "Telnet"),
]


def fingerprint_os(
    ttl: int | None,
    window_size: int | None,
    banners: list[str],
) -> dict:
    """Classify OS based on TTL, TCP window size, and banner content.

    Returns dict with predicted_os, initial_ttl, tcp_window_size.
    """
    predicted_os = "Unknown"
    ttl_val = ttl if ttl is not None else 0

    # 1. TTL-based classification
    if ttl and ttl > 0:
        predicted_os = classify_os_by_ttl(ttl)

    # 2. Banner-based refinement (overrides TTL if confident)
    combined_banner = " ".join(banners).lower() if banners else ""
    for hint, os_name in _BANNER_OS_HINTS:
        if hint in combined_banner:
            predicted_os = os_name
            break

    # 3. Window size heuristics
    if window_size and window_size > 0:
        if predicted_os == "Unknown":
            if window_size >= 65535:
                predicted_os = "Windows"
            elif window_size <= 16384:
                predicted_os = "Linux"
            elif 16384 < window_size < 65535:
                predicted_os = "Embedded/Network"

    return {
        "predicted_os": predicted_os,
        "initial_ttl": ttl_val,
        "tcp_window_size": window_size,
    }


def refine_service_from_banners(
    port: int,
    service_hint: str,
    banners: list[str],
) -> str:
    """Refine service name based on collected banner data."""
    combined = " ".join(banners).lower() if banners else ""

    for hint, svc_name in _BANNER_SERVICE_HINTS:
        if hint in combined:
            return svc_name

    return service_hint


def fingerprint_all_hosts(
    hosts: list[dict],
    port_results: dict[str, list[dict]],
) -> list[dict]:
    """Apply OS fingerprinting to all discovered hosts.

    Args:
        hosts: List of host dicts from discovery (ip, mac, discovery_method, ttl, window_size).
        port_results: Dict mapping IP -> list of open port dicts.

    Returns:
        Enriched host dicts with os_fingerprint and open_ports.
    """
    enriched: list[dict] = []

    for host in hosts:
        ip = host.get("ip", "")
        ttl = host.get("ttl")
        ws = host.get("window_size")

        # Collect banners from port scan results
        banners: list[str] = []
        open_ports: list[dict] = []
        for port_info in port_results.get(ip, []):
            banner = port_info.get("banner")
            if banner:
                banners.append(banner)
            open_ports.append(port_info)

        os_fp = fingerprint_os(ttl, ws, banners)

        enriched.append({
            "ip_address": ip,
            "mac_address": host.get("mac"),
            "status": "up",
            "discovery_method": host.get("discovery_method", "ICMP"),
            "os_fingerprint": os_fp,
            "open_ports": open_ports,
        })

    return enriched
