"""OS and device fingerprinting via TTL, TCP window size, and banner analysis."""

from __future__ import annotations

import logging

from .stealth import classify_os_by_ttl

logger = logging.getLogger(__name__)

# Banner-based OS hints (order matters: first match wins)
_BANNER_OS_HINTS: list[tuple[str, str]] = [
    # Linux distributions
    ("openssh", "Linux"),
    ("ubuntu", "Linux (Ubuntu)"),
    ("debian", "Linux (Debian)"),
    ("centos", "Linux (CentOS)"),
    ("red hat", "Linux (RHEL)"),
    ("rhel", "Linux (RHEL)"),
    ("fedora", "Linux (Fedora)"),
    ("suse", "Linux (SUSE)"),
    ("opensuse", "Linux (openSUSE)"),
    ("alpine", "Linux (Alpine)"),
    ("arch linux", "Linux (Arch)"),
    ("gentoo", "Linux (Gentoo)"),
    ("slackware", "Linux (Slackware)"),
    ("raspbian", "Linux (Raspberry Pi)"),
    ("raspberry", "Linux (Raspberry Pi)"),
    ("kali", "Linux (Kali)"),
    ("mint", "Linux (Mint)"),
    ("manjaro", "Linux (Manjaro)"),
    ("rocky", "Linux (Rocky)"),
    ("almalinux", "Linux (AlmaLinux)"),
    ("oracle linux", "Linux (Oracle)"),
    ("amzn", "Linux (Amazon)"),
    # macOS
    ("darwin", "macOS"),
    ("mac os", "macOS"),
    ("macos", "macOS"),
    ("apple", "macOS"),
    ("airport", "macOS (Apple)"),
    # Windows
    ("microsoft", "Windows"),
    ("iis", "Windows (IIS)"),
    ("microsoft-ds", "Windows"),
    ("microsoft-ds", "Windows (SMB)"),
    ("microsoft iis", "Windows (IIS)"),
    ("windows server", "Windows Server"),
    ("windows nt", "Windows NT"),
    ("win32", "Windows"),
    ("win64", "Windows"),
    ("powershell", "Windows"),
    ("remote desktop", "Windows (RDP)"),
    # BSD
    ("freebsd", "FreeBSD"),
    ("openbsd", "OpenBSD"),
    ("netbsd", "NetBSD"),
    ("dragonfly", "DragonFly BSD"),
    # Solaris / Unix
    ("solaris", "Solaris"),
    ("sunos", "Solaris/SunOS"),
    ("illumos", "Illumos"),
    ("aix", "AIX"),
    ("hp-ux", "HP-UX"),
    ("irix", "IRIX"),
    # Network / Embedded
    ("cisco", "Cisco IOS"),
    ("cisco ios", "Cisco IOS"),
    ("juniper", "Juniper"),
    ("junos", "Juniper (JunOS)"),
    ("mikrotik", "MikroTik"),
    ("routeros", "MikroTik (RouterOS)"),
    ("vyos", "VyOS"),
    ("pfsense", "pfSense"),
    ("opnsense", "OPNsense"),
    ("fortigate", "Fortinet"),
    ("fortios", "Fortinet"),
    ("paloalto", "Palo Alto"),
    ("checkpoint", "Check Point"),
    ("ubiquiti", "Ubiquiti"),
    ("ubnt", "Ubiquiti"),
    ("meraki", "Meraki (Cisco)"),
    ("aruba", "Aruba"),
    ("unifi", "Ubiquiti"),
    # IoT / Embedded
    ("linux/embedded", "Embedded Linux"),
    ("busybox", "Embedded Linux (BusyBox)"),
    ("dropbear", "Embedded Linux (Dropbear)"),
    # Web servers (typically Linux)
    ("apache", "Linux (Apache)"),
    ("nginx", "Linux (Nginx)"),
    ("lighttpd", "Linux (Lighttpd)"),
    ("cherokee", "Linux (Cherokee)"),
    ("openresty", "Linux (OpenResty)"),
    ("caddy", "Linux (Caddy)"),
    ("litespeed", "Linux (LiteSpeed)"),
    # Database banners
    ("mysql", "Linux/Unix (MySQL)"),
    ("mariadb", "Linux/Unix (MariaDB)"),
    ("postgresql", "Linux/Unix (PostgreSQL)"),
    ("redis", "Linux/Unix (Redis)"),
    ("mongodb", "Linux/Unix (MongoDB)"),
    ("elasticsearch", "Linux/Unix (Elastic)"),
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
        if predicted_os in ("Unknown", "Linux/Unix"):
            if window_size >= 65535:
                predicted_os = "Windows"
            elif 16384 < window_size < 65535:
                # Many Linux distros use 29200, 5840, 14600, 65535
                # macOS often uses 65535 or 16384
                if window_size in (65535, 65535 * 2):
                    predicted_os = "macOS/Windows"
                elif window_size <= 32768:
                    predicted_os = "Linux/Unix"
                else:
                    predicted_os = "Linux/Unix"
            elif window_size <= 16384:
                if window_size <= 4096:
                    predicted_os = "Embedded/RTOS"
                else:
                    predicted_os = "Linux/Unix"
            elif window_size == 0:
                predicted_os = "Unknown"

        # Refine for Windows specifically
        if predicted_os == "Windows" and window_size < 8192:
            predicted_os = "Embedded/Windows IoT"

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
