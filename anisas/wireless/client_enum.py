"""Client enumeration via ARP cache and DHCP lease parsing."""

from __future__ import annotations

import logging
import os
import platform
import re
import subprocess
from datetime import datetime

logger = logging.getLogger(__name__)

# Common DHCP lease file paths
_DHCP_LEASE_PATHS_LINUX = [
    "/var/lib/dhcp/dhcpd.leases",
    "/var/lib/dhclient/dhclient.leases",
    "/var/lib/NetworkManager/dhclient-*.leases",
    "/tmp/dnsmasq.leases",
    "/var/lib/dhcpd/dhcpd.leases",
]


def _parse_arp_table() -> list[dict]:
    """Parse the system ARP table for active clients."""
    clients: list[dict] = []

    try:
        if platform.system().lower() == "windows":
            result = subprocess.run(
                ["arp", "-a"],
                capture_output=True, text=True, timeout=5,
            )
            for line in result.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 3:
                    ip = parts[0]
                    mac = parts[1]
                    if _is_valid_mac(mac) and _is_valid_ip(ip):
                        clients.append({
                            "mac_address": mac,
                            "assigned_ip": ip,
                            "status": "ACTIVE",
                            "hostname": None,
                        })
        else:
            result = subprocess.run(
                ["arp", "-n"],
                capture_output=True, text=True, timeout=5,
            )
            for line in result.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 3:
                    ip = parts[0]
                    mac = parts[2] if "ether" in line.lower() else parts[1]
                    if _is_valid_mac(mac) and _is_valid_ip(ip):
                        # Skip incomplete entries
                        if mac == "(incomplete)" or mac == "00:00:00:00:00:00":
                            continue
                        clients.append({
                            "mac_address": mac,
                            "assigned_ip": ip,
                            "status": "ACTIVE",
                            "hostname": None,
                        })
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        logger.debug("ARP table parse failed: %s", e)

    return clients


def _parse_dhcp_leases() -> list[dict]:
    """Parse DHCP lease files for historical/inactive clients."""
    clients: list[dict] = []
    system = platform.system().lower()

    lease_paths = []
    if system == "linux":
        lease_paths = _DHCP_LEASE_PATHS_LINUX
    elif system == "windows":
        lease_paths = [
            r"C:\Windows\System32\dhcp",
        ]
    elif system == "darwin":
        lease_paths = [
            "/var/db/dhcpclient/leases",
        ]

    import glob
    for pattern in lease_paths:
        for path in glob.glob(pattern):
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read()

                # Parse dnsmasq format
                for block in content.split("lease"):
                    mac_match = re.search(r"([0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2})", block)
                    ip_match = re.search(r"(\d+\.\d+\.\d+\.\d+)", block)
                    host_match = re.search(r"hostname\s+([\w\.\-]+)", block)

                    if mac_match and ip_match:
                        clients.append({
                            "mac_address": mac_match.group(1),
                            "assigned_ip": ip_match.group(1),
                            "status": "INACTIVE",
                            "hostname": host_match.group(1) if host_match else None,
                        })

                # Parse ISC DHCP format
                for line in content.splitlines():
                    if "lease" in line and "{" in line:
                        ip_m = re.search(r"lease\s+(\d+\.\d+\.\d+\.\d+)", line)
                        current_ip = ip_m.group(1) if ip_m else None
                    elif "hardware ethernet" in line:
                        mac_m = re.search(r"([0-9a-fA-F:]{17})", line)
                        if mac_m and current_ip:
                            clients.append({
                                "mac_address": mac_m.group(1),
                                "assigned_ip": current_ip,
                                "status": "INACTIVE",
                                "hostname": None,
                            })
            except (FileNotFoundError, PermissionError, OSError):
                continue

    return clients


def _parse_ip_neigh() -> list[dict]:
    """Parse ip neigh (modern Linux ARP equivalent)."""
    clients: list[dict] = []
    try:
        result = subprocess.run(
            ["ip", "neigh", "show"],
            capture_output=True, text=True, timeout=5,
        )
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 5:
                ip = parts[0]
                mac = parts[4] if len(parts) > 4 else ""
                state = parts[1] if len(parts) > 1 else ""
                if _is_valid_mac(mac) and _is_valid_ip(ip):
                    status = "ACTIVE" if state in ("lladdr", "REACHABLE", "STALE", "DELAY") else "INACTIVE"
                    clients.append({
                        "mac_address": mac,
                        "assigned_ip": ip,
                        "status": status,
                        "hostname": None,
                    })
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return clients


def _is_valid_mac(mac: str) -> bool:
    return bool(re.match(r"^([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}$", mac))


def _is_valid_ip(ip: str) -> bool:
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    return all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


def enumerate_clients() -> list[dict]:
    """Enumerate network clients from ARP cache and DHCP leases.

    Returns list of client dicts with mac, ip, status, hostname.
    """
    seen: set[str] = set()
    all_clients: list[dict] = []

    # ARP table (active)
    for client in _parse_arp_table():
        key = client["mac_address"].lower()
        if key not in seen:
            seen.add(key)
            all_clients.append(client)

    # IP neigh (active, Linux)
    for client in _parse_ip_neigh():
        key = client["mac_address"].lower()
        if key not in seen:
            seen.add(key)
            all_clients.append(client)

    # DHCP leases (includes inactive)
    for client in _parse_dhcp_leases():
        key = client["mac_address"].lower()
        if key not in seen:
            seen.add(key)
            all_clients.append(client)

    return all_clients
