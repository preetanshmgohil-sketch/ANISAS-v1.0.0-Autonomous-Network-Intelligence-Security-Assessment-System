"""Client enumeration via ARP cache and DHCP lease parsing."""

from __future__ import annotations

import logging
import os
import platform
import re
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# Limit reverse DNS lookups to avoid scan delays
_MAX_RDNS_LOOKUPS = 20

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
                        clients.append(_make_client(mac, ip, "ACTIVE"))
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
                        clients.append(_make_client(mac, ip, "ACTIVE"))
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
                            "last_seen_timestamp": _now_iso(),
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
                                "last_seen_timestamp": _now_iso(),
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
                    clients.append(_make_client(mac, ip, status))
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        logger.debug("Client enumeration failed: %s", e)
    return clients


def _is_valid_mac(mac: str) -> bool:
    return bool(re.match(r"^([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}$", mac))


def _is_valid_ip(ip: str) -> bool:
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    return all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


def _batch_reverse_dns(ips: list[str]) -> dict[str, str]:
    """Perform reverse DNS lookups in parallel for a list of IPs.
    Returns dict mapping IP -> hostname for successful lookups.
    """
    results: dict[str, str] = {}
    unique_ips = list(set(ip for ip in ips if ip and ip != "0.0.0.0"))
    if not unique_ips:
        return results

    ips_to_check = unique_ips[:_MAX_RDNS_LOOKUPS]

    def _lookup(ip: str) -> tuple[str, str | None]:
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            if hostname and hostname != ip:
                return ip, hostname
        except Exception:  # noqa: BLE001
            pass
        return ip, None

    try:
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(_lookup, ip) for ip in ips_to_check]
            for future in as_completed(futures, timeout=5):
                try:
                    ip, hostname = future.result()
                    if hostname:
                        results[ip] = hostname
                except Exception:  # noqa: BLE001
                    pass
    except Exception:  # noqa: BLE001
        pass

    return results


def _now_iso() -> str:
    """Return current UTC time as ISO-8601 string."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _make_client(mac: str, ip: str, status: str = "ACTIVE") -> dict:
    """Build a client dict with timestamp. Hostname is resolved in batch later."""
    return {
        "mac_address": mac,
        "assigned_ip": ip,
        "status": status,
        "hostname": None,
        "last_seen_timestamp": _now_iso(),
    }


def enumerate_clients() -> list[dict]:
    """Enumerate network clients from ARP cache and DHCP leases.

    Returns list of client dicts with mac, ip, status, hostname, last_seen_timestamp.
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

    # Batch reverse DNS lookup for all unique IPs
    all_ips = [c["assigned_ip"] for c in all_clients if c.get("assigned_ip")]
    hostname_map = _batch_reverse_dns(all_ips)

    # Merge hostnames into client records
    for client in all_clients:
        ip = client.get("assigned_ip")
        if ip and ip in hostname_map:
            client["hostname"] = hostname_map[ip]

    return all_clients
