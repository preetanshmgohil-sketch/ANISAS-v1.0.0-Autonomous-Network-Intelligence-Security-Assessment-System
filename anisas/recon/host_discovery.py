"""Host discovery engine — ICMP ping sweep, ARP, TCP-SYN probes."""

from __future__ import annotations

import ipaddress
import logging
import os
import platform
import random
import socket
import subprocess
import concurrent.futures
from typing import Callable

from .stealth import (
    StealthConfig,
    DISCOVERY_PORTS,
    shuffle_hosts,
    tcp_connect_with_ttl_simple,
)

logger = logging.getLogger(__name__)


def _ping_host(ip: str, timeout: float = 1.5) -> bool:
    """Send a single ICMP echo request (ping)."""
    param = "-n" if platform.system().lower() == "windows" else "-c"
    timeout_param = "-w" if platform.system().lower() == "windows" else "-W"
    try:
        result = subprocess.run(
            ["ping", param, "1", timeout_param, str(int(timeout)), ip],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout + 1,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


def _arp_discover(ip: str) -> tuple[bool, str | None]:
    """Attempt ARP resolution (works on local broadcast domain)."""
    # ARP is OS-dependent; use the arp command
    try:
        if platform.system().lower() == "windows":
            result = subprocess.run(
                ["arp", "-a", ip],
                capture_output=True,
                text=True,
                timeout=2,
            )
        else:
            # Try arping or arp
            result = subprocess.run(
                ["arp", "-n", ip],
                capture_output=True,
                text=True,
                timeout=2,
            )
        output = result.stdout
        # Parse MAC from arp output
        for line in output.splitlines():
            if ip in line:
                parts = line.split()
                for part in parts:
                    mac = part.strip().replace("-", ":")
                    if len(mac) == 17 and mac.count(":") == 5:
                        return True, mac
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass
    return False, None


def _tcp_syn_discover(ip: str, timeout: float = 1.5) -> bool:
    """TCP-SYN host discovery — try connecting to common ports."""
    for port in DISCOVERY_PORTS:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(min(timeout, 0.8))
            result = sock.connect_ex((ip, port))
            sock.close()
            if result == 0:
                return True
        except (socket.timeout, OSError):
            continue
    return False


def discover_hosts_in_subnet(
    cidr: str,
    stealth: StealthConfig | None = None,
    progress_callback: Callable[[str, str], None] | None = None,
) -> list[dict]:
    """Discover active hosts within a single subnet using multi-protocol sweeps.

    Returns list of dicts: {ip, mac, discovery_method}
    """
    if stealth is None:
        stealth = StealthConfig()

    hosts = []
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return []

    # Get all usable IPs
    ip_list = [str(ip) for ip in net.hosts()]

    if stealth.randomize_host_order:
        ip_list = shuffle_hosts(ip_list)

    def check_host(ip: str) -> dict | None:
        """Check a single host with ICMP, ARP, then TCP-SYN fallback."""
        # 1. ICMP Ping
        if _ping_host(ip, stealth.timeout_seconds):
            return {"ip": ip, "mac": None, "discovery_method": "ICMP"}

        # 2. ARP (local network)
        arp_alive, mac = _arp_discover(ip)
        if arp_alive:
            return {"ip": ip, "mac": mac, "discovery_method": "ARP"}

        # 3. TCP-SYN probe fallback
        if _tcp_syn_discover(ip, stealth.timeout_seconds):
            return {"ip": ip, "mac": None, "discovery_method": "TCP-SYN"}

        return None

    # Concurrent host discovery
    max_workers = min(stealth.max_threads, len(ip_list) or 1)
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(check_host, ip): ip for ip in ip_list}
        for future in concurrent.futures.as_completed(futures):
            ip = futures[future]
            try:
                result = future.result()
                if result:
                    hosts.append(result)
                    if progress_callback:
                        progress_callback(ip, result["discovery_method"])
            except Exception as exc:
                logger.debug("Host check failed for %s: %s", ip, exc)

    return hosts
