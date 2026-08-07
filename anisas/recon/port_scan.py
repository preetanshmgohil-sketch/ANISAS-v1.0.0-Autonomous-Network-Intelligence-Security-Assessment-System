"""Port scanning and service banner grabbing."""

from __future__ import annotations

import concurrent.futures
import logging
import socket
from typing import Callable

from .stealth import StealthConfig, SERVICE_PORTS, shuffle_hosts

logger = logging.getLogger(__name__)

SCAN_PORTS = sorted(SERVICE_PORTS.keys()) + [
    111, 135, 139, 143, 179, 443, 465, 514, 554, 587,
    631, 993, 995, 1080, 1433, 1434, 1720, 1723, 2000,
    2049, 3306, 3389, 5060, 5432, 5900, 5901, 6379,
    8080, 8443, 8888, 9090, 9200, 9443, 27017,
]

# Top 20 most common ports for fast scanning
FAST_SCAN_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143,
    443, 445, 993, 995, 1433, 3306, 3389, 5432, 8080, 8443,
]


def _get_service_name(port: int) -> str:
    return SERVICE_PORTS.get(port, "unknown")


def _grab_banner(ip: str, port: int, timeout: float = 1.5) -> str | None:
    """Connect to a port and attempt to read a service banner."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(min(timeout, 1.0))
        result = sock.connect_ex((ip, port))
        if result != 0:
            sock.close()
            return None

        banner: str | None = None
        try:
            data = sock.recv(1024)
            if data:
                banner = data.decode("utf-8", errors="replace").strip()[:256]
        except (socket.timeout, OSError):
            pass  # banner unavailable — not a failure

        if not banner and port in (80, 8080, 443, 8443):
            try:
                probe = b"HEAD / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n"
                sock.sendall(probe)
                data = sock.recv(1024)
                if data:
                    first_line = data.decode("utf-8", errors="replace").split("\r\n")[0]
                    banner = first_line[:256]
            except (socket.timeout, OSError):
                pass  # HTTP probe failed — acceptable

        sock.close()
        return banner
    except (socket.timeout, OSError):
        return None


def _scan_single_host_ports(
    ip: str,
    ports: list[int],
    stealth: StealthConfig,
) -> list[dict]:
    """Scan all ports on a single host and return open port details."""
    open_ports: list[dict] = []

    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(stealth.timeout_seconds)
            result = sock.connect_ex((ip, port))
            sock.close()

            if result == 0:
                banner = _grab_banner(ip, port, stealth.timeout_seconds)
                service = _get_service_name(port)

                if banner:
                    bl = banner.lower()
                    if "ssh" in bl:
                        service = "SSH"
                    elif "http" in bl:
                        service = "HTTPS" if "https" in bl or "ssl" in bl else "HTTP"
                    elif "ftp" in bl:
                        service = "FTP"
                    elif "smtp" in bl:
                        service = "SMTP"
                    elif "rtsp" in bl:
                        service = "RTSP"

                open_ports.append({
                    "port": port,
                    "protocol": "tcp",
                    "service": service,
                    "banner": banner,
                })
        except (socket.timeout, OSError):
            continue

    return open_ports


def scan_host_ports(
    ip: str,
    stealth: StealthConfig | None = None,
    ports: list[int] | None = None,
    fast: bool = True,
) -> list[dict]:
    """Scan ports on a single host. Returns list of open port dicts."""
    if stealth is None:
        stealth = StealthConfig()
    if ports is None:
        ports = FAST_SCAN_PORTS if fast else SCAN_PORTS
    return _scan_single_host_ports(ip, ports, stealth)


def scan_all_hosts_ports(
    hosts: list[str],
    stealth: StealthConfig | None = None,
    ports: list[int] | None = None,
    progress_callback: Callable[[str, int], None] | None = None,
    fast: bool = True,
) -> dict[str, list[dict]]:
    """Scan ports across all discovered hosts concurrently.

    Returns dict mapping IP -> list of open port dicts.
    """
    if stealth is None:
        stealth = StealthConfig()
    if ports is None:
        ports = FAST_SCAN_PORTS if fast else SCAN_PORTS

    results: dict[str, list[dict]] = {}

    def scan_host(ip: str) -> tuple[str, list[dict]]:
        open_ports = _scan_single_host_ports(ip, ports, stealth)
        return ip, open_ports

    host_list = shuffle_hosts(hosts, stealth.randomize_host_order)
    max_workers = min(stealth.max_threads, len(host_list) or 1)

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(scan_host, ip): ip for ip in host_list}
        for future in concurrent.futures.as_completed(futures):
            try:
                ip, open_ports = future.result()
                results[ip] = open_ports
                if progress_callback:
                    progress_callback(ip, len(open_ports))
            except Exception as exc:
                logger.debug("Port scan failed: %s", exc)

    return results
