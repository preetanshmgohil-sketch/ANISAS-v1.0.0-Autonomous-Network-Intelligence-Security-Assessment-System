"""Stealth scanning mechanics — jitter, randomization, fragmentation, decoys."""

from __future__ import annotations

import ipaddress
import logging
import random
import socket
import struct
import time
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# Well-known OS TTL ranges (ordered by specificity)
_TTL_RANGES: list[tuple[int, int, str]] = [
    (254, 255, "Solaris/AIX/HP-UX"),
    (252, 253, "Cisco IOS"),
    (127, 128, "Windows"),
    (63, 64, "Linux/Unix"),
    (60, 62, "macOS/FreeBSD"),
    (31, 32, "Embedded/RTOS"),
    (1, 30, "Ultra-Light Embedded"),
]

# Common ports for TCP-SYN host discovery
DISCOVERY_PORTS = [80, 443, 22, 445, 3389, 8080, 21, 23, 554]

# Ports for service mapping
SERVICE_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPCBind", 135: "MSRPC",
    139: "NetBIOS", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    554: "RTSP", 993: "IMAPS", 995: "POP3S", 1723: "PPTP",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt", 8888: "HTTP-Proxy",
}


@dataclass
class StealthConfig:
    """Configuration for stealth scanning parameters."""
    enabled: bool = True
    min_delay_ms: int = 50
    max_delay_ms: int = 300
    jitter_enabled: bool = True
    randomize_host_order: bool = True
    fragmentation: bool = False
    decoy_count: int = 0
    timeout_seconds: float = 1.5
    max_threads: int = 100

    def random_delay(self) -> float:
        """Return a random delay in seconds respecting jitter settings."""
        if not self.jitter_enabled:
            return self.min_delay_ms / 1000.0
        delay_ms = random.randint(self.min_delay_ms, self.max_delay_ms)
        return delay_ms / 1000.0


def shuffle_hosts(hosts: list[str], enabled: bool = True) -> list[str]:
    """Randomize host order if stealth is enabled."""
    if not enabled:
        return hosts
    shuffled = hosts.copy()
    random.shuffle(shuffled)
    return shuffled


def build_decoy_ips(real_ip: str, count: int) -> list[str]:
    """Generate spoofed decoy source IPs for packet obfuscation."""
    if count <= 0:
        return []
    decoys: list[str] = []
    real_addr = ipaddress.ip_address(real_ip)
    for _ in range(count):
        while True:
            octets = [random.randint(1, 254) for _ in range(4)]
            decoy = ".".join(str(o) for o in octets)
            if decoy != real_ip:
                decoys.append(decoy)
                break
    return decoys


def estimate_ttl_range(ttl: int) -> tuple[int, int] | None:
    """Return the TTL ceiling range that a given TTL falls into."""
    for low, high, _ in _TTL_RANGES:
        if low <= ttl <= high:
            return (low, high)
    return None


def classify_os_by_ttl(ttl: int) -> str:
    """Classify OS category based on observed initial TTL.

    Uses TTL value and common defaults:
      - 255: Solaris, AIX, HP-UX, Cisco IOS, Juniper, some BSDs
      - 128: Windows (all versions), some embedded
      - 64:  Linux, macOS, FreeBSD, Android, iOS, most Unix-like
      - 32:  Embedded/RTOS (VxWorks, FreeRTOS, etc.)
      - 60-62: macOS (observed on some macOS versions)
    """
    # Exact matches first
    if ttl == 255:
        return "Solaris/AIX/HP-UX/Cisco"
    if ttl == 254:
        return "Cisco/Network Appliance"
    if ttl == 128:
        return "Windows"
    if ttl == 64:
        return "Linux/Unix"
    if ttl == 32:
        return "Embedded/RTOS"

    # Range-based fallback
    for low, high, os_name in _TTL_RANGES:
        if low <= ttl <= high:
            return os_name

    # Heuristic for unusual TTLs
    if ttl > 128:
        return "Network Appliance"
    if ttl > 64:
        return "Unknown (Likely Windows)"
    if ttl > 32:
        return "Unknown (Likely Unix-like)"
    if ttl > 0:
        return "Embedded/Unknown"
    return "Unknown"


def tcp_connect_with_ttl(
    ip: str,
    port: int,
    timeout: float = 1.5,
) -> tuple[bool, int | None, int | None, str | None]:
    """Attempt a TCP connect to grab TTL, window size, and banner.

    Returns:
        (is_open, ttl, window_size, banner)
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        if result != 0:
            sock.close()
            return False, None, None, None

        # Try to read a banner
        banner: str | None = None
        try:
            sock.settimeout(min(timeout, 1.0))
            data = sock.recv(1024)
            if data:
                banner = data.decode("utf-8", errors="replace").strip()[:256]
        except (socket.timeout, OSError):
            pass  # banner read timeout — expected during stealth scan

        sock.close()
        return True, None, None, banner

    except (socket.timeout, OSError):
        return False, None, None, None


def tcp_raw_syn_ttl(
    ip: str,
    port: int,
    timeout: float = 1.5,
) -> tuple[bool, int | None, int | None]:
    """Send a raw TCP SYN and read TTL + window size from the SYN-ACK.

    Uses raw sockets (requires admin/root). Falls back to connect if unavailable.

    Returns:
        (is_open, ttl, window_size)
    """
    try:
        # Build raw TCP SYN packet
        src_port = random.randint(1024, 65535)
        seq_num = random.randint(0, 2**32 - 1)

        # IP header
        ip_ihl_ver = (4 << 4) | 5
        ip_ttl = 64
        ip_proto = 6  # TCP
        ip_src = socket.inet_aton(get_local_ip())
        ip_dst = socket.inet_aton(ip)

        # TCP header
        tcp_syn = 0x02
        tcp_window = 65535
        tcp_data_offset = (5 << 4)  # 5*4 = 20 bytes
        tcp_flags = tcp_syn
        tcp_check = 0
        tcp_urg = 0

        # Pseudo header for checksum
        pseudo = struct.pack(
            "!4s4sBBH",
            ip_src, ip_dst, 0, ip_proto, 20
        )

        tcp_header = struct.pack(
            "!HHIIBBHHH",
            src_port, port, seq_num, 0,
            tcp_data_offset, tcp_flags, tcp_window, tcp_check, tcp_urg
        )

        tcp_check = checksum(pseudo + tcp_header)
        tcp_header = struct.pack(
            "!HHIIBBHHH",
            src_port, port, seq_num, 0,
            tcp_data_offset, tcp_flags, tcp_window, tcp_check, tcp_urg
        )

        full_packet = (
            struct.pack("!BBHHHBB", ip_ihl_ver, 0, 20 + 20, 0, ip_ttl, ip_proto, 0)
            + ip_src + ip_dst
            + tcp_header
        )

        send_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        send_sock.sendto(full_packet, (ip, 0))
        send_sock.close()

        # Listen for SYN-ACK
        recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        recv_sock.settimeout(timeout)
        deadline = time.monotonic() + timeout
        ttl_val: int | None = None
        win_size: int | None = None

        while time.monotonic() < deadline:
            try:
                pkt, addr = recv_sock.recvfrom(65535)
                if addr[0] == ip:
                    # Parse IP header to get TTL
                    ihl = (pkt[0] & 0x0F) * 4
                    ttl_val = pkt[8]
                    # Parse TCP header to get window size
                    tcp_offset = ihl + 14  # +14 for Ethernet header in raw
                    if len(pkt) > tcp_offset + 15:
                        win_size = struct.unpack("!H", pkt[tcp_offset + 14:tcp_offset + 16])[0]
                    break
            except socket.timeout:
                break

        recv_sock.close()
        return True, ttl_val, win_size

    except (OSError, PermissionError):
        # Fall back to connect-based method
        return tcp_connect_with_ttl_simple(ip, port, timeout)


def tcp_connect_with_ttl_simple(
    ip: str,
    port: int,
    timeout: float = 1.5,
) -> tuple[bool, int | None, int | None]:
    """Simple TCP connect that returns success but no TTL info."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        if result == 0:
            return True, None, None
        return False, None, None
    except (socket.timeout, OSError):
        return False, None, None


def checksum(data: bytes) -> int:
    """Calculate TCP/IP checksum."""
    if len(data) % 2:
        data += b'\x00'
    s = 0
    for i in range(0, len(data), 2):
        w = (data[i] << 8) + data[i + 1]
        s += w
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


def get_local_ip() -> str:
    """Get the local IP used for outbound connections."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"
