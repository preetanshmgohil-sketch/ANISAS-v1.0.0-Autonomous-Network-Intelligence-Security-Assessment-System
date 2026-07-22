"""Firewall infrastructure detection via ACK/RST probes and TTL analysis."""

from __future__ import annotations

import logging
import random
import socket
import struct
import time

logger = logging.getLogger(__name__)

# Ports commonly tested for firewall behavior
_PROBE_PORTS = [22, 23, 80, 443, 3389, 8080, 8443, 3306, 5432, 21]


def _get_local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b'\x00'
    s = 0
    for i in range(0, len(data), 2):
        w = (data[i] << 8) + data[i + 1]
        s += w
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


def _build_tcp_packet(src_ip: str, dst_ip: str, src_port: int, dst_port: int, flags: int, seq: int = 0) -> bytes:
    """Build a raw TCP packet with specified flags."""
    ip_ihl_ver = (4 << 4) | 5
    ip_ttl = 64
    ip_proto = 6

    src = socket.inet_aton(src_ip)
    dst = socket.inet_aton(dst_ip)

    tcp_data_offset = (5 << 4)
    tcp_window = 65535
    tcp_check = 0
    tcp_urg = 0

    pseudo = struct.pack("!4s4sBBH", src, dst, 0, ip_proto, 20)
    tcp_header = struct.pack("!HHIIBBHHH", src_port, dst_port, seq, 0, tcp_data_offset, flags, tcp_window, tcp_check, tcp_urg)
    tcp_check = checksum(pseudo + tcp_header)
    tcp_header = struct.pack("!HHIIBBHHH", src_port, dst_port, seq, 0, tcp_data_offset, flags, tcp_window, tcp_check, tcp_urg)

    ip_header = struct.pack("!BBHHHBB", ip_ihl_ver, 0, 20 + 20, 0, ip_ttl, ip_proto, 0)
    return ip_header + src + dst + tcp_header


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b'\x00'
    s = 0
    for i in range(0, len(data), 2):
        w = (data[i] << 8) + data[i + 1]
        s += w
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


def send_ack_probe(ip: str, port: int, timeout: float = 2.0) -> dict:
    """Send TCP ACK probe and analyze response.

    Returns dict with response_type, ttl, and details.
    """
    result = {"response_type": "no-response", "ttl": None, "details": ""}
    local_ip = _get_local_ip()
    src_port = random.randint(1024, 65535)

    try:
        # Try raw socket approach
        pkt = _build_tcp_packet(local_ip, ip, src_port, port, 0x10)  # ACK flag
        send_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        send_sock.sendto(pkt, (ip, 0))
        send_sock.close()
    except (OSError, PermissionError):
        # Fallback: TCP connect with ACK behavior simulation
        return _ack_probe_fallback(ip, port, timeout)

    # Listen for response
    try:
        recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        recv_sock.settimeout(timeout)
        deadline = time.monotonic() + timeout

        while time.monotonic() < deadline:
            try:
                data, addr = recv_sock.recvfrom(65535)
                if addr[0] == ip:
                    ttl = data[8]
                    ihl = (data[0] & 0x0F) * 4
                    tcp_offset = ihl
                    if len(data) > tcp_offset + 13:
                        flags = data[tcp_offset + 13]
                        if flags & 0x04:  # RST
                            result["response_type"] = "tcp-rst"
                            result["ttl"] = ttl
                            result["details"] = f"RST received on port {port}"
                            break
                        elif flags & 0x12 == 0x12:  # SYN-ACK
                            result["response_type"] = "syn-ack"
                            result["ttl"] = ttl
                            result["details"] = f"SYN-ACK on port {port} (port open)"
                            break
            except socket.timeout:
                break
        recv_sock.close()
    except (OSError, PermissionError):
        pass

    return result


def _ack_probe_fallback(ip: str, port: int, timeout: float) -> dict:
    """Fallback ACK probe using TCP connect."""
    result = {"response_type": "no-response", "ttl": None, "details": ""}
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        err = sock.connect_ex((ip, port))
        if err == 0:
            result["response_type"] = "connected"
            result["details"] = f"TCP connect succeeded on port {port}"
        else:
            result["response_type"] = "tcp-rst"
            result["details"] = f"Connection refused (RST) on port {port}"
        sock.close()
    except (socket.timeout, OSError):
        result["response_type"] = "no-response"
        result["details"] = "Timeout or unreachable"
    return result


def send_rst_probe(ip: str, port: int, timeout: float = 2.0) -> dict:
    """Send TCP RST probe to elicit firewall response."""
    result = {"response_type": "no-response", "ttl": None, "details": ""}
    local_ip = _get_local_ip()
    src_port = random.randint(1024, 65535)
    seq_num = random.randint(0, 2**32 - 1)

    try:
        pkt = _build_tcp_packet(local_ip, ip, src_port, port, 0x04, seq_num)  # RST flag
        send_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        send_sock.sendto(pkt, (ip, 0))
        send_sock.close()
    except (OSError, PermissionError):
        return _rst_probe_fallback(ip, port, timeout)

    # Listen for ICMP unreachable
    try:
        recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        recv_sock.settimeout(timeout)
        deadline = time.monotonic() + timeout

        while time.monotonic() < deadline:
            try:
                data, addr = recv_sock.recvfrom(65535)
                if addr[0] == ip:
                    # ICMP Type 3 = Destination Unreachable
                    if len(data) >= 8 and data[0] == 3:
                        icmp_type = data[0]
                        icmp_code = data[1]
                        result["response_type"] = "icmp-unreachable"
                        result["ttl"] = data[8] if len(data) > 8 else None
                        result["details"] = f"ICMP Type {icmp_type} Code {icmp_code}"
                        break
            except socket.timeout:
                break
        recv_sock.close()
    except (OSError, PermissionError):
        pass

    return result


def _rst_probe_fallback(ip: str, port: int, timeout: float) -> dict:
    """Fallback RST probe using connect."""
    result = {"response_type": "no-response", "ttl": None, "details": ""}
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        err = sock.connect_ex((ip, port))
        # Immediately send RST by closing without shutdown
        sock.close()
        if err == 0:
            result["response_type"] = "connected-then-rst"
            result["details"] = f"Connected then RST on port {port}"
        else:
            result["response_type"] = "tcp-rst"
            result["details"] = f"RST on port {port}"
    except (socket.timeout, OSError):
        result["response_type"] = "no-response"
    return result


def detect_firewall(
    ip: str,
    ports: list[int] | None = None,
    timeout: float = 2.0,
) -> dict:
    """Detect firewall presence by analyzing ACK/RST probe responses.

    Returns dict with detected, type, filtering_behavior.
    """
    if ports is None:
        ports = _PROBE_PORTS[:5]

    ack_responses = []
    rst_responses = []

    for port in ports:
        ack_res = send_ack_probe(ip, port, timeout)
        ack_responses.append(ack_res)
        time.sleep(0.1)

        rst_res = send_rst_probe(ip, port, timeout)
        rst_responses.append(rst_res)
        time.sleep(0.1)

    # Analyze patterns
    ack_rst_count = sum(1 for r in ack_responses if r["response_type"] == "tcp-rst")
    ack_no_response = sum(1 for r in ack_responses if r["response_type"] == "no-response")
    ack_syn_ack = sum(1 for r in ack_responses if r["response_type"] == "syn-ack")
    icmp_unreach = sum(1 for r in rst_responses if r["response_type"] == "icmp-unreachable")

    total = len(ports)

    # Firewall detection logic
    detected = False
    fw_type = "None"
    behavior = "Unfiltered"

    if ack_no_response > total * 0.5:
        # Most ACK probes get no response = stateful firewall dropping
        detected = True
        fw_type = "Stateful"
        behavior = "Filtered"
    elif ack_rst_count > total * 0.5:
        # RST responses to ACK = stateless or no firewall (open)
        if icmp_unreach > 0:
            detected = True
            fw_type = "Stateful"
            behavior = "Filtered"
        else:
            detected = False
            fw_type = "None"
            behavior = "Open-Filtered"
    elif ack_syn_ack > 0:
        # SYN-ACK to ACK = ports are open, no firewall blocking
        detected = False
        fw_type = "None"
        behavior = "Unfiltered"
    elif ack_no_response > 0 and ack_rst_count > 0:
        # Mixed responses = likely stateful with some rules
        detected = True
        fw_type = "Stateful"
        behavior = "Filtered"

    return {
        "detected": detected,
        "type": fw_type,
        "filtering_behavior": behavior,
        "details": {
            "ack_responses": ack_responses,
            "rst_responses": rst_responses,
        },
    }
