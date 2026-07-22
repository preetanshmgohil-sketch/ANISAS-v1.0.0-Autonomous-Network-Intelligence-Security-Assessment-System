"""IDS/IPS identification via signature probes and response monitoring."""

from __future__ import annotations

import logging
import random
import socket
import time

logger = logging.getLogger(__name__)

# Benign but detectable probe signatures
_PROBE_SIGNATURES = [
    {"name": "HTTP-GET", "payload": b"GET / HTTP/1.1\r\nHost: test\r\n\r\n"},
    {"name": "HTTP-HEAD", "payload": b"HEAD / HTTP/1.0\r\n\r\n"},
    {"name": "SSH-Banner", "payload": b"SSH-2.0-OpenSSH_8.9\r\n"},
    {"name": "SMTP-EHLO", "payload": b"EHLO test.local\r\n"},
    {"name": "DNS-Query", "payload": b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01"},
]

# Ports to test IDS/IPS on
_IDS_PORTS = [80, 443, 22, 25, 53, 8080, 8443]


def _send_probe(ip: str, port: int, payload: bytes, timeout: float = 2.0) -> dict:
    """Send a probe payload and capture response type."""
    result = {
        "response_type": "no-response",
        "ttl": None,
        "response_size": 0,
        "details": "",
    }

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        err = sock.connect_ex((ip, port))

        if err != 0:
            sock.close()
            result["response_type"] = "connection-refused"
            result["details"] = f"Port {port} closed"
            return result

        # Send probe
        sock.sendall(payload)
        time.sleep(0.3)

        # Try to receive response
        try:
            data = sock.recv(4096)
            if data:
                result["response_type"] = "data-received"
                result["response_size"] = len(data)
                result["details"] = data[:100].decode("utf-8", errors="replace")
        except socket.timeout:
            result["response_type"] = "timeout-after-send"

        sock.close()

    except (socket.timeout, OSError) as e:
        result["response_type"] = "error"
        result["details"] = str(e)

    return result


def _check_rst_injection(ip: str, port: int, timeout: float = 2.0) -> bool:
    """Check if sending a second connection triggers an immediate RST.

    This indicates an inline IDS/IPS resetting the connection.
    """
    rst_detected = False

    # First connection - send probe
    try:
        sock1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock1.settimeout(timeout)
        err1 = sock1.connect_ex((ip, port))
        if err1 == 0:
            sock1.sendall(b"GET /test HTTP/1.1\r\nHost: test\r\n\r\n")
            time.sleep(0.1)
            try:
                data1 = sock1.recv(1024)
            except socket.timeout:
                pass
            sock1.close()
    except (socket.timeout, OSError):
        pass

    # Second connection - check for RST pattern
    try:
        sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock2.settimeout(timeout)
        err2 = sock2.connect_ex((ip, port))
        if err2 == 0:
            # Send slightly different payload to trigger signature
            sock2.sendall(b"GET /admin HTTP/1.1\r\nHost: test\r\n\r\n")
            time.sleep(0.3)
            try:
                data2 = sock2.recv(1024)
                if not data2:
                    # Connection reset = IDS/IPS triggered
                    rst_detected = True
            except (ConnectionResetError, BrokenPipeError):
                rst_detected = True
            except socket.timeout:
                pass
            sock2.close()
    except (socket.timeout, OSError):
        pass

    return rst_detected


def detect_ids_ips(
    ip: str,
    ports: list[int] | None = None,
    timeout: float = 2.0,
) -> dict:
    """Detect IDS/IPS by sending signature probes and monitoring responses.

    Returns dict with detected, action_observed, details.
    """
    if ports is None:
        ports = _IDS_PORTS[:5]

    probe_results = []
    rst_count = 0
    drop_count = 0
    icmp_count = 0

    for port in ports:
        for sig in _PROBE_SIGNATURES[:3]:  # Test first 3 signatures
            res = _send_probe(ip, port, sig["payload"], timeout)
            res["signature"] = sig["name"]
            res["port"] = port
            probe_results.append(res)

            if res["response_type"] == "connection-refused":
                rst_count += 1
            elif res["response_type"] == "timeout-after-send":
                drop_count += 1
            elif "icmp" in res.get("details", "").lower():
                icmp_count += 1

            time.sleep(0.05)

    # Check for RST injection pattern
    rst_injection = False
    for port in ports[:3]:
        if _check_rst_injection(ip, port, timeout):
            rst_injection = True
            break

    total_probes = len(probe_results)

    # IDS/IPS detection logic
    detected = False
    action = "None"

    if rst_injection:
        detected = True
        action = "TCP-RST"
    elif drop_count > total_probes * 0.3:
        detected = True
        action = "Drop"
    elif icmp_count > 0:
        detected = True
        action = "ICMP-Unreachable"
    elif rst_count > total_probes * 0.5:
        # High RST rate could mean IDS resetting
        detected = True
        action = "TCP-RST"

    return {
        "detected": detected,
        "action_observed": action,
        "details": {
            "probe_results": probe_results[:10],  # Limit for readability
            "rst_injection_detected": rst_injection,
            "rst_count": rst_count,
            "drop_count": drop_count,
            "icmp_count": icmp_count,
        },
    }
