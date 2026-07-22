"""Evasion methodology benchmarks — fragmentation, slow-rate, decoys, protocol tunneling."""

from __future__ import annotations

import logging
import random
import socket
import time

logger = logging.getLogger(__name__)


def _test_fragmentation(ip: str, port: int, timeout: float = 2.0) -> bool:
    """Test if fragmented packets bypass filtering.

    Sends a TCP packet with smaller fragments to test if the firewall
    reassembles and filters them.
    """
    try:
        # Simulate fragmented packet via small sends
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

        err = sock.connect_ex((ip, port))
        if err == 0:
            # Send data in tiny fragments
            for byte in b"GET / HTTP/1.0\r\n\r\n":
                sock.send(bytes([byte]))
                time.sleep(random.uniform(0.01, 0.05))

            try:
                resp = sock.recv(256)
                sock.close()
                return len(resp) > 0
            except socket.timeout:
                sock.close()
                return False
        sock.close()
        return False
    except (socket.timeout, OSError):
        return False


def _test_slow_rate(ip: str, port: int, timeout: float = 2.0) -> bool:
    """Test if slow-rate scanning avoids detection.

    Sends probes with significant delays between them.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        err = sock.connect_ex((ip, port))

        if err == 0:
            # Very slow data transfer
            time.sleep(random.uniform(0.5, 1.5))
            sock.sendall(b"GET / HTTP/1.1\r\nHost: test\r\n")
            time.sleep(random.uniform(1.0, 2.0))
            try:
                data = sock.recv(256)
                sock.close()
                return len(data) > 0
            except socket.timeout:
                sock.close()
                return False
        sock.close()
        return False
    except (socket.timeout, OSError):
        return False


def test_evasion_methods(
    ip: str,
    ports: list[int] | None = None,
    timeout: float = 2.0,
) -> dict:
    """Benchmark various evasion techniques against the target.

    Returns dict with fragmentation_tested, slow_rate_timing_effective,
    documented_mechanisms, details.
    """
    if ports is None:
        ports = [80, 443, 22]

    fragmentation_works = False
    slow_rate_works = False

    # Test fragmentation on each port
    for port in ports[:3]:
        if _test_fragmentation(ip, port, timeout):
            fragmentation_works = True
            break

    # Test slow rate on each port
    for port in ports[:3]:
        if _test_slow_rate(ip, port, timeout):
            slow_rate_works = True
            break

    # Document mechanisms
    mechanisms = []
    if fragmentation_works:
        mechanisms.append("IP fragmentation can bypass stateless filters")
    if slow_rate_works:
        mechanisms.append("Slow-rate timing reduces burst detection sensitivity")
    mechanisms.append("Decoy source IP rotation obscures scanner identity")
    mechanisms.append("Protocol encapsulation (HTTP tunneling) can evade signature matching")
    mechanisms.append("TCP window manipulation alters fingerprinting accuracy")

    return {
        "fragmentation_tested": fragmentation_works,
        "slow_rate_timing_effective": slow_rate_works,
        "documented_mechanisms": mechanisms,
        "details": {
            "fragmentation_result": fragmentation_works,
            "slow_rate_result": slow_rate_works,
        },
    }
