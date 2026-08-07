"""Targeted protocol scanning — RTSP, HTTP, ONVIF WS-Discovery probing."""

from __future__ import annotations

import logging
import socket
import time

logger = logging.getLogger(__name__)

# Surveillance-relevant ports
_RTSP_PORTS = [554, 8554, 5544]
_HTTP_PORTS = [80, 8080, 8000, 8888, 443, 8443]
_ONVIF_PORTS = [80, 8000, 8080]
_UDP_DISCOVERY_PORT = 3702

_TIMEOUT = 2.0


def probe_rtsp(ip: str, port: int = 554, timeout: float = _TIMEOUT) -> dict:
    """Probe RTSP port and extract server banner.

    Returns dict with open, banner, server, details.
    """
    result = {"open": False, "banner": None, "server": None, "port": port}
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        err = sock.connect_ex((ip, port))
        if err != 0:
            sock.close()
            return result

        result["open"] = True

        # Send RTSP OPTIONS request
        request = (
            f"OPTIONS rtsp://{ip}:{port}/ RTSP/1.0\r\n"
            f"CSeq: 1\r\n"
            f"User-Agent: ANISAS-Scanner\r\n"
            f"\r\n"
        )
        sock.sendall(request.encode())

        try:
            data = sock.recv(1024)
            if data:
                banner = data.decode("utf-8", errors="replace").strip()
                result["banner"] = banner[:512]
                # Parse Server header
                for line in banner.split("\r\n"):
                    if line.lower().startswith("server:"):
                        result["server"] = line.split(":", 1)[1].strip()
                        break
        except socket.timeout:
            pass  # banner read timeout — expected for non-responding services

        sock.close()
    except (socket.timeout, OSError):
        pass  # connection failed — service likely not running

    return result


def probe_http(ip: str, port: int = 80, timeout: float = _TIMEOUT) -> dict:
    """Probe HTTP port and extract title, server header, and response info.

    Returns dict with open, title, server, status_code, headers, details.
    """
    result = {
        "open": False,
        "title": None,
        "server": None,
        "status_code": 0,
        "headers": {},
        "port": port,
    }

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        err = sock.connect_ex((ip, port))
        if err != 0:
            sock.close()
            return result

        result["open"] = True

        request = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {ip}\r\n"
            f"User-Agent: Mozilla/5.0 (compatible; ANISAS-Scanner)\r\n"
            f"Accept: text/html\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        )
        sock.sendall(request.encode())

        response = b""
        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
                if len(response) > 65536:
                    break
            except socket.timeout:
                break

        sock.close()

        decoded = response.decode("utf-8", errors="replace")
        lines = decoded.split("\r\n")

        # Parse status
        if lines and lines[0].startswith("HTTP/"):
            parts = lines[0].split(" ", 2)
            if len(parts) >= 2 and parts[1].isdigit():
                result["status_code"] = int(parts[1])

        # Parse headers
        for line in lines[1:]:
            if ":" in line and line.strip():
                key, _, value = line.partition(":")
                result["headers"][key.strip().lower()] = value.strip()

        result["server"] = result["headers"].get("server")

        # Extract title
        body_start = decoded.find("<title")
        if body_start >= 0:
            title_start = decoded.find(">", body_start)
            if title_start >= 0:
                title_end = decoded.find("</title", title_start)
                if title_end >= 0:
                    result["title"] = decoded[title_start + 1:title_end].strip()[:256]

    except (socket.timeout, OSError):
        pass  # HTTP probe failed — acceptable for non-HTTP services

    return result


def probe_onvif_discovery(ip: str, timeout: float = _TIMEOUT) -> dict:
    """Send ONVIF WS-Discovery multicast probe via UDP.

    Returns dict with responded, details.
    """
    result = {"responded": False, "details": ""}

    # WS-Discovery SOAP probe
    soap_envelope = '<?xml version="1.0" encoding="UTF-8"?>'
    soap_envelope += '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"'
    soap_envelope += ' xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery"'
    soap_envelope += ' xmlns:dn="http://www.onvif.org/ver10/network/wsdl">'
    soap_envelope += '<s:Body>'
    soap_envelope += '<d:Probe/>'
    soap_envelope += '</s:Body>'
    soap_envelope += '</s:Envelope>'

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.settimeout(timeout)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 4)

        # Send to ONVIF multicast address
        sock.sendto(soap_envelope.encode(), ("239.255.255.250", 3702))

        # Also send unicast to the target
        sock.sendto(soap_envelope.encode(), (ip, 3702))

        try:
            data, addr = sock.recvfrom(4096)
            if data:
                result["responded"] = True
                result["details"] = data.decode("utf-8", errors="replace")[:512]
        except socket.timeout:
            pass  # UDP response timeout — expected for many protocols

        sock.close()
    except (socket.timeout, OSError) as e:
        result["details"] = str(e)

    return result


def scan_host_protocols(
    ip: str,
    timeout: float = _TIMEOUT,
) -> dict:
    """Run full protocol scan on a single host.

    Returns dict with protocols_detected, rtsp, http_results, onvif.
    """
    protocols = []
    rtsp_result = None
    http_results = []
    onvif_result = None

    # RTSP probes
    for port in _RTSP_PORTS:
        res = probe_rtsp(ip, port, timeout)
        if res["open"]:
            protocols.append("RTSP")
            rtsp_result = res
            break

    # HTTP probes
    for port in _HTTP_PORTS:
        res = probe_http(ip, port, timeout)
        if res["open"]:
            protocols.append("HTTP")
            http_results.append(res)

    # ONVIF probe
    onvif_result = probe_onvif_discovery(ip, timeout)
    if onvif_result["responded"]:
        protocols.append("ONVIF")

    return {
        "ip": ip,
        "protocols_detected": protocols,
        "rtsp": rtsp_result,
        "http_results": http_results,
        "onvif": onvif_result,
    }


def scan_hosts_protocols(
    hosts: list[str],
    timeout: float = _TIMEOUT,
) -> list[dict]:
    """Scan multiple hosts for surveillance protocols.

    Returns list of protocol scan results per host.
    """
    results = []
    for ip in hosts:
        result = scan_host_protocols(ip, timeout)
        results.append(result)
    return results
