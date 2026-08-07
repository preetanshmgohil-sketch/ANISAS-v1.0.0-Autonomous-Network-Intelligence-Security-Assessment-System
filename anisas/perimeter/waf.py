"""WAF identification via HTTP header analysis and signature matching."""

from __future__ import annotations

import logging
import ssl
import socket

logger = logging.getLogger(__name__)

# WAF vendor signatures in headers/cookies
_WAF_SIGNATURES: dict[str, list[str]] = {
    "Cloudflare": [
        "cf-ray", "cloudflare", "cf-cache-status", "__cfduid",
        "server: cloudflare",
    ],
    "AWS WAF": [
        "x-amzn-requestid", "x-amz-cf-id", "x-amz-cf-pop",
        "server: amazons3",
    ],
    "Akamai": [
        "x-akamai-transformed", "server: akamaighost",
        "x-cache-key", "akamai",
    ],
    "Imperva/Incapsula": [
        "x-iinfo", "incap_ses", "_incap_ses",
        "server: imperva",
    ],
    "ModSecurity": [
        "mod_security", "modsecurity", "server: mod_security",
    ],
    "F5 BIG-IP ASM": [
        "tsavi", "server: bigip", "BIGipServer",
    ],
    "Sucuri": [
        "x-sucuri-id", "server: sucuri", "sucuri",
    ],
    "Barracuda": [
        "x-barracuda", "barracuda",
    ],
    "FortiWeb": [
        "server: fortiwaf", "fortiweb",
    ],
    "DenyAll": [
        "server: denyall", "denyall",
    ],
}

# WAF detection test payloads (benign but trigger rules)
_WAF_TEST_PAYLOADS = [
    {"name": "SQLi-Test", "path": "/?id=1' OR '1'='1"},
    {"name": "XSS-Test", "path": "/?q=<script>alert(1)</script>"},
    {"name": "Path-Traversal", "path": "/../../../etc/passwd"},
    {"name": "Normal-Request", "path": "/"},
]


def _send_http_request(
    ip: str,
    port: int,
    path: str,
    use_https: bool = False,
    timeout: float = 3.0,
) -> dict:
    """Send HTTP request and capture response headers."""
    result = {
        "status_code": 0,
        "headers": {},
        "body_snippet": "",
        "error": None,
    }

    try:
        if use_https:
            ctx = ssl.create_default_context()
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((ip, port))
            ssock = ctx.wrap_socket(sock, server_hostname=ip)
            conn = ssock
        else:
            conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            conn.settimeout(timeout)
            conn.connect((ip, port))

        request = f"GET {path} HTTP/1.1\r\nHost: {ip}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n"
        conn.sendall(request.encode())

        response = b""
        while True:
            try:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                response += chunk
                if len(response) > 65536:
                    break
            except socket.timeout:
                break

        conn.close()

        decoded = response.decode("utf-8", errors="replace")
        lines = decoded.split("\r\n")

        # Parse status line
        if lines and lines[0].startswith("HTTP/"):
            parts = lines[0].split(" ", 2)
            if len(parts) >= 2:
                result["status_code"] = int(parts[1]) if parts[1].isdigit() else 0

        # Parse headers
        for line in lines[1:]:
            if ":" in line and line.strip():
                key, _, value = line.partition(":")
                result["headers"][key.strip().lower()] = value.strip()

        # Body snippet
        body_start = decoded.find("\r\n\r\n")
        if body_start >= 0:
            result["body_snippet"] = decoded[body_start + 4:body_start + 514]

    except (socket.timeout, OSError, ssl.SSLError) as e:
        result["error"] = str(e)

    return result


def _match_waf_signatures(headers: dict, body: str) -> tuple[str, list[str]]:
    """Match response against known WAF signatures."""
    combined = " ".join(f"{k}: {v}" for k, v in headers.items()).lower()
    combined += " " + body.lower()

    matched_vendor = "Unknown"
    matched_sigs: list[str] = []

    for vendor, sigs in _WAF_SIGNATURES.items():
        for sig in sigs:
            if sig.lower() in combined:
                matched_vendor = vendor
                matched_sigs.append(sig)

    return matched_vendor, matched_sigs


def detect_waf(
    ip: str,
    ports: list[int] | None = None,
    use_https: bool = False,
    timeout: float = 3.0,
) -> dict:
    """Detect WAF presence by analyzing HTTP responses to benign and malicious payloads.

    Returns dict with detected, vendor, matched_signatures, details.
    """
    if ports is None:
        ports = [80, 443] if use_https else [80]

    vendor = "Unknown"
    all_signatures: list[str] = []
    response_anomalies: list[dict] = []

    for port in ports:
        for test in _WAF_TEST_PAYLOADS:
            resp = _send_http_request(ip, port, test["path"], use_https, timeout)

            if resp["error"]:
                continue

            # Check for WAF indicators
            v, sigs = _match_waf_signatures(resp["headers"], resp["body_snippet"])
            if v != "Unknown":
                vendor = v
                all_signatures.extend(sigs)

            # Check for blocking behavior (403, 406, 501 on malicious payloads)
            if test["name"] != "Normal-Request" and resp["status_code"] in (403, 406, 419, 501, 503):
                response_anomalies.append({
                    "test": test["name"],
                    "status": resp["status_code"],
                    "port": port,
                })

            # Check body for block pages
            body = resp["body_snippet"].lower()
            block_keywords = ["access denied", "blocked", "forbidden", "security alert",
                              "waf", "firewall", "not acceptable"]
            for kw in block_keywords:
                if kw in body and kw not in all_signatures:
                    all_signatures.append(f"block-page:{kw}")

    # WAF detection logic
    detected = False
    if vendor != "Unknown":
        detected = True
    elif len(response_anomalies) >= 2:
        detected = True
        vendor = "Unknown (behavioral detection)"
    elif any("block-page" in s for s in all_signatures):
        detected = True

    return {
        "detected": detected,
        "vendor": vendor,
        "matched_signatures": list(set(all_signatures)),
        "details": {
            "response_anomalies": response_anomalies,
        },
    }
