"""Device fingerprinting — MAC OUI lookup, banner parsing, hardware classification."""

from __future__ import annotations

import logging
import re

logger = logging.getLogger(__name__)

# IEEE OUI prefix registry for surveillance/IoT vendors (first 3 bytes of MAC)
_OUI_REGISTRY: dict[str, str] = {
    # Hikvision
    "28:57:be": "Hikvision", "44:19:b6": "Hikvision", "54:c4:9e": "Hikvision",
    "20:a6:cd": "Hikvision", "c0:56:e3": "Hikvision", "b8:a3:86": "Hikvision",
    "ac:cc:8e": "Hikvision", "d4:9c:0e": "Hikvision", "3c:e5:a6": "Hikvision",
    "a4:14:37": "Hikvision", "e0:50:8b": "Hikvision", "14:dd:a9": "Hikvision",
    # Dahua
    "3c:ef:8c": "Dahua", "e0:50:8b": "Dahua", "40:f4:ec": "Dahua",
    "fc:ad:0f": "Dahua", "00:50:a4": "Dahua", "c4:9e:12": "Dahua",
    "8c:6a:d9": "Dahua", "2b:60:78": "Dahua", "1c:60:78": "Dahua",
    # Axis
    "00:40:8c": "Axis", "ac:cc:8e": "Axis", "b8:a3:86": "Axis",
    "00:40:b0": "Axis",
    # CP Plus
    "28:57:be": "CP Plus", "44:19:b6": "CP Plus",
    # Reolink
    "d0:25:98": "Reolink", "44:87:fc": "Reolink",
    # Uniview
    "00:14:95": "Uniview", "44:87:fc": "Uniview",
    # Bosch
    "00:0b:97": "Bosch", "08:00:06": "Bosch",
    # Sony
    "00:04:1d": "Sony", "00:1a:79": "Sony",
    # Panasonic
    "00:0e:8f": "Panasonic", "00:11:32": "Panasonic",
    # Generic IoT manufacturers
    "dc:a6:32": "Raspberry Pi", "b8:27:eb": "Raspberry Pi",
    "18:b4:30": "Espressif (ESP32)", "30:ae:a4": "Espressif",
    "ec:fa:bc": "Espressif", "a4:cf:12": "Espressif",
    "00:1a:2b": "Arduino",
    "00:1b:2f": "Ubiquiti", "24:5a:4c": "Ubiquiti",
    "f0:9f:c2": "Ubiquiti", "18:e8:29": "Ubiquiti",
    "fc:ec:da": "Ubiquiti", "24:4b:fe": "ASUSTek",
    "00:1e:58": "D-Link", "1c:7e:e5": "D-Link",
    "b8:a3:86": "Netgear", "c4:04:15": "Netgear",
}

# HTTP title/vendor detection patterns
_VENDOR_PATTERNS: list[tuple[str, str, str]] = [
    (r"hikvision|hik-[a-z]", "Hikvision", "CCTV Camera"),
    (r"dahua|dh-[a-z]|dahua-ipc", "Dahua", "CCTV Camera"),
    (r"axis|axis-communication", "Axis", "CCTV Camera"),
    (r"cp[\s-]?plus", "CP Plus", "CCTV Camera"),
    (r"uniview|unv-[a-z]", "Uniview", "CCTV Camera"),
    (r"reolink", "Reolink", "CCTV Camera"),
    (r"tp[\s-]?link|tpncp", "TP-Link", "Generic IoT"),
    (r"netgear", "Netgear", "Generic IoT"),
    (r"d[\s-]?link", "D-Link", "Generic IoT"),
    (r"espressif|esp[\s-]?32|esp[\s-]?8266", "Espressif", "Generic IoT"),
    (r"raspberry[\s-]?pi", "Raspberry Pi", "Generic IoT"),
    (r"ubiquiti|ubnt", "Ubiquiti", "Generic IoT"),
    (r"cisco", "Cisco", "Generic IoT"),
    (r"hp[\s-]?printer|hewlett", "HP", "Generic IoT"),
]

# RTSP banner vendor patterns
_RTSP_VENDOR_PATTERNS: list[tuple[str, str, str]] = [
    (r"Hikvision|HIKVISION", "Hikvision", "CCTV Camera"),
    (r"Dahua|DAHUA", "Dahua", "CCTV Camera"),
    (r"Live555", "Unknown (Live555)", "CCTV Camera"),
    (r"VRPC|DVRPC", "DVR", "DVR"),
    (r"NVRPC", "NVR", "NVR"),
    (r"XVR", "XVR", "XVR"),
]

# Device classification based on open ports and services
_DEVICE_PORT_PATTERNS: list[tuple[set, str]] = [
    ({554, 80, 3702}, "CCTV Camera"),
    ({554, 80}, "CCTV Camera"),
    ({80, 3702, 8000}, "NVR"),
    ({80, 8000, 8080}, "NVR"),
    ({80, 8000}, "DVR"),
    ({80, 8080}, "XVR"),
]


def lookup_oui(mac_address: str | None) -> str:
    """Look up vendor from MAC address OUI prefix."""
    if not mac_address:
        return "Unknown"

    # Normalize MAC
    mac = mac_address.lower().replace("-", ":").strip()
    if len(mac) < 8:
        return "Unknown"

    # Try first 8 chars (XX:XX:XX)
    prefix = mac[:8]
    return _OUI_REGISTRY.get(prefix, "Unknown")


def classify_device_from_title(title: str | None) -> tuple[str, str]:
    """Classify device vendor and type from HTTP title.

    Returns (vendor, classification).
    """
    if not title:
        return "Unknown", "Generic IoT"

    title_lower = title.lower()

    for pattern, vendor, classification in _VENDOR_PATTERNS:
        if re.search(pattern, title_lower):
            return vendor, classification

    return "Unknown", "Generic IoT"


def classify_device_from_rtsp(banner: str | None) -> tuple[str, str]:
    """Classify device from RTSP server banner."""
    if not banner:
        return "Unknown", "Generic IoT"

    banner_lower = banner.lower()

    for pattern, vendor, classification in _RTSP_VENDOR_PATTERNS:
        if re.search(pattern, banner_lower):
            return vendor, classification

    return "Unknown", "Generic IoT"


def classify_from_ports(open_ports: list[int]) -> str:
    """Classify device type from open port pattern."""
    port_set = set(open_ports)
    for pattern, classification in _DEVICE_PORT_PATTERNS:
        if pattern.issubset(port_set):
            return classification
    return "Generic IoT"


def extract_firmware_version(headers: dict, banner: str | None, title: str | None) -> str:
    """Extract firmware version from HTTP headers, RTSP banner, or title."""
    # Check common firmware header fields
    for key in ["x-app-version", "x-firmware-version", "x-device-version", "x-version"]:
        val = headers.get(key.lower())
        if val:
            return val

    # Check banner for version patterns
    combined = ""
    if banner:
        combined += banner
    if title:
        combined += " " + title

    # Look for version-like strings
    version_patterns = [
        r"v?(\d+\.\d+\.\d+\.\d+)",
        r"firmware[:\s]+v?([\d.]+)",
        r"version[:\s]+v?([\d.]+)",
        r"build[:\s]+(\d+)",
    ]
    for pat in version_patterns:
        match = re.search(pat, combined, re.IGNORECASE)
        if match:
            return match.group(1)

    return "Unknown"


def fingerprint_device(
    ip: str,
    mac_address: str | None,
    protocol_data: dict,
) -> dict:
    """Perform multi-factor device fingerprinting.

    Combines OUI lookup, banner/title parsing, and port-based classification.

    Returns enriched device dict.
    """
    # 1. OUI Lookup
    oui_vendor = lookup_oui(mac_address)

    # 2. HTTP classification
    http_title = None
    http_vendor = "Unknown"
    http_class = "Generic IoT"
    headers = {}

    http_results = protocol_data.get("http_results", [])
    for hr in http_results:
        if hr.get("title"):
            http_title = hr["title"]
            http_vendor, http_class = classify_device_from_title(hr["title"])
            headers = hr.get("headers", {})
            break

    # 3. RTSP classification
    rtsp_vendor = "Unknown"
    rtsp_class = "Generic IoT"
    rtsp_banner = None

    rtsp_data = protocol_data.get("rtsp")
    if rtsp_data and rtsp_data.get("open"):
        rtsp_banner = rtsp_data.get("banner")
        rtsp_vendor, rtsp_class = classify_device_from_rtsp(rtsp_banner)

    # 4. Firmware extraction
    firmware = extract_firmware_version(headers, rtsp_banner, http_title)

    # 5. Determine final vendor (priority: OUI > HTTP > RTSP)
    vendor = oui_vendor if oui_vendor != "Unknown" else (
        http_vendor if http_vendor != "Unknown" else rtsp_vendor
    )

    # 6. Determine classification (priority: HTTP > RTSP > port-based)
    classification = http_class if http_class != "Generic IoT" else (
        rtsp_class if rtsp_class != "Generic IoT" else "Generic IoT"
    )

    # Override with OUI-based classification if available
    if vendor in ("Hikvision", "Dahua", "Axis", "CP Plus", "Reolink", "Uniview"):
        classification = "CCTV Camera"

    return {
        "ip_address": ip,
        "mac_address": mac_address,
        "oui_vendor": oui_vendor,
        "classification": classification,
        "identified_vendor": vendor,
        "firmware_version": firmware,
        "protocols_detected": protocol_data.get("protocols_detected", []),
        "http_title": http_title,
        "rtsp_banner": rtsp_banner,
        "headers": headers,
    }
