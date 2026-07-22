"""Data ingestion and preprocessing from Modules 1-5."""

from __future__ import annotations

import json
import logging
import os

logger = logging.getLogger(__name__)

# Port-to-feature mapping for device classification
_PORT_FEATURES: dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 135: "msrpc", 139: "netbios",
    143: "imap", 443: "https", 445: "smb", 554: "rtsp",
    8080: "http_alt", 8443: "https_alt", 3306: "mysql",
    3389: "rdp", 5432: "postgresql", 5900: "vnc", 8000: "http_mgmt",
    8888: "http_proxy", 9090: "web_console", 27017: "mongodb",
    3702: "onvif",
}

# Device type classification rules based on port combinations
_DEVICE_SIGNATURES: list[tuple[set, str]] = [
    ({554, 80, 3702}, "Surveillance Device"),
    ({554, 80}, "Surveillance Device"),
    ({80, 3702}, "Surveillance Device"),
    ({80, 8000}, "Surveillance Device"),
    ({22, 80, 443, 3306}, "Server"),
    ({22, 80, 443, 5432}, "Server"),
    ({22, 80, 443, 27017}, "Server"),
    ({135, 139, 445, 3389}, "Workstation"),
    ({445, 3389}, "Workstation"),
    ({135, 445}, "Workstation"),
    ({22, 80, 443}, "Server"),
    ({80, 443}, "Server"),
    ({22}, "Server"),
    ({23, 80}, "Network Gear"),
    ({161, 162}, "Network Gear"),
    ({22, 80}, "IoT/Embedded"),
    ({80, 1883}, "IoT/Embedded"),
    ({80, 8888}, "IoT/Embedded"),
    ({80,}, "IoT/Embedded"),
]


def ingest_modules(
    module_paths: dict[str, str] | None = None,
    *,
    module1_data: dict | None = None,
    module2_data: dict | None = None,
    module3_data: dict | None = None,
    module4_data: dict | None = None,
    module5_data: dict | None = None,
) -> dict:
    """Ingest JSON outputs from Modules 1-5 into a unified data structure.

    Args:
        module_paths: Dict mapping module names to JSON file paths.
        module1-5_data: Pre-loaded module data dicts (overrides file paths).

    Returns:
        Unified data dict ready for ML processing.
    """
    data = {
        "asn_details": [],
        "ip_prefixes": [],
        "active_hosts": [],
        "discovered_subnets": [],
        "perimeter_defenses": {},
        "surveillance_devices": [],
        "access_points": [],
        "enumerated_clients": [],
    }

    # Load from files if paths provided
    if module_paths:
        for key, path in module_paths.items():
            if os.path.isfile(path):
                try:
                    with open(path, "r", encoding="utf-8") as f:
                        loaded = json.load(f)
                    if key == "module1":
                        module1_data = loaded
                    elif key == "module2":
                        module2_data = loaded
                    elif key == "module3":
                        module3_data = loaded
                    elif key == "module4":
                        module4_data = loaded
                    elif key == "module5":
                        module5_data = loaded
                except (json.JSONDecodeError, FileNotFoundError) as e:
                    logger.warning("Failed to load %s: %s", path, e)

    # Merge Module 1 data
    if module1_data:
        data["asn_details"] = module1_data.get("asn_details", [])
        data["ip_prefixes"] = module1_data.get("ip_prefixes", [])

    # Merge Module 2 data
    if module2_data:
        data["active_hosts"] = module2_data.get("active_hosts", [])
        data["discovered_subnets"] = module2_data.get("discovered_subnets", [])

    # Merge Module 3 data
    if module3_data:
        data["perimeter_defenses"] = module3_data.get("perimeter_defenses", {})

    # Merge Module 4 data
    if module4_data:
        data["surveillance_devices"] = module4_data.get("surveillance_devices", [])

    # Merge Module 5 data
    if module5_data:
        data["access_points"] = module5_data.get("access_points", [])
        data["enumerated_clients"] = module5_data.get("enumerated_clients", [])

    return data


def extract_feature_vector(host: dict) -> list[float]:
    """Extract a numerical feature vector from a host for ML classification.

    Features: one-hot encoded ports + TTL + window size.
    """
    # Port features (one-hot for common ports)
    open_ports = set()
    for port_info in host.get("open_ports", []):
        p = port_info.get("port", 0)
        if p in _PORT_FEATURES:
            open_ports.add(p)

    port_vector = [1.0 if p in open_ports else 0.0 for p in sorted(_PORT_FEATURES.keys())]

    # TTL feature
    os_fp = host.get("os_fingerprint", {})
    ttl = os_fp.get("initial_ttl", 0) / 255.0  # Normalize to 0-1

    # Window size feature
    ws = os_fp.get("tcp_window_size") or 0
    ws_norm = min(ws / 65535.0, 1.0)  # Normalize to 0-1

    return port_vector + [ttl, ws_norm]


def extract_os_features(host: dict) -> list[float]:
    """Extract features for OS fingerprinting."""
    os_fp = host.get("os_fingerprint", {})
    ttl = os_fp.get("initial_ttl", 0)
    ws = os_fp.get("tcp_window_size") or 0

    # Additional features from banners
    banners = []
    for port_info in host.get("open_ports", []):
        b = port_info.get("banner", "")
        if b:
            banners.append(b)

    # Simple banner features
    has_ssh = 1.0 if any("ssh" in b.lower() for b in banners) else 0.0
    has_http = 1.0 if any("http" in b.lower() for b in banners) else 0.0
    has_windows = 1.0 if any("microsoft" in b.lower() or "iis" in b.lower() for b in banners) else 0.0
    has_linux = 1.0 if any("ubuntu" in b.lower() or "debian" in b.lower() or "centos" in b.lower() for b in banners) else 0.0

    return [float(ttl), float(ws), has_ssh, has_http, has_windows, has_linux]
