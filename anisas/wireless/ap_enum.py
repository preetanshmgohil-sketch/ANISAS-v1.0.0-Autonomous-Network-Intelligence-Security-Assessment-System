"""Access Point enumeration via system wireless tools."""

from __future__ import annotations

import logging
import platform
import re
import subprocess

logger = logging.getLogger(__name__)


def _run_nmcli_scan() -> list[dict]:
    """Parse nmcli device wifi list for AP information."""
    aps: list[dict] = []
    try:
        result = subprocess.run(
            ["nmcli", "-t", "-f", "SSID,BSSID,CHAN,RATE,BARS,SECURITY", "device", "wifi", "list"],
            capture_output=True, text=True, timeout=10,
        )
        for line in result.stdout.strip().splitlines():
            parts = line.split(":")
            if len(parts) >= 6:
                ssid = parts[0].strip()
                bssid = parts[1].strip()
                channel_str = parts[2].strip()
                bars = parts[4].strip()
                security = parts[5].strip()

                if not bssid or bssid == "BSSID":
                    continue

                # Convert bars to approximate RSSI
                signal = _bars_to_rssi(bars)

                # Parse encryption type
                encryption = _parse_encryption(security)

                aps.append({
                    "ssid": ssid,
                    "bssid": bssid,
                    "channel": int(channel_str) if channel_str.isdigit() else 0,
                    "signal_rssi": signal,
                    "encryption_type": encryption,
                })
    except (FileNotFoundError, subprocess.TimeoutExpired):
        logger.debug("nmcli not available")
    return aps


def _run_iwlist_scan() -> list[dict]:
    """Parse iwlist scan output for AP information."""
    aps: list[dict] = []
    try:
        result = subprocess.run(
            ["iwlist", "scanning"],
            capture_output=True, text=True, timeout=15,
        )
        current: dict = {}
        for line in result.stdout.splitlines():
            line = line.strip()
            if "Cell" in line and "Address:" in line:
                if current.get("bssid"):
                    aps.append(current)
                mac_match = re.search(r"Address:\s*([0-9A-Fa-f:]{17})", line)
                current = {"bssid": mac_match.group(1) if mac_match else "", "ssid": "", "channel": 0, "signal_rssi": 0, "encryption_type": "Unknown"}
            elif line.startswith("ESSID:"):
                current["ssid"] = line.split('"')[1] if '"' in line else ""
            elif "Channel:" in line:
                ch = re.search(r"Channel:(\d+)", line)
                if ch:
                    current["channel"] = int(ch.group(1))
            elif "Signal level=" in line:
                sig = re.search(r"Signal level=(-?\d+)", line)
                if sig:
                    current["signal_rssi"] = int(sig.group(1))
            elif "Encryption key:" in line:
                if "off" in line.lower():
                    current["encryption_type"] = "OPEN"
            elif "IE:" in line:
                ie = line.lower()
                if "wpa3" in ie or "sae" in ie:
                    current["encryption_type"] = "WPA3-SAE"
                elif "wpa2" in ie or "rsn" in ie:
                    current["encryption_type"] = "WPA2-PSK"
                elif "wpa " in ie:
                    current["encryption_type"] = "WPA-PSK"

        if current.get("bssid"):
            aps.append(current)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        logger.debug("iwlist not available")
    return aps


def _run_netsh_scan() -> list[dict]:
    """Parse netsh wlan show networks on Windows."""
    aps: list[dict] = []
    try:
        result = subprocess.run(
            ["netsh", "wlan", "show", "networks", "mode=bssid"],
            capture_output=True, text=True, timeout=10,
        )
        current: dict = {}
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.startswith("SSID") and ":" in line:
                if current.get("ssid"):
                    aps.append(current)
                current = {"ssid": line.split(":", 1)[1].strip(), "bssid": "", "channel": 0, "signal_rssi": 0, "encryption_type": "Unknown"}
            elif line.startswith("BSSID") and ":" in line:
                current["bssid"] = line.split(":", 1)[1].strip()
            elif line.startswith("Channel") and ":" in line:
                ch = line.split(":", 1)[1].strip()
                if ch.isdigit():
                    current["channel"] = int(ch)
            elif line.startswith("Signal") and ":" in line:
                sig = line.split(":", 1)[1].strip().replace("%", "")
                if sig.isdigit():
                    current["signal_rssi"] = _percent_to_rssi(int(sig))
            elif "Authentication" in line and ":" in line:
                auth = line.split(":", 1)[1].strip()
                current["encryption_type"] = _parse_windows_auth(auth)

        if current.get("ssid"):
            aps.append(current)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        logger.debug("netsh not available")
    return aps


def _bars_to_rssi(bars: str) -> int:
    """Convert signal bars to approximate RSSI dBm."""
    bar_count = bars.count("*") + bars.count("▂▄▆█")
    mapping = {0: -100, 1: -80, 2: -65, 3: -50, 4: -35, 5: -30}
    return mapping.get(bar_count, -70)


def _percent_to_rssi(percent: int) -> int:
    """Convert signal percentage to approximate RSSI dBm."""
    return max(-100, min(0, int((percent / 2.0) - 100)))


def _parse_encryption(security_str: str) -> str:
    """Parse encryption type from nmcli security string."""
    s = security_str.upper()
    if "WPA3" in s or "SAE" in s:
        return "WPA3-SAE"
    if "WPA2" in s or "RSN" in s:
        return "WPA2-PSK"
    if "WPA" in s:
        return "WPA-PSK"
    if "OPEN" in s or not security_str.strip():
        return "OPEN"
    if "802.1X" in s or "EAP" in s:
        return "802.1X"
    return "Unknown"


def _parse_windows_auth(auth: str) -> str:
    """Parse Windows netsh authentication string."""
    a = auth.upper()
    if "WPA3" in a or "SAE" in a:
        return "WPA3-SAE"
    if "WPA2" in a:
        return "WPA2-PSK"
    if "WPA" in a:
        return "WPA-PSK"
    if "OPEN" in a:
        return "OPEN"
    if "802.1X" in a:
        return "802.1X"
    return "Unknown"


def enumerate_aps() -> list[dict]:
    """Discover nearby Access Points using available system tools.

    Tries nmcli -> iwlist -> netsh based on platform.
    Returns list of AP dicts.
    """
    system = platform.system().lower()

    # Try nmcli first (cross-platform, most common)
    aps = _run_nmcli_scan()
    if aps:
        logger.info("Found %d APs via nmcli", len(aps))
        return aps

    # Try platform-specific tools
    if system == "linux":
        aps = _run_iwlist_scan()
        if aps:
            logger.info("Found %d APs via iwlist", len(aps))
            return aps
    elif system == "windows":
        aps = _run_netsh_scan()
        if aps:
            logger.info("Found %d APs via netsh", len(aps))
            return aps

    logger.warning("No wireless scanning tools available. Returning empty AP list.")
    return []
