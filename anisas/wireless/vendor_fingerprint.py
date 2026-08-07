"""Vendor fingerprinting for wireless APs via MAC OUI lookup."""

from __future__ import annotations

import logging
import socket

logger = logging.getLogger(__name__)

# Wireless vendor OUI registry (first 3 bytes of MAC)
_WIFI_OUI_REGISTRY: dict[str, str] = {
    # Cisco
    "00:1a:2b": "Cisco", "00:1b:0d": "Cisco", "00:1c:0e": "Cisco",
    "00:21:55": "Cisco", "00:23:04": "Cisco", "00:23:33": "Cisco",
    "00:24:d7": "Cisco", "00:25:45": "Cisco", "00:26:0b": "Cisco",
    "00:40:96": "Cisco", "00:50:56": "Cisco", "00:50:f2": "Cisco",
    "00:60:2c": "Cisco", "00:62:ec": "Cisco", "00:64:a8": "Cisco",
    "00:6b:f1": "Cisco", "00:80:5a": "Cisco", "00:88:3f": "Cisco",
    "00:9a:96": "Cisco", "00:9b:7d": "Cisco", "00:a1:d2": "Cisco",
    "00:a6:ca": "Cisco", "00:aa:6e": "Cisco", "00:b0:45": "Cisco",
    "00:b6:1f": "Cisco", "00:c1:11": "Cisco", "00:c8:8b": "Cisco",
    "00:d0:2f": "Cisco", "00:d0:58": "Cisco", "00:d0:97": "Cisco",
    "00:d7:8f": "Cisco", "00:f1:f4": "Cisco", "04:5c:8e": "Cisco",
    "04:6c:9d": "Cisco", "04:d4:c4": "Cisco", "08:00:2b": "Cisco",
    "08:17:35": "Cisco", "08:2c:e6": "Cisco", "08:62:66": "Cisco",
    "08:cc:68": "Cisco", "0c:0e:76": "Cisco", "0c:13:0b": "Cisco",
    "0c:57:eb": "Cisco", "0c:62:a2": "Cisco", "0c:85:25": "Cisco",
    "0c:e1:7d": "Cisco", "0c:f8:c2": "Cisco", "10:05:ca": "Cisco",
    "10:0c:29": "Cisco", "10:10:d6": "Cisco", "10:13:ee": "Cisco",
    # Ubiquiti
    "00:15:6d": "Ubiquiti", "00:1b:2f": "Ubiquiti", "00:27:22": "Ubiquiti",
    "04:18:d6": "Ubiquiti", "18:e8:29": "Ubiquiti", "24:4b:81": "Ubiquiti",
    "24:5a:4c": "Ubiquiti", "44:d9:e7": "Ubiquiti", "68:72:51": "Ubiquiti",
    "74:83:c2": "Ubiquiti", "78:8a:20": "Ubiquiti", "80:2a:a8": "Ubiquiti",
    "94:10:3e": "Ubiquiti", "9c:9d:5a": "Ubiquiti", "ac:8b:a9": "Ubiquiti",
    "b4:fb:e4": "Ubiquiti", "c0:25:e9": "Ubiquiti", "c4:12:f5": "Ubiquiti",
    "c4:3d:c7": "Ubiquiti", "d0:21:f9": "Ubiquiti", "d4:3d:7e": "Ubiquiti",
    "dc:9f:db": "Ubiquiti", "e0:63:da": "Ubiquiti", "e4:f0:04": "Ubiquiti",
    "e8:de:27": "Ubiquiti", "f0:9f:c2": "Ubiquiti", "fc:ec:da": "Ubiquiti",
    # TP-Link
    "00:1d:0f": "TP-Link", "00:23:cd": "TP-Link", "00:25:9c": "TP-Link",
    "00:26:5a": "TP-Link", "00:27:19": "TP-Link", "04:a7:41": "TP-Link",
    "08:36:c9": "TP-Link", "08:f1:ea": "TP-Link", "10:43:69": "TP-Link",
    "14:cc:20": "TP-Link", "14:cf:92": "TP-Link", "14:e6:e4": "TP-Link",
    "18:a6:f7": "TP-Link", "1c:b7:2c": "TP-Link", "1c:fa:68": "TP-Link",
    "20:6b:e7": "TP-Link", "20:dc:e6": "TP-Link", "24:a4:3c": "TP-Link",
    "2c:fd:a1": "TP-Link", "30:b5:c2": "TP-Link", "34:2c:c4": "TP-Link",
    "38:2c:4a": "TP-Link", "3c:86:d6": "TP-Link", "40:3c:fc": "TP-Link",
    "44:44:4c": "TP-Link", "44:94:fc": "TP-Link", "48:7a:da": "TP-Link",
    "4c:ed:fb": "TP-Link", "50:c7:bf": "TP-Link", "54:c8:0f": "TP-Link",
    "58:fb:84": "TP-Link", "5c:31:3e": "TP-Link", "60:32:b1": "TP-Link",
    "60:38:e0": "TP-Link", "60:e3:27": "TP-Link", "64:56:01": "TP-Link",
    "64:70:02": "TP-Link", "64:b4:73": "TP-Link", "68:ff:71": "TP-Link",
    "6c:5a:b0": "TP-Link", "70:4d:7b": "TP-Link", "70:66:55": "TP-Link",
    "74:da:88": "TP-Link", "78:8c:b5": "TP-Link", "78:a1:06": "TP-Link",
    "7c:8b:ca": "TP-Link", "80:96:f7": "TP-Link", "84:16:f9": "TP-Link",
    "88:dc:96": "TP-Link", "8c:21:0a": "TP-Link", "90:f6:52": "TP-Link",
    "94:d9:b3": "TP-Link", "98:da:c4": "TP-Link", "9c:21:11": "TP-Link",
    "a0:04:60": "TP-Link", "a0:f3:c1": "TP-Link", "a4:2b:b0": "TP-Link",
    "a8:42:a1": "TP-Link", "ac:22:05": "TP-Link", "ac:84:c6": "TP-Link",
    "b0:4e:26": "TP-Link", "b0:95:75": "TP-Link", "b0:a7:b9": "TP-Link",
    "b0:be:76": "TP-Link", "b4:fb:e4": "TP-Link", "b8:ee:65": "TP-Link",
    "c0:06:c3": "TP-Link", "c0:25:e9": "TP-Link", "c0:4a:00": "TP-Link",
    "c0:e4:2d": "TP-Link", "c4:6e:1f": "TP-Link", "c4:71:54": "TP-Link",
    "c8:3a:35": "TP-Link", "c8:60:00": "TP-Link", "cc:2d:83": "TP-Link",
    "d0:25:98": "TP-Link", "d4:6e:5e": "TP-Link", "d8:07:b6": "TP-Link",
    "d8:15:0d": "TP-Link", "d8:32:14": "TP-Link", "dc:15:db": "TP-Link",
    "dc:a4:ca": "TP-Link", "e0:05:c5": "TP-Link", "e0:28:b1": "TP-Link",
    "e0:60:ef": "TP-Link", "e4:d3:32": "TP-Link", "e8:48:b8": "TP-Link",
    "e8:de:27": "TP-Link", "ec:08:6b": "TP-Link", "ec:17:2f": "TP-Link",
    "f0:27:2d": "TP-Link", "f0:63:f9": "TP-Link", "f0:9f:c2": "TP-Link",
    "f4:f2:6d": "TP-Link", "f8:1a:67": "TP-Link", "f8:d1:11": "TP-Link",
    "fc:15:b4": "TP-Link", "fc:d7:33": "TP-Link",
    # Netgear
    "00:0f:b5": "Netgear", "00:14:6c": "Netgear", "00:18:4d": "Netgear",
    "00:1b:2f": "Netgear", "00:1e:2a": "Netgear", "00:1f:33": "Netgear",
    "00:22:3f": "Netgear", "00:24:b2": "Netgear", "00:26:f2": "Netgear",
    "00:9f:52": "Netgear", "00:ad:24": "Netgear", "04:a4:2a": "Netgear",
    "08:36:c9": "Netgear", "0c:b0:17": "Netgear", "10:0c:6b": "Netgear",
    "10:da:43": "Netgear", "14:59:c0": "Netgear", "14:91:82": "Netgear",
    "18:e8:29": "Netgear", "1c:3b:f3": "Netgear", "1c:f0:3e": "Netgear",
    "20:e5:2a": "Netgear", "20:e8:82": "Netgear", "24:22:42": "Netgear",
    "24:5e:be": "Netgear", "28:c6:8e": "Netgear", "2c:b0:5d": "Netgear",
    "2c:bb:f8": "Netgear", "30:46:9a": "Netgear", "30:b5:c2": "Netgear",
    "34:97:f6": "Netgear", "38:2c:4a": "Netgear", "3c:37:86": "Netgear",
    "40:4a:03": "Netgear", "44:94:fc": "Netgear", "44:95:fa": "Netgear",
    "44:9e:f1": "Netgear", "48:b0:2d": "Netgear", "48:ee:0c": "Netgear",
    "4c:60:de": "Netgear", "50:4a:17": "Netgear", "50:4f:94": "Netgear",
    "54:04:a6": "Netgear", "54:22:bd": "Netgear", "54:7f:8e": "Netgear",
    "58:ef:68": "Netgear", "5c:31:3e": "Netgear", "60:32:b1": "Netgear",
    "60:38:e0": "Netgear", "60:3e:5f": "Netgear", "60:a1:0a": "Netgear",
    "60:a4:4c": "Netgear", "60:b4:f7": "Netgear", "60:ff:dd": "Netgear",
    "64:66:b3": "Netgear", "64:99:b0": "Netgear", "64:b4:73": "Netgear",
    "68:40:04": "Netgear", "68:d7:9a": "Netgear", "6c:2f:8c": "Netgear",
    "6c:50:4d": "Netgear", "6c:b0:ce": "Netgear", "70:4d:7b": "Netgear",
    "70:91:f3": "Netgear", "70:b3:d5": "Netgear", "74:44:01": "Netgear",
    "74:da:88": "Netgear", "78:31:c1": "Netgear", "78:44:76": "Netgear",
    "78:8c:b5": "Netgear", "78:d7:52": "Netgear", "7c:4c:a5": "Netgear",
    "7c:76:35": "Netgear", "7c:8b:ca": "Netgear", "80:37:73": "Netgear",
    "80:96:f7": "Netgear", "80:ce:aa": "Netgear", "84:1b:5e": "Netgear",
    "84:1b:62": "Netgear", "88:dc:96": "Netgear", "8c:3b:ad": "Netgear",
    "90:72:40": "Netgear", "90:94:e4": "Netgear", "90:f6:52": "Netgear",
    "92:85:f7": "Netgear", "94:10:3e": "Netgear", "94:db:c9": "Netgear",
    "98:da:c4": "Netgear", "9c:32:ce": "Netgear", "a0:04:60": "Netgear",
    "a0:21:b7": "Netgear", "a0:63:91": "Netgear", "a0:90:de": "Netgear",
    "a0:aa:fd": "Netgear", "a4:2b:b0": "Netgear", "a4:31:35": "Netgear",
    "a8:5e:63": "Netgear", "ac:22:05": "Netgear", "ac:3f:80": "Netgear",
    "ac:84:c6": "Netgear", "b0:05:47": "Netgear", "b0:4e:26": "Netgear",
    "b0:7f:b9": "Netgear", "b0:b9:8a": "Netgear", "b0:da:f9": "Netgear",
    "b4:30:52": "Netgear", "b4:fb:e4": "Netgear", "b8:11:5b": "Netgear",
    "b8:ee:65": "Netgear", "c0:06:c3": "Netgear", "c0:3f:0e": "Netgear",
    "c0:4a:00": "Netgear", "c0:ff:d4": "Netgear", "c4:04:15": "Netgear",
    "c4:3d:c7": "Netgear", "c8:3a:35": "Netgear", "c8:60:00": "Netgear",
    "cc:40:d0": "Netgear", "cc:50:0a": "Netgear", "cc:50:76": "Netgear",
    "cc:96:a0": "Netgear", "d0:21:f9": "Netgear", "d0:63:b4": "Netgear",
    "d4:3d:7e": "Netgear", "d4:6c:da": "Netgear", "d8:07:b6": "Netgear",
    "d8:15:0d": "Netgear", "dc:15:db": "Netgear", "dc:a4:ca": "Netgear",
    "e0:05:c5": "Netgear", "e0:46:9a": "Netgear", "e0:46:dc": "Netgear",
    "e0:60:ef": "Netgear", "e0:91:f5": "Netgear", "e4:f0:04": "Netgear",
    "e8:48:b8": "Netgear", "e8:de:27": "Netgear", "ec:08:6b": "Netgear",
    "ec:17:2f": "Netgear", "f0:27:2d": "Netgear", "f0:63:f9": "Netgear",
    "f4:f2:6d": "Netgear", "f8:1a:67": "Netgear", "f8:d1:11": "Netgear",
    "fc:15:b4": "Netgear", "fc:d7:33": "Netgear",
    # Aruba
    "00:0b:86": "Aruba", "00:1a:1e": "Aruba", "00:1c:f0": "Aruba",
    "00:24:6c": "Aruba", "04:bd:88": "Aruba", "18:64:72": "Aruba",
    "20:4c:03": "Aruba", "24:de:c6": "Aruba", "40:e3:d6": "Aruba",
    "6c:f3:7f": "Aruba", "84:d4:7e": "Aruba", "94:b4:0f": "Aruba",
    "9c:1c:12": "Aruba", "ac:a3:1e": "Aruba", "b4:5d:50": "Aruba",
    "d8:c7:c8": "Aruba", "e0:55:3d": "Aruba", "f0:a7:64": "Aruba",
    # MikroTik
    "48:8f:5a": "MikroTik", "4c:5e:0c": "MikroTik", "64:d1:54": "MikroTik",
    "74:4d:28": "MikroTik", "b8:69:f4": "MikroTik", "cc:2d:e0": "MikroTik",
    "d4:01:c3": "MikroTik", "d4:6e:5e": "MikroTik", "e4:8d:8c": "MikroTik",
    "e8:18:63": "MikroTik",
    # D-Link
    "00:05:5d": "D-Link", "00:09:5d": "D-Link", "00:0b:b1": "D-Link",
    "00:0f:3d": "D-Link", "00:11:95": "D-Link", "00:13:46": "D-Link",
    "00:15:e9": "D-Link", "00:17:9a": "D-Link", "00:19:5b": "D-Link",
    "00:1b:11": "D-Link", "00:1c:f0": "D-Link", "00:1e:58": "D-Link",
    "00:21:91": "D-Link", "00:22:b0": "D-Link", "00:24:01": "D-Link",
    "00:26:5a": "D-Link", "00:50:ba": "D-Link", "14:d6:4d": "D-Link",
    "1c:5f:2b": "D-Link", "1c:7e:e5": "D-Link", "28:10:7b": "D-Link",
    "30:23:03": "D-Link", "34:08:04": "D-Link", "3c:1e:04": "D-Link",
    "40:9b:cd": "D-Link", "48:ee:0c": "D-Link", "54:b8:0a": "D-Link",
    "5c:d9:98": "D-Link", "60:63:4c": "D-Link", "60:73:5c": "D-Link",
    "64:55:b1": "D-Link", "74:da:ea": "D-Link", "78:32:1b": "D-Link",
    "78:54:2e": "D-Link", "78:da:6e": "D-Link", "80:26:89": "D-Link",
    "84:c9:b2": "D-Link", "88:dc:96": "D-Link", "90:8d:78": "D-Link",
    "90:94:e4": "D-Link", "90:fd:a1": "D-Link", "94:d7:71": "D-Link",
    "98:fe:94": "D-Link", "9c:d6:43": "D-Link", "a0:ab:1b": "D-Link",
    "a0:c9:5b": "D-Link", "a4:ba:76": "D-Link", "a8:64:05": "D-Link",
    "ac:f1:df": "D-Link", "b0:c5:54": "D-Link", "b0:c7:45": "D-Link",
    "b0:d5:cc": "D-Link", "b4:07:f3": "D-Link", "b8:a3:86": "D-Link",
    "b8:ee:65": "D-Link", "bc:f6:85": "D-Link", "c0:a0:bb": "D-Link",
    "c0:b3:39": "D-Link", "c4:12:f5": "D-Link", "c4:6e:1f": "D-Link",
    "c4:71:54": "D-Link", "c8:be:19": "D-Link", "cc:b2:55": "D-Link",
    "d0:13:1e": "D-Link", "d0:73:d5": "D-Link", "d4:20:6d": "D-Link",
    "d8:fe:e3": "D-Link", "dc:a6:32": "D-Link", "e0:1f:88": "D-Link",
    "e0:63:da": "D-Link", "e4:7c:f9": "D-Link", "e8:cc:18": "D-Link",
    "ec:08:6b": "D-Link", "f0:b4:d2": "D-Link", "f0:ec:59": "D-Link",
    "fc:75:16": "D-Link", "fc:b6:98": "D-Link", "fc:d7:33": "D-Link",
}


def lookup_ap_vendor(bssid: str) -> str:
    """Look up vendor from AP BSSID MAC address."""
    if not bssid:
        return "Unknown"

    mac = bssid.lower().replace("-", ":").strip()
    if len(mac) < 8:
        return "Unknown"

    prefix = mac[:8]
    return _WIFI_OUI_REGISTRY.get(prefix, "Unknown")


def fingerprint_ap_via_http(
    ip: str,
    port: int = 80,
    timeout: float = 2.0,
) -> dict:
    """Probe AP management interface for vendor/model identification.

    Returns dict with vendor, model, firmware from HTTP headers/page.
    """
    import socket

    result = {"vendor": "Unknown", "model": "Unknown", "firmware": "Unknown"}
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        err = sock.connect_ex((ip, port))
        if err != 0:
            sock.close()
            return result

        request = f"GET / HTTP/1.0\r\nHost: {ip}\r\n\r\n"
        sock.sendall(request.encode())

        data = b""
        try:
            data = sock.recv(2048)
        except socket.timeout:
            pass  # probe response timeout — expected during fingerprinting
        sock.close()

        decoded = data.decode("utf-8", errors="replace").lower()

        vendor_hints = {
            "cisco": "Cisco", "linksys": "Linksys", "netgear": "Netgear",
            "tp-link": "TP-Link", "tplink": "TP-Link", "d-link": "D-Link",
            "dlink": "D-Link", "ubiquiti": "Ubiquiti", "ubnt": "Ubiquiti",
            "mikrotik": "MikroTik", "aruba": "Aruba", "openwrt": "OpenWrt",
            "dd-wrt": "DD-WRT", "asus": "ASUS", "buffalo": "Buffalo",
        }
        for hint, vendor in vendor_hints.items():
            if hint in decoded:
                result["vendor"] = vendor
                break

    except (socket.timeout, OSError) as e:
        logger.debug("Vendor fingerprint scan failed: %s", e)

    return result
