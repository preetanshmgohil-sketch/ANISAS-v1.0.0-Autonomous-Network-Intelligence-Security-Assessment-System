"""Authentication mechanism analysis for wireless networks."""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


def analyze_authentication(
    access_points: list[dict],
    clients: list[dict],
) -> dict:
    """Analyze wireless authentication mechanisms and document vulnerabilities.

    Returns dict with primary_auth_method, mac_filtering_detected, vulnerability_assessment.
    """
    if not access_points:
        # No APs detected — infer from client data
        active_clients = [c for c in clients if c.get("status") == "ACTIVE"]
        total_clients = len(clients)

        if total_clients == 0:
            return {
                "primary_auth_method": "Unknown",
                "mac_filtering_detected": False,
                "vulnerability_assessment": "No access points or clients detected.",
            }

        # If we have many clients, network likely uses standard auth
        assessment_parts = []
        if total_clients > 20:
            assessment_parts.append(
                f"Network has {total_clients} active clients suggesting an infrastructure network. "
                "No wireless APs detected — this may be a wired-only segment or APs use hidden SSIDs."
            )
        else:
            assessment_parts.append(
                f"Detected {total_clients} client(s) but no wireless access points. "
                "The network may be wired-only or APs are out of scan range."
            )

        # Check for multicast/broadcast patterns suggesting managed network
        multicast_count = sum(1 for c in clients if _is_multicast_ip(c.get("assigned_ip", "")))
        if multicast_count > 5:
            assessment_parts.append(
                "Significant multicast traffic detected — indicates a managed enterprise network."
            )

        # Check for private IP ranges suggesting NAT'd infrastructure
        private_count = sum(1 for c in clients if _is_private_ip(c.get("assigned_ip", "")))
        if private_count > 0:
            assessment_parts.append(
                f"{private_count} client(s) on private IP space — typical of corporate LAN segments."
            )

        return {
            "primary_auth_method": "Unknown (no APs detected)",
            "mac_filtering_detected": _detect_mac_filtering(clients),
            "vulnerability_assessment": " | ".join(assessment_parts) if assessment_parts else "Insufficient data for assessment.",
        }

    # Determine primary auth from strongest AP
    strongest_ap = max(access_points, key=lambda a: a.get("signal_rssi", -100))
    primary_auth = strongest_ap.get("encryption_type", "Unknown")

    # Detect MAC filtering indicators
    mac_filtering = _detect_mac_filtering(clients)

    # Build vulnerability assessment
    vulns: list[str] = []

    if primary_auth == "OPEN":
        vulns.append(
            "CRITICAL: Network uses open (unencrypted) association. "
            "All traffic is transmitted in cleartext and accessible to passive sniffers."
        )
    elif primary_auth == "WPA-PSK":
        vulns.append(
            "HIGH: WPA-PSK uses a shared passphrase vulnerable to offline dictionary attacks "
            "once a 4-way handshake is captured."
        )
    elif primary_auth == "WPA2-PSK":
        vulns.append(
            "MEDIUM: WPA2-PSK is susceptible to KRACK attacks and offline dictionary attacks "
            "if weak passphrases are used."
        )
    elif primary_auth == "WPA3-SAE":
        vulns.append(
            "LOW: WPA3-SAE provides strong protection against offline dictionary attacks. "
            "Verify downgrade attack protections are enabled."
        )
    elif primary_auth == "802.1X":
        vulns.append(
            "LOW: 802.1X Enterprise authentication provides per-user credentials. "
            "Verify RADIUS server configuration and certificate validation."
        )

    if mac_filtering:
        vulns.append(
            "HIGH: MAC address filtering detected. MAC addresses are transmitted in cleartext "
            "and can be trivially spoofed using packet injection or interface reconfiguration."
        )

    vulns.append(
        "RECOMMENDATION: Deploy WPA3-Enterprise (802.1X) with certificate-based authentication, "
        "disable MAC-only ACLs, and enable wireless intrusion detection (WIDS)."
    )

    return {
        "primary_auth_method": primary_auth,
        "mac_filtering_detected": mac_filtering,
        "vulnerability_assessment": " | ".join(vulns),
    }


def _detect_mac_filtering(clients: list[dict]) -> bool:
    """Heuristically detect MAC filtering based on client patterns."""
    if not clients:
        return False

    # If we have a mix of active/inactive clients with very few active,
    # it could indicate MAC filtering is active
    active = sum(1 for c in clients if c.get("status") == "ACTIVE")
    total = len(clients)

    # Strong indicator: if we can enumerate clients from DHCP but ARP is sparse
    if total > 5 and active < total * 0.3:
        return True

    return False


def _is_multicast_ip(ip: str) -> bool:
    """Check if an IP is in the multicast range (224.0.0.0 - 239.255.255.255)."""
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        first = int(parts[0])
        return 224 <= first <= 239
    except ValueError:
        return False


def _is_private_ip(ip: str) -> bool:
    """Check if an IP is in a private/reserved range."""
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        a, b = int(parts[0]), int(parts[1])
        return (
            a == 10
            or (a == 172 and 16 <= b <= 31)
            or (a == 192 and b == 168)
            or a == 127
            or (a == 169 and b == 254)
        )
    except ValueError:
        return False
