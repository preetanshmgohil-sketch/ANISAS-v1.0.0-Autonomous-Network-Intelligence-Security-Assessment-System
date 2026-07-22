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
        return {
            "primary_auth_method": "Unknown",
            "mac_filtering_detected": False,
            "vulnerability_assessment": "No access points detected for analysis.",
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
