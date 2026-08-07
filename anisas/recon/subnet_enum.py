"""Subnet enumeration — break CIDRs into actionable /24 or /28 blocks."""

from __future__ import annotations

import ipaddress
import logging

logger = logging.getLogger(__name__)


def enumerate_subnets(
    prefixes: list[str],
    max_prefix_len: int = 28,
    max_subnets: int = 5,
) -> list[str]:
    """Break input CIDR prefixes into smaller actionable subnets.

    Large blocks (> /24) are split into /24 chunks.
    Blocks between /24 and max_prefix_len are split into max_prefix_len.

    Args:
        prefixes: List of CIDR strings from Module 1 (e.g., ["8.8.8.0/24"]).
        max_prefix_len: Maximum prefix length to split into (default /28 = 16 hosts).
        max_subnets: Maximum number of subnets to return (default 5).

    Returns:
        List of CIDR strings for scanning.
    """
    result: list[str] = []
    for prefix in prefixes:
        try:
            net = ipaddress.ip_network(prefix, strict=False)
        except ValueError:
            logger.warning("Invalid CIDR prefix skipped: %s", prefix)
            continue

        # Only process IPv4 for scanning
        if net.version != 4:
            logger.info("IPv6 prefix skipped for host scanning: %s", prefix)
            continue

        prefix_len = net.prefixlen

        if prefix_len <= 24:
            # Large block — split into /24s
            for sub in net.subnets(new_prefix=24):
                result.append(str(sub))
                if len(result) >= max_subnets:
                    break
        elif prefix_len <= max_prefix_len:
            # Medium block — split into max_prefix_len
            for sub in net.subnets(new_prefix=max_prefix_len):
                result.append(str(sub))
                if len(result) >= max_subnets:
                    break
        else:
            # Already granular enough
            result.append(str(net))

        if len(result) >= max_subnets:
            break

    logger.info("Enumerated %d scannable subnets from %d prefixes", len(result), len(prefixes))
    return result[:max_subnets]


def generate_host_ips(cidr: str) -> list[str]:
    """Generate all usable host IPs within a subnet (excluding network/broadcast)."""
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return []

    hosts = []
    for ip in net.hosts():
        hosts.append(str(ip))
    return hosts


def estimate_subnet_vlans(
    subnets: list[str],
) -> list[dict]:
    """Create subnet entries with VLAN detection placeholders.

    VLAN detection happens in host_discovery via TTL analysis.
    """
    return [
        {
            "cidr": s,
            "vlan_detected": False,
            "estimated_vlan_id": None,
        }
        for s in subnets
    ]
