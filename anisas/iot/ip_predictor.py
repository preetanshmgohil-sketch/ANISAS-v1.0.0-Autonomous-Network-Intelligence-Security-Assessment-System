"""Predictive IP range analysis — identify high-probability surveillance device clusters."""

from __future__ import annotations

import ipaddress
import logging

logger = logging.getLogger(__name__)


def analyze_ip_clusters(
    device_ips: list[str],
    all_subnets: list[str] | None = None,
) -> list[dict]:
    """Analyze discovered IPs to predict surveillance device clusters.

    Uses sequential IP detection, subnet density, and VLAN segmentation patterns.

    Returns list of predicted IP ranges with probability scores.
    """
    if not device_ips:
        return []

    # Convert to integers for analysis
    ip_ints: list[int] = []
    for ip in device_ips:
        try:
            ip_ints.append(int(ipaddress.ip_address(ip)))
        except ValueError:
            continue

    ip_ints.sort()

    predictions: list[dict] = []

    # 1. Find sequential IP clusters
    if len(ip_ints) >= 2:
        clusters = _find_sequential_clusters(ip_ints)
        for cluster_start, cluster_end, count in clusters:
            # Calculate probability based on density
            total_ips = cluster_end - cluster_start + 1
            density = count / total_ips if total_ips > 0 else 0
            probability = min(0.95, 0.5 + (density * 0.3) + (count / 20.0))

            start_ip = str(ipaddress.ip_address(cluster_start))
            end_ip = str(ipaddress.ip_address(cluster_end))

            # Determine best CIDR
            cidr = _fit_cidr(start_ip, end_ip)

            predictions.append({
                "cidr_range": cidr,
                "probability_score": round(probability, 2),
                "rationale": (
                    f"Sequential cluster of {count} surveillance devices detected "
                    f"in range {start_ip}-{end_ip}. High density ({density:.0%}) "
                    f"suggests dedicated surveillance subnet."
                ),
            })

    # 2. Subnet-based predictions
    if all_subnets:
        for subnet in all_subnets:
            try:
                net = ipaddress.ip_network(subnet, strict=False)
                hosts_in_subnet = sum(
                    1 for ip in ip_ints
                    if ipaddress.ip_address(str(ipaddress.ip_address(ip))) in net
                )
                total_host_count = net.num_addresses - 2
                if total_host_count > 0:
                    density = hosts_in_subnet / total_host_count
                    if density > 0.15 and hosts_in_subnet >= 3:
                        probability = min(0.9, 0.4 + (density * 0.4) + (hosts_in_subnet / 15.0))
                        predictions.append({
                            "cidr_range": str(net),
                            "probability_score": round(probability, 2),
                            "rationale": (
                                f"{hosts_in_subnet} of {total_host_count} hosts in {subnet} "
                                f"are surveillance devices (density: {density:.0%}). "
                                f"Likely dedicated surveillance VLAN."
                            ),
                        })
            except ValueError:
                continue

    # 3. /28 block predictions (common for camera assignments)
    if len(ip_ints) >= 3:
        for ip_int in ip_ints:
            # Align to /28 boundary
            block_start = ip_int & ~0xF
            block_end = block_start | 0xE
            block_count = sum(1 for x in ip_ints if block_start <= x <= block_end)
            if block_count >= 3:
                cidr = f"{ipaddress.ip_address(block_start)}/28"
                probability = min(0.85, 0.3 + (block_count / 14.0))
                predictions.append({
                    "cidr_range": cidr,
                    "probability_score": round(probability, 2),
                    "rationale": (
                        f"{block_count} surveillance devices in /28 block {cidr}. "
                        f"Common pattern for camera IP assignments."
                    ),
                })

    # Deduplicate by CIDR
    seen: set[str] = set()
    unique: list[dict] = []
    for p in predictions:
        if p["cidr_range"] not in seen:
            seen.add(p["cidr_range"])
            unique.append(p)

    # Sort by probability
    unique.sort(key=lambda x: x["probability_score"], reverse=True)

    return unique[:10]  # Top 10 predictions


def _find_sequential_clusters(ip_ints: list[int]) -> list[tuple[int, int, int]]:
    """Find sequential clusters of IPs."""
    if not ip_ints:
        return []

    clusters: list[tuple[int, int, int]] = []
    current_start = ip_ints[0]
    current_end = ip_ints[0]
    current_count = 1

    for i in range(1, len(ip_ints)):
        if ip_ints[i] - ip_ints[i - 1] <= 5:  # Allow small gaps
            current_end = ip_ints[i]
            current_count += 1
        else:
            if current_count >= 2:
                clusters.append((current_start, current_end, current_count))
            current_start = ip_ints[i]
            current_end = ip_ints[i]
            current_count = 1

    if current_count >= 2:
        clusters.append((current_start, current_end, current_count))

    return clusters


def _fit_cidr(start_ip: str, end_ip: str) -> str:
    """Find the smallest CIDR block that contains both IPs."""
    start_int = int(ipaddress.ip_address(start_ip))
    end_int = int(ipaddress.ip_address(end_ip))

    # Try progressively larger CIDR blocks
    for prefix_len in range(32, 0, -1):
        mask = (0xFFFFFFFF << (32 - prefix_len)) & 0xFFFFFFFF
        network_start = start_int & mask
        network_end = network_start | (~mask & 0xFFFFFFFF)

        if network_start <= start_int and network_end >= end_int:
            network = ipaddress.ip_network(f"{ipaddress.ip_address(network_start)}/{prefix_len}", strict=False)
            return str(network)

    return f"{start_ip}/32"
