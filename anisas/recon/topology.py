"""Topology graph generation — nodes (subnet/gateway/host) and edges."""

from __future__ import annotations

import ipaddress
import logging

logger = logging.getLogger(__name__)


def build_topology(
    target_prefix: str,
    subnets: list[str],
    active_hosts: list[dict],
    gateways: list[str] | None = None,
) -> dict:
    """Construct an adjacency graph for the network topology.

    Node types:
        - subnet: parent CIDR blocks
        - gateway: detected router/gateway IPs
        - host: active hosts

    Edges connect subnets to gateways and gateways to hosts.

    Returns:
        Dict with 'nodes' and 'edges' lists.
    """
    nodes: list[dict] = []
    edges: list[dict] = []
    seen_nodes: set[str] = set()

    def add_node(node_id: str, node_type: str) -> None:
        if node_id not in seen_nodes:
            nodes.append({"id": node_id, "type": node_type})
            seen_nodes.add(node_id)

    def add_edge(src: str, tgt: str) -> None:
        edge_key = (src, tgt)
        reverse_key = (tgt, src)
        if edge_key not in seen_nodes and reverse_key not in seen_nodes:
            edges.append({"source": src, "target": tgt})
            seen_nodes.add(edge_key)

    # 1. Add the target prefix as root subnet
    add_node(target_prefix, "subnet")

    # 2. Add discovered subnets and connect to target prefix
    for subnet in subnets:
        add_node(subnet, "subnet")
        if subnet != target_prefix:
            add_edge(target_prefix, subnet)

    # 3. Detect likely gateways (first usable IP in each subnet is often the gateway)
    detected_gateways: list[str] = []
    for subnet in subnets:
        try:
            net = ipaddress.ip_network(subnet, strict=False)
            hosts = list(net.hosts())
            if hosts:
                gw = str(hosts[0])
                detected_gateways.append(gw)
                add_node(gw, "gateway")
                add_edge(subnet, gw)
        except ValueError:
            continue

    # 4. Add additional gateways if provided
    if gateways:
        for gw in gateways:
            add_node(gw, "gateway")
            detected_gateways.append(gw)

    # 5. Add active hosts and connect to their subnet/gateway
    host_ips = set()
    for host in active_hosts:
        ip = host.get("ip_address") or host.get("ip", "")
        if not ip:
            continue
        host_ips.add(ip)
        add_node(ip, "host")

        # Find which subnet this host belongs to
        matched_subnet = None
        for subnet in subnets:
            try:
                net = ipaddress.ip_network(subnet, strict=False)
                if ipaddress.ip_address(ip) in net:
                    matched_subnet = subnet
                    break
            except ValueError:
                continue

        if matched_subnet:
            # Connect to gateway if detected for this subnet, else to subnet directly
            gw = None
            try:
                net = ipaddress.ip_network(matched_subnet, strict=False)
                gw = str(list(net.hosts())[0])
            except (ValueError, IndexError):
                pass

            if gw and gw in host_ips:
                add_edge(gw, ip)
            else:
                add_edge(matched_subnet, ip)

    logger.info(
        "Topology built: %d nodes, %d edges", len(nodes), len(edges)
    )
    return {"nodes": nodes, "edges": edges}
