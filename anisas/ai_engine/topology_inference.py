"""Graph-based topology inference engine."""

from __future__ import annotations

import ipaddress
import logging

logger = logging.getLogger(__name__)


def infer_topology(
    subnets: list[str],
    hosts: list[dict],
    gateways: list[str] | None = None,
) -> dict:
    """Infer network topology from scan data using graph-based analysis.

    Constructs a hierarchical graph: ASN/prefix -> subnets -> gateways -> hosts.

    Returns dict with nodes and links.
    """
    nodes: list[dict] = []
    links: list[dict] = []
    seen_nodes: set[str] = set()
    seen_edges: set[tuple[str, str]] = set()

    def add_node(node_id: str, label: str, node_type: str) -> None:
        if node_id not in seen_nodes:
            nodes.append({"id": node_id, "label": label, "type": node_type})
            seen_nodes.add(node_id)

    def add_edge(src: str, tgt: str, weight: float = 1.0) -> None:
        edge = (src, tgt) if src <= tgt else (tgt, src)
        if edge not in seen_edges:
            links.append({"source": src, "target": tgt, "weight": weight})
            seen_edges.add(edge)

    # 1. Add subnets as parent nodes
    for subnet in subnets:
        add_node(subnet, subnet, "subnet")

    # 2. Detect gateways (first usable IP per subnet)
    detected_gateways: list[str] = []
    for subnet in subnets:
        try:
            net = ipaddress.ip_network(subnet, strict=False)
            hosts_in_net = list(net.hosts())
            if hosts_in_net:
                gw = str(hosts_in_net[0])
                detected_gateways.append(gw)
                add_node(gw, f"GW:{gw}", "gateway")
                add_edge(subnet, gw, weight=2.0)
        except ValueError:
            continue

    # Add explicit gateways
    if gateways:
        for gw in gateways:
            if gw not in seen_nodes:
                detected_gateways.append(gw)
                add_node(gw, f"GW:{gw}", "gateway")

    # 3. Add hosts and connect to subnet/gateway
    for host in hosts:
        ip = host.get("ip_address", host.get("ip", ""))
        if not ip:
            continue

        dev_type = host.get("predicted_device_type", "device")
        add_node(ip, f"{dev_type}:{ip}", "device")

        # Find parent subnet
        for subnet in subnets:
            try:
                net = ipaddress.ip_network(subnet, strict=False)
                if ipaddress.ip_address(ip) in net:
                    # Connect to gateway if in same subnet
                    gw = None
                    for g in detected_gateways:
                        try:
                            if ipaddress.ip_address(g) in net:
                                gw = g
                                break
                        except ValueError:
                            continue

                    if gw:
                        add_edge(gw, ip, weight=1.0)
                    else:
                        add_edge(subnet, ip, weight=1.0)
                    break
            except ValueError:
                continue

    # 4. Infer hidden links based on TTL patterns
    ttl_groups: dict[int, list[str]] = {}
    for host in hosts:
        ip = host.get("ip_address", host.get("ip", ""))
        os_fp = host.get("os_fingerprint", {})
        ttl = os_fp.get("initial_ttl", 0)
        if ip and ttl:
            bucket = (ttl // 32) * 32
            ttl_groups.setdefault(bucket, []).append(ip)

    # Add weak links between same TTL group (likely same network segment)
    for ttl_bucket, group_hosts in ttl_groups.items():
        if len(group_hosts) >= 2:
            for i in range(min(3, len(group_hosts))):
                for j in range(i + 1, min(5, len(group_hosts))):
                    add_edge(group_hosts[i], group_hosts[j], weight=0.3)

    return {"nodes": nodes, "links": links}
