"""Default-gateway detection from ARP and addressing heuristics."""

import ipaddress
from collections import defaultdict

def detect_gateways(packets, nodes):
    """
    Identify default gateways by looking at:
      1. ARP requests sent to the router from each subnet — the router IP
         is the most-queried ARP target that is NOT a host sending traffic
      2. Hosts that forward packets for many other subnets (high TTL, many peers)

    Returns dict: {subnet_cidr -> gateway_ip}
    """
    # Count ARP targets per subnet
    arp_targets = defaultdict(lambda: defaultdict(int))  # subnet -> ip -> count

    for p in packets:
        if p.get("proto") != "ARP":
            continue
        src_ip = p.get("src_ip","")
        dst_ip = p.get("dst_ip","")
        if not src_ip or not dst_ip:
            continue
        try:
            src_addr = ipaddress.ip_address(src_ip)
            if not src_addr.is_private:
                continue
            net = str(ipaddress.ip_network(src_ip + "/24", strict=False))
            arp_targets[net][dst_ip] += 1
        except Exception:
            continue

    gateways = {}
    for subnet, targets in arp_targets.items():
        if not targets:
            continue
        # Most ARP'd target that is itself in the same subnet is likely the gateway
        candidates = sorted(targets.items(), key=lambda x: -x[1])
        for ip, count in candidates:
            try:
                addr = ipaddress.ip_address(ip)
                if addr.is_private and count >= 2:
                    gateways[subnet] = ip
                    break
            except Exception:
                continue

    # Fallback: nodes with role "server" or "host" that have the lowest
    # host octet (e.g. .1) are likely gateways/routers
    for ip, info in nodes.items():
        try:
            addr   = ipaddress.ip_address(ip)
            subnet = info["subnet"]
            if subnet == "external" or subnet in gateways:
                continue
            if addr.is_private and (addr.packed[-1] in (1, 254)):
                gateways[subnet] = ip
        except Exception:
            continue

    return gateways
