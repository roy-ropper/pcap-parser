"""Traceroute path reconstruction from ICMP TTL-exceeded replies."""

import socket
from collections import defaultdict

# ─────────────────────────────────────────────────────────────────────────────
# Traceroute / ICMP TTL-exceeded hop reconstructor
# ─────────────────────────────────────────────────────────────────────────────

def extract_traceroutes(packets):
    """
    Reconstruct traceroute paths from ICMP TTL-exceeded (type 11) replies.

    A traceroute works by sending probes with increasing TTL values.
    Each router that drops a packet (TTL=0) sends back an ICMP type 11
    "Time Exceeded" message.  The inner IP header tells us the original
    destination; the outer IP source is the hop.

    Returns list of traceroute dicts:
        {src, dst, hops: [{hop_n, router_ip, rtt_ms}]}
    """
    # Collect ICMP type-11 replies: outer_src = router, inner = original probe
    # We detect them by looking at ICMP packets where proto is ICMP and
    # the payload starts with an IP header (inner encapsulated packet).
    hop_events = []   # (origin_src, final_dst, hop_router, approx_ttl_level)

    for p in packets:
        if p.get("proto") != "ICMP":
            continue
        payload = p.get("app_payload", b"")
        # ICMP header: type(1) code(1) checksum(2) rest(4) = 8 bytes
        # For type 11 (TTL exceeded), the payload is the original IP header + 8 bytes
        if len(payload) < 8:
            continue
        icmp_type = payload[0]
        if icmp_type != 11:   # Time Exceeded
            continue
        inner = payload[8:]   # original IP packet (at least 20 bytes header)
        if len(inner) < 20:
            continue
        try:
            inner_ihl  = (inner[0] & 0x0F) * 4
            inner_src  = socket.inet_ntoa(inner[12:16])
            inner_dst  = socket.inet_ntoa(inner[16:20])
            router_ip  = p["src_ip"]   # the router sending the TTL-exceeded back
            hop_events.append((inner_src, inner_dst, router_ip))
        except Exception:
            continue

    if not hop_events:
        return []

    # Group by (origin → destination) pair
    paths = defaultdict(list)
    for origin, dest, router in hop_events:
        paths[(origin, dest)].append(router)

    traces = []
    for (origin, dest), routers in paths.items():
        # Deduplicate while preserving order
        seen = []
        for r in routers:
            if r not in seen:
                seen.append(r)
        hops = [{"hop_n": i+1, "router_ip": r} for i, r in enumerate(seen)]
        traces.append({"src": origin, "dst": dest, "hops": hops})

    return traces


