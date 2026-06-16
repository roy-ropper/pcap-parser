"""Network graph construction: nodes, edges, per-packet rows, and findings."""

import socket
import ipaddress
from collections import defaultdict

from ..constants import CLEARTEXT_PROTOS, LATERAL_PROTOS, _os_from_ttl
from ..extractors.cleartext import extract_cleartext
from .roles import guess_role
from .hostnames import resolve_hostnames_from_packets
from .findings import compute_findings


def _collapse(ip):
    try:
        addr = ipaddress.ip_address(ip)
        if not addr.is_private:
            return str(ipaddress.ip_network(ip+"/24", strict=False))
    except ValueError:
        pass
    return ip


def build_graph(packets, min_packets=1, collapse_external=False, extra_hostnames=None):
    """
    Returns nodes, edges, rows, findings
    """
    nodes = defaultdict(lambda: dict(
        count=0, bytes=0, is_private=False, role="client",
        macs=set(), mac_to_ips=defaultdict(set),
        subnet="", hostname="",
        protocols=set(), open_ports=set(),
        ttls=[], win_sizes=[],
        os_guess="Unknown",
        flags=set(),           # pentest flags
        first_seen=None, last_seen=None,
    ))
    edges = defaultdict(lambda: dict(
        count=0, bytes=0, protocols=set(), ports=set(), resources=set(),
        timestamps=[],
    ))
    rows          = []   # raw per-packet rows for Excel connections sheet
    findings      = []   # pentest findings rows
    cleartext_hits = []  # extracted credentials / sensitive data

    FAKE = {"ff:ff:ff:ff:ff:ff","00:00:00:00:00:00",""}

    # ARP table: ip -> set of MACs seen (anomaly detection)
    arp_table = defaultdict(set)
    # Track connections per IP pair over time (beaconing detection)
    conn_times = defaultdict(list)

    for p in packets:
        src, dst = p["src_ip"], p["dst_ip"]
        if collapse_external:
            src = _collapse(src); dst = _collapse(dst)
        if src == dst:
            continue

        smac = p.get("src_mac","")
        dmac = p.get("dst_mac","")

        # ARP anomaly tracking
        if p.get("arp_sender_mac"):
            arp_table[p["arp_sender_ip"]].add(p["arp_sender_mac"])

        if smac and smac not in FAKE:
            nodes[src]["macs"].add(smac)
            nodes[src]["mac_to_ips"][smac].add(src)
        if dmac and dmac not in FAKE:
            nodes[dst]["macs"].add(dmac)
            nodes[dst]["mac_to_ips"][dmac].add(dst)

        nodes[src]["count"] += 1; nodes[src]["bytes"] += p["length"]
        nodes[dst]["count"] += 1; nodes[dst]["bytes"] += p["length"]

        ts = p.get("ts_us", 0)
        for ip in (src, dst):
            if nodes[ip]["first_seen"] is None or ts < nodes[ip]["first_seen"]:
                nodes[ip]["first_seen"] = ts
            if nodes[ip]["last_seen"] is None or ts > nodes[ip]["last_seen"]:
                nodes[ip]["last_seen"] = ts

        if p.get("ttl"):
            nodes[src]["ttls"].append(p["ttl"])
        if p.get("win_size"):
            nodes[src]["win_sizes"].append(p["win_size"])

        proto = p["proto"]
        port  = p["dst_port"] or p["src_port"]

        # Open ports: a host is "listening" if it receives connections on known service ports
        if port and port < 1024:
            nodes[dst]["open_ports"].add(port)
        nodes[dst]["protocols"].add(proto)
        nodes[src]["protocols"].add(proto)

        key = (src, dst)
        edges[key]["count"]    += 1
        edges[key]["bytes"]    += p["length"]
        edges[key]["protocols"].add(proto)
        if port:       edges[key]["ports"].add(port)
        if p.get("resource"): edges[key]["resources"].add(p["resource"])
        conn_times[key].append(ts)

        rows.append(dict(
            src_ip=src, dst_ip=dst,
            src_mac=smac, dst_mac=dmac,
            proto=proto, port=port,
            resource=p.get("resource",""),
            ttl=p.get("ttl"),
        ))

        # Cleartext credential / sensitive data extraction
        hits = extract_cleartext(p)
        cleartext_hits.extend(hits)

    # ── Filter ────────────────────────────────────────────────────────────────
    edges = {k:v for k,v in edges.items() if v["count"] >= min_packets}
    active = {ip for pair in edges for ip in pair}
    nodes  = {k:v for k,v in nodes.items() if k in active}

    # ── Infer "locally-observed" IPs from ARP / MAC presence ────────────────
    # An IP seen in ARP sender/target or with a known MAC is definitely
    # on a local network segment, even if it's not RFC 1918.
    # This handles organisations using non-RFC1918 address blocks internally
    # (e.g. 20.x.x.x, 100.64.x.x CGNAT, 172.15.x.x etc.)
    # ── Infer locally-attached IPs from definitive L2 signals only ──────────
    # ARP sender IPs are ALWAYS on the local segment (ARP is never routed).
    # DHCP assigned addresses are also always local.
    # We deliberately do NOT use "has a MAC address" for regular TCP/UDP frames:
    # behind NAT, every packet has the gateway's MAC — using that would wrongly
    # classify 8.8.8.8 as "local" when it's just the gateway's upstream link.
    locally_observed_ips = set()
    for p in packets:
        # ARP sender/target are L2-local by definition
        arp_s = p.get("arp_sender_ip")
        if arp_s:
            locally_observed_ips.add(arp_s)
        if p.get("proto") == "ARP":
            arp_t = p.get("dst_ip","")
            if arp_t and arp_t not in ("0.0.0.0", "255.255.255.255"):
                locally_observed_ips.add(arp_t)
        # DHCP assigned IP (yiaddr) is always local
        if p.get("proto") == "DHCP":
            try:
                payload = p.get("app_payload", b"")
                if len(payload) >= 20:
                    for off in (12, 16):   # ciaddr + yiaddr
                        ip4 = socket.inet_ntoa(payload[off:off+4])
                        if ip4 not in ("0.0.0.0",):
                            locally_observed_ips.add(ip4)
            except Exception:
                pass
    locally_observed_ips.discard("")
    locally_observed_ips.discard("0.0.0.0")
    locally_observed_ips.discard("255.255.255.255")

    # ── Build the "always internal" network list ──────────────────────────────
    # These ranges are never globally routable and must always be internal,
    # regardless of whether we see ARP traffic for them.
    _ALWAYS_INTERNAL_NETS = [
        ipaddress.ip_network("10.0.0.0/8"),          # RFC 1918
        ipaddress.ip_network("172.16.0.0/12"),        # RFC 1918
        ipaddress.ip_network("192.168.0.0/16"),       # RFC 1918
        ipaddress.ip_network("169.254.0.0/16"),       # Link-local (RFC 3927)
        ipaddress.ip_network("127.0.0.0/8"),          # Loopback
        ipaddress.ip_network("100.64.0.0/10"),        # CGNAT shared (RFC 6598)
        ipaddress.ip_network("192.0.0.0/24"),         # IANA special (RFC 5736)
        ipaddress.ip_network("198.18.0.0/15"),        # Benchmarking (RFC 2544)
        ipaddress.ip_network("198.51.100.0/24"),      # Documentation (RFC 5737)
        ipaddress.ip_network("203.0.113.0/24"),       # Documentation (RFC 5737)
        ipaddress.ip_network("192.0.2.0/24"),         # Documentation (RFC 5737)
        ipaddress.ip_network("240.0.0.0/4"),          # Reserved (RFC 1112)
    ]
    # Merge in any caller-supplied networks (--internal-networks option)
    _extra_nets = (extra_hostnames or {}).get("__internal_networks__", [])
    _ALL_INTERNAL_NETS = _ALWAYS_INTERNAL_NETS + list(_extra_nets)

    def _is_internal_ip(ip_str):
        """Return True if this IP belongs to a non-globally-routable / internal range."""
        try:
            addr2 = ipaddress.ip_address(ip_str.split("/")[0])
            if addr2.is_private or addr2.is_link_local or addr2.is_loopback:
                return True
            if addr2.is_multicast:
                return False
            for net in _ALL_INTERNAL_NETS:
                if addr2 in net:
                    return True
            if ip_str in locally_observed_ips:
                return True
            return False
        except ValueError:
            return False

    # ── Annotate nodes ────────────────────────────────────────────────────────
    for ip, info in nodes.items():
        try:
            addr = ipaddress.ip_address(ip.split("/")[0])
            is_priv = _is_internal_ip(ip)
            if ip == "255.255.255.255" or addr.is_multicast:
                is_priv = False
            info["is_private"] = is_priv
            info["subnet"] = (str(ipaddress.ip_network(ip + "/24", strict=False))
                              if is_priv else "external")
        except ValueError:
            info["is_private"] = False; info["subnet"] = "external"

        info["role"] = guess_role(ip, edges)

        # OS guess from most common TTL
        if info["ttls"]:
            common_ttl = max(set(info["ttls"]), key=info["ttls"].count)
            info["os_guess"] = _os_from_ttl(common_ttl)
            info["ttl_val"]  = common_ttl
        else:
            info["os_guess"] = "Unknown"
            info["ttl_val"]  = None

        # Pentest flags on node
        if info["protocols"] & CLEARTEXT_PROTOS:
            info["flags"].add("⚠ Cleartext protocol")
        if info["protocols"] & LATERAL_PROTOS and info["is_private"]:
            info["flags"].add("🔴 Lateral movement proto")

    # ── Passive hostname resolution from packet data ─────────────────────────
    passive_hostnames = resolve_hostnames_from_packets(packets)
    # Apply passive names first (lowest priority)
    for ip, hn in passive_hostnames.items():
        if ip in nodes and not nodes[ip]["hostname"]:
            nodes[ip]["hostname"] = hn
    # File-supplied hostnames override passive ones (highest priority)
    if extra_hostnames:
        for ip, hn in extra_hostnames.items():
            if ip in nodes:
                nodes[ip]["hostname"] = hn

    # fqdn field — populated later by cli.py after extract_network_names()
    for info in nodes.values():
        info["fqdn"] = None


    findings = compute_findings(nodes, edges, arp_table, conn_times, packets)

    return nodes, edges, rows, findings, cleartext_hits, dict(arp_table)
