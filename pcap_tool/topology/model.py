"""Build a normalized TopologyModel from a run_pipeline() result dict.

This is the single place that turns raw extractor output (nodes/edges,
findings, cleartext hits, DNS events, Wi-Fi survey data, EAP-TLS streams)
into a unified set of TopoNode / TopoEdge objects tagged with a small
red-team-relevant vocabulary, consumed by render_policy.select_edges() and
the diagram generators.

Tag vocabulary: cleartext, cleartext_creds, ssh, lateral_movement,
unusual_outbound, beaconing, exfiltration, icmp_tunneling, snmp_cleartext,
dns_tunneling, radius_eap_tls, wifi_assoc, deauth.
"""

from dataclasses import dataclass, field

from ..extractors.certificates import extract_eap_tls_streams
from .capture_device import detect_capture_device


_SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}

_LATERAL_PROTOS = {"SMB", "RDP", "VNC"}


def _higher_sev(a, b):
    if a is None:
        return b
    if b is None:
        return a
    return a if _SEV_RANK.get(a, 0) >= _SEV_RANK.get(b, 0) else b


@dataclass
class TopoNode:
    id: str
    kind: str                       # "host" | "ap" | "wifi_client" | "eap_tls_peer"
    ip: str = None
    mac: str = None
    hostname: str = None
    role: str = None                # "server" | "host" | "client" (from roles.py)
    device_category: str = "unknown"
    subnet: str = None
    os_guess: str = None
    is_private: bool = False
    is_gateway: bool = False
    is_capture_device: bool = False
    protocols: list = field(default_factory=list)
    open_ports: list = field(default_factory=list)
    bytes: int = 0
    count: int = 0
    max_severity: str = None
    extra: dict = field(default_factory=dict)


@dataclass
class TopoEdge:
    src: str
    dst: str
    protocols: list = field(default_factory=list)
    ports: list = field(default_factory=list)
    bytes: int = 0
    count: int = 0
    resources: list = field(default_factory=list)
    tags: set = field(default_factory=set)
    notes: list = field(default_factory=list)
    max_severity: str = None


@dataclass
class TopologyModel:
    title: str
    nodes: dict
    edges: list
    findings: list
    gateways: dict
    capture_device: dict
    dns_servers: set
    traceroutes: list = field(default_factory=list)


def guess_device_category(ip, info, gateways=None):
    """Map a raw `nodes[ip]` dict to a diagram device category."""
    if gateways and ip in gateways.values():
        return "network_device"
    if not info.get("is_private", False):
        return "external"
    role = info.get("role")
    if role == "server":
        return "server"
    if role == "host":
        return "workstation"
    if role == "client":
        return "client"
    return "unknown"


# Finding category -> edge tag, for findings whose src/dst are real edge endpoints.
_FINDING_TAG = {
    "Cleartext Protocol": "cleartext",
    "Lateral Movement Indicator": "lateral_movement",
    "Unusual Outbound": "unusual_outbound",
    "Potential Beaconing": "beaconing",
    "Possible Exfiltration / Top Talker": "exfiltration",
    "ICMP Tunneling Indicator": "icmp_tunneling",
}

# Finding categories whose src is a node (not an edge endpoint pair).
_NODE_LEVEL_CATEGORIES = {"ARP Anomaly / Possible MITM", "Port Scan"}


def _build_host_nodes(nodes_raw, gateways):
    gw_ips = set(gateways.values())
    topo_nodes = {}
    for ip, info in nodes_raw.items():
        topo_nodes[ip] = TopoNode(
            id=ip,
            kind="host",
            ip=ip,
            hostname=info.get("hostname") or None,
            role=info.get("role"),
            device_category=guess_device_category(ip, info, gateways),
            subnet=info.get("subnet"),
            os_guess=info.get("os_guess"),
            is_private=info.get("is_private", False),
            is_gateway=ip in gw_ips,
            protocols=sorted(info.get("protocols", set())),
            open_ports=sorted(info.get("open_ports", set())),
            bytes=info.get("bytes", 0),
            count=info.get("count", 0),
        )
    return topo_nodes


def _build_edges(edges_raw):
    topo_edges = []
    edge_index = {}
    for (src, dst), info in edges_raw.items():
        e = TopoEdge(
            src=src, dst=dst,
            protocols=sorted(info.get("protocols", set())),
            ports=sorted(info.get("ports", set())),
            bytes=info.get("bytes", 0),
            count=info.get("count", 0),
            resources=sorted(info.get("resources", set())),
        )
        topo_edges.append(e)
        edge_index[(src, dst)] = e
    return topo_edges, edge_index


def _apply_findings(topo_nodes, edge_index, topo_edges, findings, dns_servers):
    for f in findings:
        category = f.get("category")
        severity = f.get("severity")
        src, dst = f.get("src"), f.get("dst")

        if category == "DNS Tunneling Indicator":
            # src = client IP, dst = base domain (not a real edge endpoint) —
            # attach to the client's edge(s) toward any known DNS server.
            for e in topo_edges:
                if e.src == src and e.dst in dns_servers:
                    e.tags.add("dns_tunneling")
                    e.notes.append(f"DNS tunneling suspected: {dst}")
                    e.max_severity = _higher_sev(e.max_severity, severity)
            continue

        if category in _NODE_LEVEL_CATEGORIES:
            node = topo_nodes.get(src)
            if node:
                node.max_severity = _higher_sev(node.max_severity, severity)
            continue

        edge = edge_index.get((src, dst))
        if edge is None:
            continue

        tag = _FINDING_TAG.get(category)
        if tag:
            edge.tags.add(tag)
        if f.get("detail"):
            edge.notes.append(f["detail"])
        edge.max_severity = _higher_sev(edge.max_severity, severity)


def _apply_cleartext_hits(edge_index, cleartext_hits):
    for hit in cleartext_hits:
        edge = edge_index.get((hit.get("src_ip"), hit.get("dst_ip")))
        if edge is None:
            continue
        edge.tags.add("cleartext_creds")
        edge.notes.append(f"{hit.get('protocol','')} {hit.get('type','')}: {hit.get('value','')}")
        edge.max_severity = _higher_sev(edge.max_severity, "HIGH")


def _apply_protocol_tags(topo_edges, dns_servers):
    for e in topo_edges:
        protos = set(e.protocols)
        if "SSH" in protos:
            e.tags.add("ssh")
        if protos & _LATERAL_PROTOS:
            e.tags.add("lateral_movement")
        if "SNMP" in protos:
            e.tags.add("snmp_cleartext")
            e.max_severity = _higher_sev(e.max_severity, "MEDIUM")
        if "DNS" in protos:
            dns_servers.add(e.dst)


def _ensure_mac_node(topo_nodes, node_id, mac, kind, device_category):
    if node_id not in topo_nodes:
        topo_nodes[node_id] = TopoNode(
            id=node_id, kind=kind, mac=mac,
            device_category=device_category,
            is_private=True,
        )
    return topo_nodes[node_id]


def _apply_eap_tls(topo_nodes, topo_edges, packets):
    for stream in extract_eap_tls_streams(packets):
        smac = stream.get("supplicant_mac")
        amac = stream.get("authenticator_mac")
        if not smac or not amac:
            continue
        sid, aid = f"mac:{smac}", f"mac:{amac}"
        _ensure_mac_node(topo_nodes, sid, smac, "eap_tls_peer", "client")
        _ensure_mac_node(topo_nodes, aid, amac, "eap_tls_peer", "network_device")

        notes = []
        if stream.get("sni"):
            notes.append(f"SNI: {stream['sni']}")
        for cert in stream.get("certs", []):
            if cert.get("subject"):
                notes.append(f"cert subject: {cert['subject']}")

        topo_edges.append(TopoEdge(
            src=sid, dst=aid,
            protocols=["EAP-TLS"],
            tags={"radius_eap_tls"},
            notes=notes,
        ))


def _apply_wifi(topo_nodes, topo_edges, wifi_data):
    aps = wifi_data.get("aps", [])
    clients = wifi_data.get("clients", [])
    events = wifi_data.get("events", [])
    client_by_mac = {c.get("mac"): c for c in clients}

    mac_edge_index = {}

    for ap in aps:
        bssid = ap.get("bssid")
        if not bssid:
            continue
        aid = f"mac:{bssid}"
        if aid not in topo_nodes:
            topo_nodes[aid] = TopoNode(
                id=aid, kind="ap", mac=bssid,
                hostname=ap.get("ssid") or None,
                device_category="ap", is_private=True,
                extra={"ssid": ap.get("ssid", ""), "channel": ap.get("channel", 0),
                       "enc": ap.get("enc", "Open"), "wps": bool(ap.get("wps", False))},
            )

        for cmac in ap.get("clients", []):
            cid = f"mac:{cmac}"
            if cid not in topo_nodes:
                cinfo = client_by_mac.get(cmac, {})
                topo_nodes[cid] = TopoNode(
                    id=cid, kind="wifi_client", mac=cmac,
                    device_category="client", is_private=True,
                    extra={"probed_ssids": sorted(cinfo.get("probed_ssids", set()))},
                )
            edge = TopoEdge(src=aid, dst=cid, tags={"wifi_assoc"},
                             notes=[f"SSID: {ap.get('ssid') or '(hidden)'}"])
            topo_edges.append(edge)
            mac_edge_index[frozenset((aid, cid))] = edge

    for ev in events:
        if ev.get("frame_type") not in ("Deauthentication", "Disassociation"):
            continue
        bssid = ev.get("bssid") or ev.get("dst_mac") or ""
        src_mac = ev.get("src_mac") or ""
        other = src_mac if src_mac != bssid else (ev.get("dst_mac") or "")
        if not bssid or not other:
            continue
        aid, oid = f"mac:{bssid}", f"mac:{other}"
        _ensure_mac_node(topo_nodes, aid, bssid, "ap", "ap")
        _ensure_mac_node(topo_nodes, oid, other, "wifi_client", "client")

        key = frozenset((aid, oid))
        edge = mac_edge_index.get(key)
        if edge is None:
            edge = TopoEdge(src=aid, dst=oid)
            topo_edges.append(edge)
            mac_edge_index[key] = edge
        edge.tags.add("deauth")
        edge.notes.append(f"Deauth/disassoc: {ev.get('detail','')}")
        edge.max_severity = _higher_sev(edge.max_severity, "MEDIUM")


def build_topology(result):
    """Normalize a run_pipeline() result dict into a TopologyModel."""
    nodes_raw = result.get("nodes", {})
    edges_raw = result.get("edges", {})
    findings = result.get("findings", [])
    cleartext_hits = result.get("cleartext_hits", [])
    wifi_data = result.get("wifi_data") or {}
    gateways = result.get("gateways") or {}
    traceroutes = result.get("traceroutes") or []
    packets = result.get("packets", [])
    title = result.get("title", "Network Diagram")

    topo_nodes = _build_host_nodes(nodes_raw, gateways)
    topo_edges, edge_index = _build_edges(edges_raw)

    dns_servers = set()
    for e in topo_edges:
        if "DNS" in e.protocols:
            dns_servers.add(e.dst)

    _apply_findings(topo_nodes, edge_index, topo_edges, findings, dns_servers)
    _apply_cleartext_hits(edge_index, cleartext_hits)
    _apply_protocol_tags(topo_edges, dns_servers)
    _apply_eap_tls(topo_nodes, topo_edges, packets)
    _apply_wifi(topo_nodes, topo_edges, wifi_data)

    capture_device = detect_capture_device(packets, nodes_raw)
    cap_ip = capture_device.get("ip")
    if cap_ip and cap_ip in topo_nodes:
        topo_nodes[cap_ip].is_capture_device = True

    return TopologyModel(
        title=title,
        nodes=topo_nodes,
        edges=topo_edges,
        findings=findings,
        gateways=gateways,
        capture_device=capture_device,
        dns_servers=dns_servers,
        traceroutes=traceroutes,
    )
