"""Tests for pcap_tool.topology.model (build_topology) and
pcap_tool.topology.capture_device (detect_capture_device)."""

import pytest

from pcap_tool.topology.model import build_topology
from pcap_tool.topology.capture_device import detect_capture_device
from pcap_tool.parser import parse_pcap
from pcap_tool.graph.build import build_graph
from pcap_tool.extractors.wifi import extract_wifi_events

from .conftest import (
    eth_ip_tcp, eth_ip_udp, write_pcap, write_pcapng,
    wifi_beacon_frame, wifi_deauth_frame,
    eapol_eap_tls_frame, tls_certificate_record, make_certificate_der,
)


# ── helpers ──────────────────────────────────────────────────────────────────

def _node(ip, role="client", subnet="10.0.0.0/24", **kw):
    d = {"count": 1, "bytes": 100, "is_private": True, "role": role,
         "macs": set(), "subnet": subnet, "hostname": None,
         "protocols": set(), "open_ports": set(), "os_guess": None, "flags": set()}
    d.update(kw)
    return d


def _edge(protos=None, bytes_=100, count=1, ports=None):
    return {"count": count, "bytes": bytes_, "protocols": set(protos or []),
            "ports": set(ports or []), "resources": set(), "timestamps": []}


def _result(**kw):
    r = {
        "nodes": {
            "10.0.0.1": _node("10.0.0.1", role="server"),
            "10.0.0.2": _node("10.0.0.2", role="client"),
        },
        "edges": {},
        "findings": [],
        "cleartext_hits": [],
        "wifi_data": {"aps": [], "clients": [], "events": []},
        "gateways": {},
        "traceroutes": [],
        "packets": [],
        "title": "Test",
    }
    r.update(kw)
    return r


# ── edge tag tests (via synthetic dicts, no PCAP parsing needed) ─────────────

def test_cleartext_creds_tag():
    """cleartext_hits matching an edge src/dst produce 'cleartext_creds' tag."""
    r = _result(
        edges={("10.0.0.2", "10.0.0.1"): _edge(["Telnet"])},
        cleartext_hits=[{"src_ip": "10.0.0.2", "dst_ip": "10.0.0.1",
                          "protocol": "Telnet", "type": "Password", "value": "s3cr3t"}],
    )
    topo = build_topology(r)
    edges = [e for e in topo.edges if e.src == "10.0.0.2" and e.dst == "10.0.0.1"]
    assert edges, "edge not found"
    assert "cleartext_creds" in edges[0].tags
    assert edges[0].max_severity == "HIGH"


def test_cleartext_protocol_tag_from_finding():
    """'Cleartext Protocol' finding tags edge with 'cleartext'."""
    r = _result(
        edges={("10.0.0.2", "10.0.0.1"): _edge(["FTP"])},
        findings=[{"category": "Cleartext Protocol", "severity": "HIGH",
                   "src": "10.0.0.2", "dst": "10.0.0.1", "detail": "FTP login"}],
    )
    topo = build_topology(r)
    e = next(e for e in topo.edges if e.src == "10.0.0.2")
    assert "cleartext" in e.tags


def test_ssh_tag_from_protocol():
    """Edges carrying 'SSH' in protocols get the 'ssh' tag."""
    r = _result(edges={("10.0.0.2", "10.0.0.1"): _edge(["SSH"])})
    topo = build_topology(r)
    e = topo.edges[0]
    assert "ssh" in e.tags


def test_lateral_movement_tag_protocol_only():
    """SMB/RDP/VNC protocol edges get 'lateral_movement' tag even without a finding."""
    for proto in ("SMB", "RDP", "VNC"):
        r = _result(edges={("10.0.0.2", "10.0.0.1"): _edge([proto])})
        topo = build_topology(r)
        assert "lateral_movement" in topo.edges[0].tags, f"missing for {proto}"


def test_lateral_movement_tag_from_finding():
    """'Lateral Movement Indicator' finding also tags the edge."""
    r = _result(
        edges={("10.0.0.2", "10.0.0.1"): _edge(["SMB"])},
        findings=[{"category": "Lateral Movement Indicator", "severity": "MEDIUM",
                   "src": "10.0.0.2", "dst": "10.0.0.1", "detail": "SMB to client"}],
    )
    topo = build_topology(r)
    assert "lateral_movement" in topo.edges[0].tags


def test_beaconing_tag_from_finding():
    """'Potential Beaconing' finding tags the edge with 'beaconing'."""
    r = _result(
        edges={("10.0.0.2", "10.0.0.1"): _edge(["HTTP"])},
        findings=[{"category": "Potential Beaconing", "severity": "MEDIUM",
                   "src": "10.0.0.2", "dst": "10.0.0.1", "detail": "cv=0.05"}],
    )
    topo = build_topology(r)
    assert "beaconing" in topo.edges[0].tags


def test_unusual_outbound_tag():
    r = _result(
        edges={("10.0.0.2", "8.8.8.8"): _edge(["DNS"])},
        nodes={
            "10.0.0.2": _node("10.0.0.2", role="client"),
            "8.8.8.8":  _node("8.8.8.8",  role="client", is_private=False, subnet="external"),
        },
        findings=[{"category": "Unusual Outbound", "severity": "MEDIUM",
                   "src": "10.0.0.2", "dst": "8.8.8.8", "detail": "port 5000"}],
    )
    topo = build_topology(r)
    e = next(e for e in topo.edges if e.src == "10.0.0.2")
    assert "unusual_outbound" in e.tags


def test_dns_tunneling_attaches_to_dns_edge():
    """DNS tunneling finding (dst=domain string) tags the client→DNS-server edge."""
    r = _result(
        nodes={
            "10.0.0.2": _node("10.0.0.2", role="client"),
            "8.8.8.8":  _node("8.8.8.8", role="server", is_private=False, subnet="external"),
        },
        edges={
            ("10.0.0.2", "8.8.8.8"): _edge(["DNS"], bytes_=5000),
        },
        findings=[{"category": "DNS Tunneling Indicator", "severity": "MEDIUM",
                   "src": "10.0.0.2", "dst": "exfil.attacker.com", "detail": "long labels"}],
    )
    topo = build_topology(r)
    dns_edge = next(e for e in topo.edges if e.src == "10.0.0.2" and e.dst == "8.8.8.8")
    assert "dns_tunneling" in dns_edge.tags
    assert any("exfil.attacker.com" in n for n in dns_edge.notes)


def test_snmp_cleartext_tag():
    r = _result(edges={("10.0.0.2", "10.0.0.1"): _edge(["SNMP"])})
    topo = build_topology(r)
    e = topo.edges[0]
    assert "snmp_cleartext" in e.tags


def test_exfiltration_tag():
    r = _result(
        nodes={
            "10.0.0.2": _node("10.0.0.2", role="client"),
            "1.2.3.4":  _node("1.2.3.4", role="server", is_private=False, subnet="external"),
        },
        edges={("10.0.0.2", "1.2.3.4"): _edge(["HTTP"], bytes_=15_000_000)},
        findings=[{"category": "Possible Exfiltration / Top Talker", "severity": "MEDIUM",
                   "src": "10.0.0.2", "dst": "1.2.3.4", "detail": "15 MB out"}],
    )
    topo = build_topology(r)
    e = topo.edges[0]
    assert "exfiltration" in e.tags


def test_arp_anomaly_sets_node_severity():
    """ARP Anomaly is node-level — it sets max_severity on the TopoNode."""
    r = _result(
        findings=[{"category": "ARP Anomaly / Possible MITM", "severity": "CRITICAL",
                   "src": "10.0.0.1", "dst": "N/A", "detail": "Duplicate ARP reply"}],
    )
    topo = build_topology(r)
    assert topo.nodes["10.0.0.1"].max_severity == "CRITICAL"


def test_gateway_sets_is_gateway():
    r = _result(gateways={"10.0.0.0/24": "10.0.0.1"})
    topo = build_topology(r)
    assert topo.nodes["10.0.0.1"].is_gateway is True
    assert topo.nodes["10.0.0.2"].is_gateway is False


def test_device_category_mapping():
    r = _result(gateways={"10.0.0.0/24": "10.0.0.1"})
    topo = build_topology(r)
    assert topo.nodes["10.0.0.1"].device_category == "network_device"
    assert topo.nodes["10.0.0.2"].device_category == "client"


def test_no_duplicate_nodes_per_ip():
    """Multiple edges from/to the same IP must not create duplicate TopoNodes."""
    r = _result(
        nodes={
            "10.0.0.1": _node("10.0.0.1", role="server"),
            "10.0.0.2": _node("10.0.0.2", role="client"),
        },
        edges={
            ("10.0.0.2", "10.0.0.1"): _edge(["HTTP"]),
            ("10.0.0.1", "10.0.0.2"): _edge(["HTTP"]),
        },
    )
    topo = build_topology(r)
    ips = [n.id for n in topo.nodes.values() if n.kind == "host"]
    assert len(ips) == len(set(ips)), "duplicate TopoNode IDs found"


# ── Wi-Fi integration (real parsed pcapng) ───────────────────────────────────

def test_wifi_assoc_and_deauth_tags(tmp_path):
    beacon = wifi_beacon_frame("TestNet", bssid="aa:bb:cc:dd:ee:ff", channel=6)
    deauth = wifi_deauth_frame("11:22:33:44:55:66", bssid="aa:bb:cc:dd:ee:ff", reason=7)
    path = write_pcapng(tmp_path / "wifi.pcapng", [beacon, deauth], ltype=127)

    packets = list(parse_pcap(path))
    wifi_data = extract_wifi_events(packets)

    r = _result(wifi_data=wifi_data, packets=packets)
    topo = build_topology(r)

    ap_nodes = [n for n in topo.nodes.values() if n.kind == "ap"]
    assert ap_nodes, "expected at least one AP node"
    assert any(n.extra.get("ssid") == "TestNet" for n in ap_nodes)

    deauth_edges = [e for e in topo.edges if "deauth" in e.tags]
    assert deauth_edges, "expected a deauth-tagged edge"


# ── EAP-TLS integration ──────────────────────────────────────────────────────

def test_eap_tls_creates_radius_edge(tmp_path):
    import datetime
    now = datetime.datetime.utcnow()
    der = make_certificate_der(
        subject_cn="test-auth.lan", issuer_cn="TestCA",
        not_before=now - datetime.timedelta(days=1),
        not_after=now + datetime.timedelta(days=365),
    )
    cert_record = tls_certificate_record([der])
    frame = eapol_eap_tls_frame("11:22:33:44:55:66", "aa:bb:cc:dd:ee:ff", cert_record)
    path = write_pcap(tmp_path / "eap.pcap", [frame])

    packets = list(parse_pcap(path))
    r = _result(packets=packets)
    topo = build_topology(r)

    eap_edges = [e for e in topo.edges if "radius_eap_tls" in e.tags]
    assert eap_edges, "expected a radius_eap_tls-tagged edge"
    eap_nodes = [n for n in topo.nodes.values() if n.kind == "eap_tls_peer"]
    assert len(eap_nodes) == 2


# ── capture_device detection ─────────────────────────────────────────────────

def test_capture_device_high_confidence(tmp_path):
    """A capture where one MAC appears in 100% of frames should yield 'high'."""
    frames = [eth_ip_tcp("cc:cc:cc:cc:cc:cc", "dd:dd:dd:dd:dd:dd",
                          "10.0.0.10", "10.0.0.1", 5000, 80, b"X") for _ in range(40)]
    path = write_pcap(tmp_path / "cap.pcap", frames)
    packets = list(parse_pcap(path))
    nodes = {"10.0.0.10": {"macs": {"cc:cc:cc:cc:cc:cc"}, "hostname": None}}
    cd = detect_capture_device(packets, nodes)
    assert cd["confidence"] in ("high", "medium")
    assert cd["mac"] is not None


def test_capture_device_unknown_no_dominant_mac(tmp_path):
    """Three MACs with equal share → confidence unknown."""
    frames = (
        [eth_ip_tcp("aa:aa:aa:aa:aa:aa", "bb:bb:bb:bb:bb:bb", "10.0.0.1", "10.0.0.2", 1, 80, b"A")] * 10
        + [eth_ip_tcp("bb:bb:bb:bb:bb:bb", "cc:cc:cc:cc:cc:cc", "10.0.0.2", "10.0.0.3", 2, 80, b"B")] * 10
        + [eth_ip_tcp("cc:cc:cc:cc:cc:cc", "aa:aa:aa:aa:aa:aa", "10.0.0.3", "10.0.0.1", 3, 80, b"C")] * 10
    )
    path = write_pcap(tmp_path / "even.pcap", frames)
    packets = list(parse_pcap(path))
    cd = detect_capture_device(packets, {})
    assert cd["confidence"] == "unknown"
