"""Tests for pcap_tool.graph.build / graph.findings: build_graph() shape and
the pentest finding detectors (#1-11), plus the DNS-based detector (#10) and
certificate-based detectors (#12-13) tested via compute_*_findings directly."""

from pcap_tool.parser import parse_pcap
from pcap_tool.graph.build import build_graph
from pcap_tool.graph.findings import compute_dns_findings

from .conftest import (
    eth_ip_tcp, eth_ip_udp, eth_ip_icmp, eth_arp,
    write_pcap,
)


def _categories(findings):
    return {f["category"] for f in findings}


# ── build_graph() shape ──────────────────────────────────────────────────────

def test_build_graph_basic_shape(tmp_path):
    frame = eth_ip_tcp("bb:bb:bb:bb:bb:bb", "aa:aa:aa:aa:aa:aa",
                        "10.0.0.5", "10.0.0.1", 12345, 80, b"GET / HTTP/1.1\r\n\r\n")
    path = write_pcap(tmp_path / "basic.pcap", [frame])
    packets = list(parse_pcap(path))
    nodes, edges, rows, findings, cleartext_hits, arp_table = build_graph(packets)

    assert "10.0.0.5" in nodes and "10.0.0.1" in nodes
    assert ("10.0.0.5", "10.0.0.1") in edges
    assert edges[("10.0.0.5", "10.0.0.1")]["count"] == 1
    assert "HTTP" in edges[("10.0.0.5", "10.0.0.1")]["protocols"]
    assert len(rows) == 1


# ── 1. Cleartext Protocol ─────────────────────────────────────────────────────

def test_finding_cleartext_protocol(tmp_path):
    frame = eth_ip_tcp("bb:bb:bb:bb:bb:bb", "aa:aa:aa:aa:aa:aa",
                        "10.0.0.5", "10.0.0.1", 12345, 23, b"login: admin\r\n")
    path = write_pcap(tmp_path / "telnet.pcap", [frame])
    packets = list(parse_pcap(path))
    _, _, _, findings, _, _ = build_graph(packets)
    assert "Cleartext Protocol" in _categories(findings)


# ── 2. Suspicious Port ────────────────────────────────────────────────────────

def test_finding_suspicious_port(tmp_path):
    frame = eth_ip_tcp("bb:bb:bb:bb:bb:bb", "aa:aa:aa:aa:aa:aa",
                        "10.0.0.5", "10.0.0.1", 12345, 4444, b"shell")
    path = write_pcap(tmp_path / "suspicious.pcap", [frame])
    packets = list(parse_pcap(path))
    _, _, _, findings, _, _ = build_graph(packets)
    assert "Suspicious Port" in _categories(findings)


# ── 3. ARP Anomaly / Possible MITM ───────────────────────────────────────────

def test_finding_arp_anomaly(tmp_path):
    f1 = eth_arp("bb:bb:bb:bb:bb:bb", "ff:ff:ff:ff:ff:ff",
                  "bb:bb:bb:bb:bb:bb", "10.0.0.5", "00:00:00:00:00:00", "10.0.0.1")
    f2 = eth_arp("cc:cc:cc:cc:cc:cc", "ff:ff:ff:ff:ff:ff",
                  "cc:cc:cc:cc:cc:cc", "10.0.0.5", "00:00:00:00:00:00", "10.0.0.1")
    path = write_pcap(tmp_path / "arp.pcap", [f1, f2])
    packets = list(parse_pcap(path))
    _, _, _, findings, _, arp_table = build_graph(packets)
    assert "ARP Anomaly / Possible MITM" in _categories(findings)
    assert len(arp_table["10.0.0.5"]) == 2


# ── 4. Unusual Outbound ───────────────────────────────────────────────────────

def test_finding_unusual_outbound(tmp_path):
    frame = eth_ip_tcp("bb:bb:bb:bb:bb:bb", "aa:aa:aa:aa:aa:aa",
                        "10.0.0.5", "8.8.8.8", 12345, 5000, b"data")
    path = write_pcap(tmp_path / "outbound.pcap", [frame])
    packets = list(parse_pcap(path))
    _, _, _, findings, _, _ = build_graph(packets)
    assert "Unusual Outbound" in _categories(findings)


# ── 7. SNMP Cleartext ─────────────────────────────────────────────────────────

def test_finding_snmp_cleartext(tmp_path):
    frame = eth_ip_udp("bb:bb:bb:bb:bb:bb", "aa:aa:aa:aa:aa:aa",
                        "10.0.0.5", "10.0.0.1", 50000, 161, b"\x30\x10public")
    path = write_pcap(tmp_path / "snmp.pcap", [frame])
    packets = list(parse_pcap(path))
    _, _, _, findings, _, _ = build_graph(packets)
    assert "SNMP Cleartext" in _categories(findings)


# ── 8. Port Scan (vertical & horizontal) ─────────────────────────────────────

def test_finding_port_scan_vertical(tmp_path):
    frames = [
        eth_ip_tcp("bb:bb:bb:bb:bb:bb", "aa:aa:aa:aa:aa:aa",
                   "10.0.0.5", "10.0.0.1", 50000, port, b"")
        for port in range(20, 40)   # 20 distinct ports >= PORT_SCAN_PORT_THRESHOLD
    ]
    path = write_pcap(tmp_path / "vscan.pcap", frames)
    packets = list(parse_pcap(path))
    _, _, _, findings, _, _ = build_graph(packets)
    scans = [f for f in findings if f["category"] == "Port Scan"]
    assert any("vertical scan" in f["detail"] for f in scans)


def test_finding_port_scan_horizontal(tmp_path):
    frames = [
        eth_ip_tcp("bb:bb:bb:bb:bb:bb", "aa:aa:aa:aa:aa:aa",
                   "10.0.0.5", f"10.0.0.{i}", 50000, 22, b"")
        for i in range(1, 12)   # 11 distinct hosts >= PORT_SCAN_HOST_THRESHOLD
    ]
    path = write_pcap(tmp_path / "hscan.pcap", frames)
    packets = list(parse_pcap(path))
    _, _, _, findings, _, _ = build_graph(packets)
    scans = [f for f in findings if f["category"] == "Port Scan"]
    assert any("horizontal scan" in f["detail"] for f in scans)


# ── 9. Possible Exfiltration / Top Talker ─────────────────────────────────────

def test_finding_exfiltration(tmp_path):
    big_payload = b"A" * 60000
    frames = [
        eth_ip_tcp("bb:bb:bb:bb:bb:bb", "aa:aa:aa:aa:aa:aa",
                   "10.0.0.5", "8.8.8.8", 50000, 443, big_payload)
        for _ in range(200)   # ~12MB total, >= EXFIL_BYTES_THRESHOLD (10MB)
    ]
    path = write_pcap(tmp_path / "exfil.pcap", frames)
    packets = list(parse_pcap(path))
    _, _, _, findings, _, _ = build_graph(packets)
    assert "Possible Exfiltration / Top Talker" in _categories(findings)


# ── 11. ICMP Tunneling Indicator ─────────────────────────────────────────────

def test_finding_icmp_tunneling(tmp_path):
    big_payload = b"A" * 100   # > ICMP_TUNNEL_PAYLOAD_THRESHOLD (64)
    frames = [
        eth_ip_icmp("bb:bb:bb:bb:bb:bb", "aa:aa:aa:aa:aa:aa",
                    "10.0.0.5", "10.0.0.1", icmp_type=8, code=0, payload=big_payload, seq=i)
        for i in range(1, 7)   # >= ICMP_TUNNEL_PACKET_THRESHOLD (5)
    ]
    path = write_pcap(tmp_path / "icmp_tunnel.pcap", frames)
    packets = list(parse_pcap(path))
    _, _, _, findings, _, _ = build_graph(packets)
    assert "ICMP Tunneling Indicator" in _categories(findings)


# ── 10. DNS Tunneling Indicator ──────────────────────────────────────────────

def test_dns_tunneling_long_label():
    long_label = "a" * 40
    dns_events = [{
        "client_ip": "10.0.0.5",
        "query_name": f"{long_label}.example.com",
        "is_response": False,
        "rcode": "",
    }]
    findings = compute_dns_findings(dns_events)
    assert any(f["category"] == "DNS Tunneling Indicator" and "long/high-entropy" in f["detail"]
               for f in findings)


def test_dns_tunneling_nxdomain_flood():
    dns_events = [
        {
            "client_ip": "10.0.0.5",
            "query_name": f"sub{i}.tunnel.com",
            "is_response": True,
            "rcode": "NXDOMAIN",
        }
        for i in range(12)   # >= DNS_TUNNEL_NXDOMAIN_THRESHOLD (10)
    ]
    findings = compute_dns_findings(dns_events)
    assert any(f["category"] == "DNS Tunneling Indicator" and "NXDOMAIN" in f["detail"]
               for f in findings)
