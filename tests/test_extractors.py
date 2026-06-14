"""Tests for pcap_tool.extractors: cleartext, banners, TLS, DNS, WiFi, traceroute."""

import base64
import socket
import struct

from pcap_tool.parser import parse_pcap
from pcap_tool.extractors.cleartext import extract_cleartext
from pcap_tool.extractors.banners import extract_banners
from pcap_tool.extractors.tls import extract_tls_sessions
from pcap_tool.extractors.dns import extract_dns_events
from pcap_tool.extractors.wifi import extract_wifi_events
from pcap_tool.extractors.traceroute import extract_traceroutes

from .conftest import (
    eth_frame, eth_ip_tcp, eth_ip_udp, eth_ip_icmp,
    ipv4_packet, tcp_segment, udp_segment,
    write_pcap, write_pcapng,
    tls_client_hello_record,
    dns_query_frame, dns_response_frame,
    wifi_beacon_frame,
)


# ── cleartext ────────────────────────────────────────────────────────────────

def test_ftp_username_password(tmp_path):
    frame = eth_ip_tcp("bb:bb:bb:bb:bb:bb", "aa:aa:aa:aa:aa:aa",
                        "10.0.0.5", "10.0.0.1", 12345, 21, b"USER admin\r\n")
    path = write_pcap(tmp_path / "ftp.pcap", [frame])
    packets = list(parse_pcap(path))
    hits = extract_cleartext(packets[0])
    assert any(h["type"] == "FTP Username" and h["value"] == "admin" for h in hits)


def test_http_basic_auth(tmp_path):
    creds = base64.b64encode(b"admin:password").decode()
    payload = (f"GET / HTTP/1.1\r\nHost: example.com\r\n"
               f"Authorization: Basic {creds}\r\n\r\n").encode()
    frame = eth_ip_tcp("bb:bb:bb:bb:bb:bb", "aa:aa:aa:aa:aa:aa",
                        "10.0.0.5", "10.0.0.1", 12345, 80, payload)
    path = write_pcap(tmp_path / "http.pcap", [frame])
    packets = list(parse_pcap(path))
    hits = extract_cleartext(packets[0])
    assert any(h["type"] == "HTTP Basic Auth (decoded)" and h["value"] == "admin:password"
               for h in hits)


def test_snmp_community_string(tmp_path):
    payload = b"\x30\x29\x02\x01\x00\x04\x0bmycommunity\xa0\x1b\x02\x04\x00\x00\x00\x01"
    frame = eth_ip_udp("bb:bb:bb:bb:bb:bb", "aa:aa:aa:aa:aa:aa",
                        "10.0.0.5", "10.0.0.1", 50000, 161, payload)
    path = write_pcap(tmp_path / "snmp.pcap", [frame])
    packets = list(parse_pcap(path))
    assert packets[0]["proto"] == "SNMP"
    hits = extract_cleartext(packets[0])
    assert any(h["type"] == "SNMP Community String" and h["value"] == "mycommunity"
               for h in hits)


# ── banners ──────────────────────────────────────────────────────────────────

def test_http_server_banner(tmp_path):
    payload = (b"HTTP/1.1 200 OK\r\n"
               b"Server: nginx/1.18.0\r\n"
               b"Content-Length: 0\r\n\r\n")
    frame = eth_ip_tcp("aa:aa:aa:aa:aa:aa", "bb:bb:bb:bb:bb:bb",
                        "10.0.0.1", "10.0.0.5", 80, 54321, payload)
    path = write_pcap(tmp_path / "banner.pcap", [frame])
    packets = list(parse_pcap(path))
    banners = extract_banners(packets)
    assert any(b["banner_type"] == "HTTP Server Header" and b["value"] == "nginx/1.18.0"
               for b in banners)


# ── TLS ──────────────────────────────────────────────────────────────────────

def test_tls_client_hello_sni(tmp_path):
    record = tls_client_hello_record(sni_host="example.com")
    frame = eth_ip_tcp("bb:bb:bb:bb:bb:bb", "aa:aa:aa:aa:aa:aa",
                        "10.0.0.5", "93.184.216.34", 50000, 443, record)
    path = write_pcap(tmp_path / "tls.pcap", [frame])
    packets = list(parse_pcap(path))
    sessions = extract_tls_sessions(packets)
    assert len(sessions) == 1
    sess = sessions[0]
    assert sess["sni"] == "example.com"
    assert sess["client_ip"] == "10.0.0.5"
    assert sess["server_ip"] == "93.184.216.34"
    assert sess["server_port"] == 443


# ── DNS ──────────────────────────────────────────────────────────────────────

def test_dns_query_and_response(tmp_path):
    qname = "host.example.com"

    query_frame = dns_query_frame("bb:bb:bb:bb:bb:bb", "aa:aa:aa:aa:aa:aa",
                                   "10.0.0.5", "8.8.8.8", 50000, qname)

    resp_frame = dns_response_frame("aa:aa:aa:aa:aa:aa", "bb:bb:bb:bb:bb:bb",
                                     "8.8.8.8", "10.0.0.5", 53, 50000, qname,
                                     answer_ip="93.184.216.34", ttl=300)

    path = write_pcap(tmp_path / "dns.pcap", [query_frame, resp_frame])
    packets = list(parse_pcap(path))
    events = extract_dns_events(packets)
    assert len(events) == 2

    query_evt = next(e for e in events if not e["is_response"])
    assert query_evt["query_name"] == qname
    assert query_evt["qtype"] == "A"

    resp_evt = next(e for e in events if e["is_response"])
    assert resp_evt["query_name"] == qname
    assert resp_evt["answer_ip"] == "93.184.216.34"
    assert resp_evt["ttl"] == 300


# ── WiFi ─────────────────────────────────────────────────────────────────────

def test_wifi_beacon_ap(tmp_path):
    frame = wifi_beacon_frame("TestNet", bssid="aa:bb:cc:dd:ee:ff", channel=6)

    path = write_pcap(tmp_path / "wifi.pcap", [frame], ltype=127)
    packets = list(parse_pcap(path))
    wifi_data = extract_wifi_events(packets)
    aps = wifi_data["aps"]
    assert any(ap["ssid"] == "TestNet" for ap in aps)


# ── Traceroute ───────────────────────────────────────────────────────────────

def test_traceroute_hops(tmp_path):
    probe_src, probe_dst = "10.0.0.5", "8.8.8.8"
    inner_hdr = struct.pack(">BBHHHBBH4s4s",
                             0x45, 0, 28, 0, 0x4000, 1, 17, 0,
                             socket.inet_aton(probe_src), socket.inet_aton(probe_dst))

    def icmp_time_exceeded(router_ip):
        icmp_payload = struct.pack(">BBHHH", 11, 0, 0, 0, 0) + inner_hdr
        return eth_frame("bb:bb:bb:bb:bb:bb", "aa:aa:aa:aa:aa:aa", 0x0800,
                          ipv4_packet(router_ip, probe_src, 1, icmp_payload))

    frames = [icmp_time_exceeded("10.0.0.254"), icmp_time_exceeded("10.0.1.1")]
    path = write_pcap(tmp_path / "trace.pcap", frames)
    packets = list(parse_pcap(path))
    traces = extract_traceroutes(packets)
    assert len(traces) == 1
    tr = traces[0]
    assert tr["src"] == probe_src
    assert tr["dst"] == probe_dst
    hop_ips = [h["router_ip"] for h in tr["hops"]]
    assert hop_ips == ["10.0.0.254", "10.0.1.1"]
