"""Tests for pcap_tool.parser: global header formats, link types, dissection."""

import struct

from pcap_tool.parser import parse_pcap

from .conftest import (
    eth_ip_tcp, eth_ip_udp, eth_arp,
    pcap_bytes, write_pcap, write_pcapng,
)


def test_le_pcap_basic_tcp(tmp_path):
    frame = eth_ip_tcp("bb:bb:bb:bb:bb:bb", "aa:aa:aa:aa:aa:aa",
                        "10.0.0.5", "10.0.0.1", 12345, 80, b"GET / HTTP/1.1\r\n\r\n")
    path = write_pcap(tmp_path / "le.pcap", [frame], endian="<")
    packets = list(parse_pcap(path))
    assert len(packets) == 1
    p = packets[0]
    assert p["src_ip"] == "10.0.0.5"
    assert p["dst_ip"] == "10.0.0.1"
    assert p["proto"] == "HTTP"
    assert p["dst_port"] == 80
    assert p["src_mac"] == "bb:bb:bb:bb:bb:bb"
    assert p["dst_mac"] == "aa:aa:aa:aa:aa:aa"


def test_be_pcap(tmp_path):
    frame = eth_ip_udp("bb:bb:bb:bb:bb:bb", "aa:aa:aa:aa:aa:aa",
                        "10.0.0.5", "8.8.8.8", 50000, 53, b"\x00" * 10)
    path = write_pcap(tmp_path / "be.pcap", [frame], endian=">")
    packets = list(parse_pcap(path))
    assert len(packets) == 1
    assert packets[0]["proto"] == "DNS"
    assert packets[0]["dst_ip"] == "8.8.8.8"


def test_nanosecond_pcap(tmp_path):
    frame = eth_ip_tcp("bb:bb:bb:bb:bb:bb", "aa:aa:aa:aa:aa:aa",
                        "10.0.0.5", "10.0.0.1", 12345, 443)
    path = write_pcap(tmp_path / "ns.pcap", [frame], endian="<", nanosecond=True)
    packets = list(parse_pcap(path))
    assert len(packets) == 1
    assert packets[0]["proto"] == "HTTPS"


def test_arp_packet(tmp_path):
    frame = eth_arp("bb:bb:bb:bb:bb:bb", "ff:ff:ff:ff:ff:ff",
                     "bb:bb:bb:bb:bb:bb", "10.0.0.5",
                     "00:00:00:00:00:00", "10.0.0.1")
    path = write_pcap(tmp_path / "arp.pcap", [frame])
    packets = list(parse_pcap(path))
    assert len(packets) == 1
    p = packets[0]
    assert p["proto"] == "ARP"
    assert p["arp_sender_ip"] == "10.0.0.5"
    assert p["arp_sender_mac"] == "bb:bb:bb:bb:bb:bb"


def test_raw_ipv4_link_type(tmp_path):
    # ltype 101 = raw IPv4, no Ethernet header at all
    from .conftest import ipv4_packet, tcp_segment
    raw = ipv4_packet("10.0.0.5", "10.0.0.1", 6, tcp_segment(1234, 22))
    path = write_pcap(tmp_path / "raw.pcap", [raw], ltype=101)
    packets = list(parse_pcap(path))
    assert len(packets) == 1
    assert packets[0]["proto"] == "SSH"
    assert packets[0]["src_ip"] == "10.0.0.5"


def test_sll_link_type(tmp_path):
    # ltype 113 = Linux cooked capture: 16-byte header, ethertype at [14:16]
    from .conftest import ipv4_packet, udp_segment
    sll_hdr = b"\x00" * 14 + struct.pack(">H", 0x0800)
    ip_pkt = ipv4_packet("10.0.0.5", "10.0.0.1", 17, udp_segment(123, 123, b"\x00" * 40))
    path = write_pcap(tmp_path / "sll.pcap", [sll_hdr + ip_pkt], ltype=113)
    packets = list(parse_pcap(path))
    assert len(packets) == 1
    assert packets[0]["proto"] == "NTP"


def test_pcapng_minimal(tmp_path):
    frame = eth_ip_tcp("bb:bb:bb:bb:bb:bb", "aa:aa:aa:aa:aa:aa",
                        "10.0.0.5", "10.0.0.1", 12345, 80)
    path = write_pcapng(tmp_path / "test.pcapng", [frame])
    packets = list(parse_pcap(path))
    assert len(packets) == 1
    assert packets[0]["proto"] == "HTTP"


def test_vlan_tagged_frame(tmp_path):
    from .conftest import eth_frame, ipv4_packet, tcp_segment
    inner = ipv4_packet("10.0.0.5", "10.0.0.1", 6, tcp_segment(1234, 80))
    # 802.1Q tag: TPID 0x8100, TCI with VLAN id 42, then real ethertype 0x0800
    vlan_payload = struct.pack(">HH", 0x002A, 0x0800) + inner
    frame = eth_frame("aa:aa:aa:aa:aa:aa", "bb:bb:bb:bb:bb:bb", 0x8100, vlan_payload)
    path = write_pcap(tmp_path / "vlan.pcap", [frame])
    packets = list(parse_pcap(path))
    assert len(packets) == 1
    assert packets[0]["vlan_id"] == 42
    assert packets[0]["proto"] == "HTTP"
