"""Tests for pcap_tool.diagrams: draw.io L3/L2 XML generation."""

import xml.etree.ElementTree as ET

from pcap_tool.parser import parse_pcap
from pcap_tool.graph.build import build_graph
from pcap_tool.graph.gateways import detect_gateways
from pcap_tool.extractors.traceroute import extract_traceroutes
from pcap_tool.extractors.wifi import extract_wifi_events
from pcap_tool.diagrams.drawio_l3 import generate_drawio
from pcap_tool.diagrams.drawio_l2 import generate_l2_drawio

from .conftest import eth_ip_tcp, write_pcap


def _build(tmp_path):
    frame = eth_ip_tcp("bb:bb:bb:bb:bb:bb", "aa:aa:aa:aa:aa:aa",
                        "10.0.0.5", "10.0.0.1", 12345, 80, b"GET / HTTP/1.1\r\n\r\n")
    path = write_pcap(tmp_path / "diag.pcap", [frame])
    packets = list(parse_pcap(path))
    nodes, edges, rows, findings, cleartext_hits, arp_table = build_graph(packets)
    gateways = detect_gateways(packets, nodes)
    traceroutes = extract_traceroutes(packets)
    wifi_data = extract_wifi_events(packets)
    return packets, nodes, edges, findings, gateways, traceroutes, arp_table, wifi_data


def test_generate_drawio_l3_is_valid_xml(tmp_path):
    _, nodes, edges, findings, gateways, traceroutes, _, _ = _build(tmp_path)
    xml_str = generate_drawio(nodes, findings, gateways, traceroutes, title="Test Diagram")
    root = ET.fromstring(xml_str)
    assert root.tag == "mxGraphModel"


def test_generate_drawio_l2_is_valid_xml(tmp_path):
    _, nodes, edges, findings, gateways, traceroutes, arp_table, wifi_data = _build(tmp_path)
    xml_str = generate_l2_drawio(wifi_data, nodes, arp_table, title="Test L2")
    root = ET.fromstring(xml_str)
    assert root.tag == "mxGraphModel"
