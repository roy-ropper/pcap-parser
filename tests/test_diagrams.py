"""Tests for pcap_tool.diagrams: topology draw.io + SVG generation."""

import xml.etree.ElementTree as ET

from pcap_tool.parser import parse_pcap
from pcap_tool.graph.build import build_graph
from pcap_tool.graph.gateways import detect_gateways
from pcap_tool.extractors.traceroute import extract_traceroutes
from pcap_tool.extractors.wifi import extract_wifi_events
from pcap_tool.topology.model import build_topology, TopoEdge, TopologyModel, TopoNode
from pcap_tool.topology.render_policy import select_edges, RenderResult
from pcap_tool.diagrams.drawio_topology import generate_topology_drawio
from pcap_tool.diagrams.topology_svg import generate_topology_svg
from pcap_tool.diagrams.drawio_l2 import generate_l2_drawio

from .conftest import eth_ip_tcp, write_pcap


def _build(tmp_path):
    """Run the full pipeline on a minimal synthetic capture and return topology+render."""
    frame = eth_ip_tcp("bb:bb:bb:bb:bb:bb", "aa:aa:aa:aa:aa:aa",
                        "10.0.0.5", "10.0.0.1", 12345, 80, b"GET / HTTP/1.1\r\n\r\n")
    path = write_pcap(tmp_path / "diag.pcap", [frame])
    packets = list(parse_pcap(path))
    nodes, edges, rows, findings, cleartext_hits, arp_table = build_graph(packets)
    gateways = detect_gateways(packets, nodes)
    traceroutes = extract_traceroutes(packets)
    wifi_data = extract_wifi_events(packets)
    result = dict(packets=packets, nodes=nodes, edges=edges, findings=findings,
                  cleartext_hits=cleartext_hits, gateways=gateways,
                  traceroutes=traceroutes, wifi_data=wifi_data, title="Test Diagram")
    topo = build_topology(result)
    render = select_edges(topo)
    return topo, render, nodes, wifi_data, arp_table


def _cleartext_topology():
    """A minimal topology with one cleartext-creds edge and one normal edge."""
    nodes = {
        "10.0.0.1": TopoNode(id="10.0.0.1", kind="host", ip="10.0.0.1",
                              device_category="server", subnet="10.0.0.0/24",
                              is_private=True, role="server"),
        "10.0.0.2": TopoNode(id="10.0.0.2", kind="host", ip="10.0.0.2",
                              device_category="client", subnet="10.0.0.0/24",
                              is_private=True, role="client"),
    }
    bad_edge = TopoEdge(src="10.0.0.2", dst="10.0.0.1",
                        protocols=["Telnet"], bytes=500,
                        tags={"cleartext", "cleartext_creds"},
                        max_severity="HIGH")
    topo = TopologyModel(
        title="Test", nodes=nodes, edges=[bad_edge], findings=[],
        gateways={}, capture_device={}, dns_servers=set(), traceroutes=[],
    )
    render = select_edges(topo)
    return topo, render


# ── draw.io topology (L3) ─────────────────────────────────────────────────────

def test_generate_topology_drawio_valid_xml(tmp_path):
    topo, render, *_ = _build(tmp_path)
    xml_str = generate_topology_drawio(topo, render, title="Test Diagram")
    root = ET.fromstring(xml_str)
    assert root.tag == "mxGraphModel"


def test_generate_topology_drawio_has_nodes_and_edges(tmp_path):
    topo, render, *_ = _build(tmp_path)
    xml_str = generate_topology_drawio(topo, render)
    root = ET.fromstring(xml_str)
    cells = root.findall(".//mxCell")
    # Should have at least the two host node cells plus infrastructure cells
    assert len(cells) >= 4


def test_generate_topology_drawio_cleartext_edge_style():
    """A cleartext-creds edge should produce an mxCell with red strokeColor."""
    topo, render = _cleartext_topology()
    xml_str = generate_topology_drawio(topo, render, title="Cleartext Test")
    root = ET.fromstring(xml_str)
    edge_cells = [c for c in root.findall(".//mxCell")
                  if c.get("edge") == "1" and "#b85450" in (c.get("style") or "")]
    assert edge_cells, "expected at least one red edge cell for cleartext traffic"


def test_generate_topology_drawio_edge_cap(tmp_path):
    """Total rendered edge cells must not exceed DEFAULT_MAX_EDGES + structure cells."""
    from pcap_tool.topology.render_policy import DEFAULT_MAX_EDGES
    topo, render, *_ = _build(tmp_path)
    xml_str = generate_topology_drawio(topo, render)
    root = ET.fromstring(xml_str)
    edge_cells = [c for c in root.findall(".//mxCell") if c.get("edge") == "1"]
    assert len(edge_cells) <= DEFAULT_MAX_EDGES + 20  # +20 for legend lines etc.


def test_generate_topology_drawio_capture_box(tmp_path):
    """The capture device info box should appear in the XML."""
    topo, render, *_ = _build(tmp_path)
    xml_str = generate_topology_drawio(topo, render)
    assert "capture_box" in xml_str or "Capture device" in xml_str


# ── SVG topology ─────────────────────────────────────────────────────────────

def test_generate_topology_svg_valid_xml(tmp_path):
    topo, render, *_ = _build(tmp_path)
    svg_str = generate_topology_svg(topo, render, title="Test")
    assert "<svg" in svg_str
    root = ET.fromstring(svg_str)
    assert root.tag == "svg" or root.tag.endswith("}svg")


def test_generate_topology_svg_xss_safety():
    """Hostnames with <script>/& must be XML-escaped, not interpreted as markup."""
    nodes = {
        "10.0.0.1": TopoNode(id="10.0.0.1", kind="host", ip="10.0.0.1",
                              hostname='<script>alert("xss")</script>',
                              device_category="server", subnet="10.0.0.0/24",
                              is_private=True, role="server"),
        "10.0.0.2": TopoNode(id="10.0.0.2", kind="host", ip="10.0.0.2",
                              hostname="A & B",
                              device_category="client", subnet="10.0.0.0/24",
                              is_private=True, role="client"),
    }
    topo = TopologyModel(
        title="XSS Test", nodes=nodes, edges=[], findings=[],
        gateways={}, capture_device={}, dns_servers=set(), traceroutes=[],
    )
    render = RenderResult(edges=[], node_summaries={})
    svg_str = generate_topology_svg(topo, render)
    # XML must parse without errors (which would break on unescaped < or &)
    ET.fromstring(svg_str)
    # The raw script tag must NOT appear unescaped in the SVG text
    assert "<script>" not in svg_str
    # & must be represented as &amp; in attribute/text content
    assert "&amp;" in svg_str or "A & B" not in svg_str


# ── L2/Wi-Fi draw.io (unchanged generator) ───────────────────────────────────

def test_generate_drawio_l2_is_valid_xml(tmp_path):
    _, _, nodes, wifi_data, arp_table = _build(tmp_path)
    xml_str = generate_l2_drawio(wifi_data, nodes, arp_table, title="Test L2")
    root = ET.fromstring(xml_str)
    assert root.tag == "mxGraphModel"
