"""Tests for pcap_tool.diagrams.vsdx: hand-rolled .vsdx (Visio OOXML) export."""

import io
import zipfile
import xml.etree.ElementTree as ET

from pcap_tool.parser import parse_pcap
from pcap_tool.graph.build import build_graph
from pcap_tool.graph.gateways import detect_gateways
from pcap_tool.diagrams.vsdx import generate_vsdx

from .conftest import eth_ip_tcp, write_pcap

REQUIRED_PARTS = {
    "[Content_Types].xml",
    "_rels/.rels",
    "docProps/core.xml",
    "docProps/app.xml",
    "visio/document.xml",
    "visio/_rels/document.xml.rels",
    "visio/windows.xml",
    "visio/pages/pages.xml",
    "visio/pages/_rels/pages.xml.rels",
    "visio/pages/page1.xml",
}


def test_generate_vsdx_zip_structure(tmp_path):
    frame = eth_ip_tcp("bb:bb:bb:bb:bb:bb", "aa:aa:aa:aa:aa:aa",
                        "10.0.0.5", "10.0.0.1", 12345, 80, b"GET / HTTP/1.1\r\n\r\n")
    path = write_pcap(tmp_path / "vsdx.pcap", [frame])
    packets = list(parse_pcap(path))
    nodes, edges, rows, findings, cleartext_hits, arp_table = build_graph(packets)
    gateways = detect_gateways(packets, nodes)

    buf = generate_vsdx(nodes, edges, findings, gateways, title="Test Diagram")
    assert isinstance(buf, io.BytesIO)

    zf = zipfile.ZipFile(buf)
    names = set(zf.namelist())
    assert REQUIRED_PARTS.issubset(names)

    for name in names:
        if name.endswith(".xml") or name.endswith(".rels"):
            ET.fromstring(zf.read(name))
