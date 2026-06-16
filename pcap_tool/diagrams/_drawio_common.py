"""Shared helpers for the draw.io diagram generators: XML-safe string
escaping, subnet-container rendering, and the traceroute section."""

from ._xml_helpers import _cell, _geo
from ..graph.layout import SUBNET_PALETTES, CONT_TITLE, PAGE_X

# XML 1.0 forbids most control characters (anything < 0x09, 0x0B, 0x0C,
# 0x0E-0x1F). Strip them from packet-derived strings before embedding.
_illegal_xml = str.maketrans(
    "", "",
    "".join(chr(i) for i in list(range(0, 9)) + [11, 12] + list(range(14, 32)))
)


def xs(s):
    """Return s safe for embedding in draw.io XML cell values (html=1)."""
    if not isinstance(s, str):
        s = str(s)
    s = s.translate(_illegal_xml)
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def draw_subnet_containers(g, containers):
    """Render one swimlane container per subnet. Returns {subnet: cell_id}."""
    cont_ids = {}
    for ci, cont in enumerate(containers):
        cid = f"cont_{ci}"
        cont_ids[cont["subnet"]] = cid
        if cont["subnet"] == "external":
            fill, stroke = "#fff3e0", "#e65100"; fc = "#bf360c"
            lbl = "&#x2601;  External / Internet"
        else:
            fill, stroke = SUBNET_PALETTES[cont["palette_idx"] % len(SUBNET_PALETTES)]
            fc = stroke
            lbl = f"Subnet: {xs(cont['subnet'])}"

        cc = _cell(g, id=cid, value=f"<b>{lbl}</b>",
                   style=(f"swimlane;startSize={CONT_TITLE};fillColor={fill};"
                          f"strokeColor={stroke};fontColor={fc};fontSize=11;"
                          "fontStyle=1;rounded=1;arcSize=3;swimlaneLine=1;"
                          "align=left;spacingLeft=8;html=1;"),
                   vertex="1", parent="1")
        _geo(cc, x=cont["x"], y=cont["y"], w=cont["w"], h=cont["h"])
    return cont_ids


def draw_traceroute_section(g, traceroutes, node_id_map, start_y):
    """Draw traceroute hop chains below the main diagram, as a horizontal
    chain of hop nodes per trace, grouped in a swimlane container."""
    HOP_W      = 120
    HOP_H      = 50
    HOP_GAP    = 60
    SECT_PAD   = 20
    SECT_TITLE = 30
    cy         = int(start_y)
    SHAPE_ROUTER = "shape=mxgraph.cisco.routers.router;"

    hdr = _cell(g, id="tr_hdr",
                value="<b>&#128246; Traceroute Paths (reconstructed from ICMP TTL-exceeded)</b>",
                style=("text;html=1;strokeColor=none;fillColor=none;"
                       "align=left;verticalAlign=middle;fontSize=13;"
                       "fontColor=#333;fontStyle=1;"),
                vertex="1", parent="1")
    _geo(hdr, x=PAGE_X, y=cy, w=900, h=28)
    cy += 36

    for ti, trace in enumerate(traceroutes):
        hops = trace["hops"]
        n_hops = len(hops)
        if n_hops == 0:
            continue

        src_label = trace.get("src_hostname") or trace["src"]
        dst_label = trace.get("dst_hostname") or trace["dst"]
        plural = "s" if n_hops != 1 else ""
        title_lbl = (f"<b>Trace {ti+1}:</b>  {xs(src_label)}  &#8594;  {xs(dst_label)}  "
                     f"<font style='font-size:9px;color:#666;'>({n_hops} hop{plural})</font>")

        total_nodes = 1 + n_hops + 1
        cw = SECT_PAD * 2 + total_nodes * HOP_W + (total_nodes - 1) * HOP_GAP
        ch = SECT_TITLE + SECT_PAD * 2 + HOP_H

        cid = f"tr_cont_{ti}"
        cc = _cell(g, id=cid, value=title_lbl,
                   style=(f"swimlane;startSize={SECT_TITLE};"
                          "fillColor=#f0f4f8;strokeColor=#607d8b;"
                          "fontColor=#37474f;fontSize=10;"
                          "fontStyle=0;rounded=1;arcSize=3;html=1;"),
                   vertex="1", parent="1")
        _geo(cc, x=PAGE_X, y=cy, w=cw, h=ch)

        def hop_node(node_id, col_idx, label, shape, fill, stroke, tooltip=""):
            nx = SECT_PAD + col_idx * (HOP_W + HOP_GAP)
            ny = SECT_TITLE + SECT_PAD
            nc = _cell(g, id=node_id, value=label, tooltip=tooltip,
                       style=(f"{shape}fillColor={fill};strokeColor={stroke};"
                              "verticalLabelPosition=bottom;verticalAlign=top;"
                              "labelPosition=center;align=center;fontSize=9;html=1;"),
                       vertex="1", parent=cid)
            _geo(nc, x=nx, y=ny, w=HOP_W, h=HOP_H)
            return node_id

        def hop_edge(eid, src_id, tgt_id, lbl=""):
            ec = _cell(g, id=eid, value=lbl,
                       style=("endArrow=block;endFill=1;"
                              "strokeColor=#607d8b;strokeWidth=1.5;"
                              "fontSize=8;fontColor=#607d8b;"
                              "rounded=1;html=1;"),
                       edge="1", source=src_id, target=tgt_id,
                       parent=cid)
            import xml.etree.ElementTree as ET
            ET.SubElement(ec, "mxGeometry", relative="1", **{"as": "geometry"})

        origin_id = f"tr{ti}_origin"
        origin_lbl = (f"<b>{xs(src_label)}</b><br/>"
                      f"<font style='font-size:8px;color:#555;'>{xs(trace['src'])}</font>")
        hop_node(origin_id, 0, origin_lbl,
                 "shape=mxgraph.cisco.computers_and_peripherals.pc;",
                 "#fff2cc", "#d6b656", f"Traceroute origin: {xs(trace['src'])}")

        prev_id = origin_id
        for hi, hop in enumerate(hops):
            hop_ip = hop["router_ip"]
            hop_hn = hop.get("hostname", "")
            hop_lbl = (f"<b>Hop {hop['hop_n']}</b><br/>"
                       f"<font style='font-size:8px;'>{xs(hop_hn or hop_ip)}</font><br/>"
                       f"<font style='font-size:7px;color:#888;'>{xs(hop_ip) if hop_hn else ''}</font>")
            nid = f"tr{ti}_hop{hi}"
            is_known = hop_ip in node_id_map
            fill = "#dae8fc" if is_known else "#f5f5f5"
            stroke = "#6c8ebf" if is_known else "#aaaaaa"
            known_note = "\nKnown node in diagram" if is_known else ""
            hop_node(nid, hi + 1, hop_lbl, SHAPE_ROUTER, fill, stroke,
                     tooltip=f"Router hop {hop['hop_n']}: {xs(hop_ip)}{known_note}")
            hop_edge(f"tr{ti}_e{hi}", prev_id, nid)
            prev_id = nid

        dst_id = f"tr{ti}_dst"
        dst_lbl = (f"<b>{xs(dst_label)}</b><br/>"
                   f"<font style='font-size:8px;color:#555;'>{xs(trace['dst'])}</font>")
        hop_node(dst_id, n_hops + 1, dst_lbl,
                 "shape=mxgraph.cisco.storage.cloud;",
                 "#ffe6cc", "#d79b00", f"Trace destination: {xs(trace['dst'])}")
        hop_edge(f"tr{ti}_efinal", prev_id, dst_id, "")

        cy += ch + 16
