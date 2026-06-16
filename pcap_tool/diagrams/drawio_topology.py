"""Red-team traffic-topology draw.io diagram generator.

Consumes a `TopologyModel` (pcap_tool.topology.model) and a `RenderResult`
(pcap_tool.topology.render_policy) and emits a draw.io/mxgraph XML document
with subnet zones, a Wi-Fi zone, a RADIUS/802.1X zone, traffic edges coloured
and labelled by red-team relevance, a capture-device box, and a legend.
Supersedes drawio_l3.py.
"""

import math
import xml.etree.ElementTree as ET
from xml.dom import minidom

from ._xml_helpers import _cell, _geo
from ._drawio_common import xs, _illegal_xml, draw_subnet_containers, draw_traceroute_section
from ..graph.layout import (
    layout, PAGE_X, PAGE_Y, CONT_TITLE, CONT_GAP_Y, CONT_PAD,
    STRIDE_X, STRIDE_Y, NODES_PER_ROW, LABEL_RESERVE,
    SHAPE_SERVER, SHAPE_PC, SHAPE_CLOUD, SHAPE_ROUTER, SHAPE_AP,
    ROLE_FILL_STROKE, FLAG_FILL_STROKE, NODE_W, NODE_H, LEGEND_W,
)

# ─────────────────────────────────────────────────────────────────────────────
# Device category -> shape / colour
# ─────────────────────────────────────────────────────────────────────────────

DEVICE_FILL_STROKE = {
    "server":         ROLE_FILL_STROKE["server"],
    "workstation":    ROLE_FILL_STROKE["host"],
    "client":         ROLE_FILL_STROKE["client"],
    "external":       ROLE_FILL_STROKE["external"],
    "network_device": ("#e1d5e7", "#9673a6"),
    "ap":             ("#cce5ff", "#4a86c8"),
    "unknown":        ("#f5f5f5", "#999999"),
}

DEVICE_SHAPE = {
    "server":         SHAPE_SERVER,
    "workstation":    SHAPE_PC,
    "client":         SHAPE_PC,
    "external":       SHAPE_CLOUD,
    "network_device": SHAPE_ROUTER,
    "ap":             SHAPE_AP,
    "unknown":        SHAPE_PC,
}

# Order in which an edge's tags are checked when picking its style/label —
# earlier entries win when an edge carries more than one tag.
EDGE_TAG_PRIORITY = [
    "cleartext_creds", "cleartext", "lateral_movement", "beaconing",
    "dns_tunneling", "exfiltration", "unusual_outbound", "icmp_tunneling",
    "snmp_cleartext", "deauth", "radius_eap_tls", "ssh", "wifi_assoc",
]

_EDGE_BASE = ("endArrow=block;endFill=1;rounded=1;html=1;"
              "labelBackgroundColor=#ffffff;fontSize=9;")


def _log_width(num_bytes, max_bytes, min_w=1.0, max_w=6.0):
    if num_bytes <= 0 or max_bytes <= 0:
        return min_w
    t = math.log(num_bytes + 1) / math.log(max_bytes + 1)
    return min_w + t * (max_w - min_w)


def _note_value(notes, prefix):
    for n in notes:
        if n.startswith(prefix):
            return n.split(":", 1)[1].strip()
    return ""


def _edge_style_and_label(e, max_bytes):
    primary_proto = e.protocols[0] if e.protocols else ""

    for tag in EDGE_TAG_PRIORITY:
        if tag not in e.tags:
            continue
        if tag == "cleartext_creds":
            return (_EDGE_BASE + "strokeColor=#b85450;strokeWidth=3;fontColor=#b85450;",
                    f"&#9888; Cleartext creds: {xs(primary_proto)}")
        if tag == "cleartext":
            return (_EDGE_BASE + "strokeColor=#b85450;strokeWidth=3;fontColor=#b85450;",
                    f"&#9888; Cleartext: {xs(primary_proto)}")
        if tag == "lateral_movement":
            return (_EDGE_BASE + "strokeColor=#d79b00;strokeWidth=2.5;fontColor=#d79b00;",
                    f"Lateral: {xs(primary_proto)}")
        if tag == "beaconing":
            return (_EDGE_BASE + "strokeColor=#b85450;strokeWidth=2;"
                                  "dashed=1;dashPattern=4 4;fontColor=#b85450;",
                    "&#128257; Beaconing")
        if tag == "dns_tunneling":
            domain = _note_value(e.notes, "DNS tunneling suspected")
            label = f"DNS tunneling: {xs(domain)}" if domain else "DNS tunneling?"
            return (_EDGE_BASE + "strokeColor=#9673a6;strokeWidth=2;"
                                  "dashed=1;dashPattern=3 3;fontColor=#9673a6;",
                    label)
        if tag == "exfiltration":
            w = _log_width(e.bytes, max_bytes, 2, 6)
            return (_EDGE_BASE + f"strokeColor=#b85450;strokeWidth={w:.1f};fontColor=#b85450;",
                    "&#11014; Exfiltration")
        if tag == "unusual_outbound":
            w = _log_width(e.bytes, max_bytes, 2, 6)
            return (_EDGE_BASE + f"strokeColor=#b85450;strokeWidth={w:.1f};fontColor=#b85450;",
                    "&#11014; Unusual outbound")
        if tag == "icmp_tunneling":
            return (_EDGE_BASE + "strokeColor=#b85450;strokeWidth=2;dashed=1;fontColor=#b85450;",
                    "ICMP tunneling?")
        if tag == "snmp_cleartext":
            return (_EDGE_BASE + "strokeColor=#d79b00;strokeWidth=2;fontColor=#d79b00;",
                    "SNMP (cleartext)")
        if tag == "deauth":
            return (_EDGE_BASE + "strokeColor=#b85450;strokeWidth=2;fontColor=#b85450;",
                    "&#9888; Deauth/disassoc")
        if tag == "radius_eap_tls":
            return (_EDGE_BASE + "strokeColor=#00695c;strokeWidth=1.5;"
                                  "dashed=1;dashPattern=2 2;fontColor=#00695c;",
                    "RADIUS / EAP-TLS")
        if tag == "ssh":
            return (_EDGE_BASE + "strokeColor=#6c8ebf;strokeWidth=1.5;fontColor=#6c8ebf;",
                    "SSH")
        if tag == "wifi_assoc":
            ssid = _note_value(e.notes, "SSID")
            return ("endArrow=none;startArrow=none;strokeColor=#cccccc;strokeWidth=1;"
                    "rounded=1;html=1;labelBackgroundColor=#ffffff;fontSize=9;"
                    "fontColor=#888888;",
                    xs(ssid))

    # Default: an unflagged "top talker" edge, width scaled by traffic volume.
    w = _log_width(e.bytes, max_bytes, 1, 4)
    return (_EDGE_BASE + f"strokeColor=#999999;strokeWidth={w:.1f};fontColor=#999999;",
            xs(primary_proto) if primary_proto else "")


# ─────────────────────────────────────────────────────────────────────────────
# Node rendering
# ─────────────────────────────────────────────────────────────────────────────

def _node_label(tn):
    lines = []
    if tn.kind == "host":
        primary = tn.hostname or tn.ip or tn.id
        lines.append(f"<b>{xs(primary)}</b>")
        if tn.hostname:
            lines.append(f"<font style='font-size:9px;'>{xs(tn.ip)}</font>")
        lines.append(f"<font style='font-size:8px;color:#666;'>OS: {xs(tn.os_guess or 'Unknown')}</font>")
    elif tn.kind == "ap":
        ssid = tn.extra.get("ssid") or "(hidden SSID)"
        enc = tn.extra.get("enc", "Open")
        ch = tn.extra.get("channel", 0)
        lines.append(f"<b>{xs(ssid)}</b>")
        lines.append(f"<font style='font-size:8px;color:#444;'>{xs(tn.mac)}</font>")
        lines.append(f"<font style='font-size:8px;color:#666;'>{xs(enc)} &middot; ch{xs(ch)}</font>")
        if tn.extra.get("wps"):
            lines.append("<font style='font-size:8px;color:#b85450;'>&#9888; WPS</font>")
    elif tn.kind == "wifi_client":
        lines.append(f"<b>{xs(tn.mac)}</b>")
        probed = tn.extra.get("probed_ssids") or []
        if probed:
            lines.append(f"<font style='font-size:8px;color:#666;'>probing: {xs(', '.join(probed[:2]))}</font>")
    elif tn.kind == "eap_tls_peer":
        lines.append(f"<b>{xs(tn.mac)}</b>")
        lines.append(f"<font style='font-size:8px;color:#666;'>{xs(tn.device_category)}</font>")
    else:
        lines.append(f"<b>{xs(tn.id)}</b>")

    if tn.is_capture_device:
        lines.append("<font style='font-size:8px;color:#b8860b;'>&#128225; Capture host</font>")

    return "<br/>".join(lines)


def _node_tooltip(tn):
    parts = []
    if tn.protocols:
        parts.append(f"Protocols: {', '.join(tn.protocols)}")
    if tn.open_ports:
        parts.append(f"Open ports (passive): {', '.join(str(p) for p in tn.open_ports)}")
    if tn.count:
        parts.append(f"Pkts: {tn.count:,}  Bytes: {tn.bytes:,}")
    if tn.is_gateway:
        parts.append("Gateway / router")
    if tn.max_severity:
        parts.append(f"&#9888; Max finding severity: {tn.max_severity}")
    return "\n".join(parts)


def _draw_node(g, nid, parent, rx, ry, tn):
    fill, stroke = DEVICE_FILL_STROKE.get(tn.device_category, DEVICE_FILL_STROKE["unknown"])
    shape = DEVICE_SHAPE.get(tn.device_category, SHAPE_PC)
    extra = ""
    if tn.device_category == "unknown":
        extra += "dashed=1;"
    if tn.max_severity in ("HIGH", "CRITICAL"):
        fill, stroke = FLAG_FILL_STROKE
    if tn.is_capture_device:
        stroke = "#DAA520"
        extra += "strokeWidth=3;"

    nc = _cell(g, id=nid, value=_node_label(tn), tooltip=_node_tooltip(tn),
               style=(f"{shape}fillColor={fill};strokeColor={stroke};{extra}"
                      "verticalLabelPosition=bottom;verticalAlign=top;"
                      "labelPosition=center;align=center;"
                      "labelBackgroundColor=none;labelBorderColor=none;"
                      "fontSize=9;whiteSpace=wrap;html=1;"),
               vertex="1", parent=parent)
    _geo(nc, x=rx, y=ry, w=NODE_W, h=NODE_H)


def _draw_zone(g, zone_id, title_html, fill, stroke, node_ids, topology, start_x, start_y, cols=NODES_PER_ROW):
    """Lay out a list of TopoNode ids in a grid inside a swimlane container.

    Returns ({node_id: cell_id}, (x, y, w, h)) — the latter is the container's
    bounding box, used to advance the layout cursor for the next zone.
    """
    n = len(node_ids)
    if n == 0:
        return {}, (start_x, start_y, 0, 0)

    ncols = min(n, cols)
    nrows = math.ceil(n / cols)
    cw = ncols * STRIDE_X + CONT_PAD * 2
    ch = nrows * STRIDE_Y + CONT_PAD * 2 + CONT_TITLE

    cc = _cell(g, id=zone_id, value=title_html,
               style=(f"swimlane;startSize={CONT_TITLE};fillColor={fill};"
                      f"strokeColor={stroke};fontColor={stroke};fontSize=11;"
                      "fontStyle=1;rounded=1;arcSize=3;swimlaneLine=1;"
                      "align=left;spacingLeft=8;html=1;"),
               vertex="1", parent="1")
    _geo(cc, x=start_x, y=start_y, w=cw, h=ch)

    cell_ids = {}
    abs_pos = {}
    for i, topo_id in enumerate(node_ids):
        r, c = divmod(i, cols)
        rx = CONT_PAD + c * STRIDE_X
        ry = CONT_TITLE + CONT_PAD + r * STRIDE_Y
        cell_id = f"{zone_id}_{i}"
        cell_ids[topo_id] = cell_id
        abs_pos[topo_id] = (start_x + rx, start_y + ry)
        _draw_node(g, cell_id, zone_id, rx, ry, topology.nodes[topo_id])

    return cell_ids, (start_x, start_y, cw, ch), abs_pos


# ─────────────────────────────────────────────────────────────────────────────
# Capture-device box & legend
# ─────────────────────────────────────────────────────────────────────────────

def _add_capture_box(g, topology):
    cd = topology.capture_device or {}
    if cd.get("confidence") == "unknown" or not cd.get("mac"):
        text = (f"&#128225; <b>Capture device:</b> unknown<br/>"
                f"<font style='font-size:9px;color:#888;'>{xs(cd.get('note',''))}</font>")
    else:
        ident = cd.get("hostname") or cd.get("ip") or cd.get("mac")
        text = (f"&#128225; <b>Capture device:</b> {xs(ident)}<br/>"
                f"<font style='font-size:9px;color:#888;'>{xs(cd.get('mac',''))} "
                f"&middot; confidence: {xs(cd.get('confidence',''))}</font>")

    box = _cell(g, id="capture_box", value=text,
                 style=("rounded=1;html=1;fillColor=#fffbe6;strokeColor=#d6b656;"
                        "align=left;verticalAlign=middle;spacingLeft=8;fontSize=10;"
                        "whiteSpace=wrap;"),
                 vertex="1", parent="1")
    _geo(box, x=PAGE_X + 920, y=22, w=320, h=42)


def _add_legend(g, topology):
    device_rows = [
        ("server", "Server"),
        ("workstation", "Workstation"),
        ("client", "Client"),
        ("network_device", "Network device / Gateway"),
        ("external", "External"),
        ("ap", "Access Point"),
        ("unknown", "Unknown"),
    ]
    edge_rows = [
        ("#b85450", "Cleartext / creds / exfil"),
        ("#d79b00", "Lateral movement"),
        ("#9673a6", "DNS tunneling"),
        ("#00695c", "RADIUS / EAP-TLS"),
        ("#6c8ebf", "SSH"),
        ("#999999", "Top talker (by volume)"),
    ]
    height = 30 + len(device_rows) * 22 + 14 + len(edge_rows) * 18 + 14

    bg = _cell(g, id="legend_bg", value="<b>Legend</b>",
               style=("rounded=1;html=1;fillColor=#f5f5f5;strokeColor=#666;"
                      "fontColor=#333;align=center;verticalAlign=top;"
                      "spacingTop=6;fontSize=11;"),
               vertex="1", parent="1")
    _geo(bg, x=20, y=100, w=LEGEND_W, h=height)

    y = 130
    for di, (cat, lbl) in enumerate(device_rows):
        fill, stroke = DEVICE_FILL_STROKE.get(cat, DEVICE_FILL_STROKE["unknown"])
        shape = DEVICE_SHAPE.get(cat, SHAPE_PC)
        rs = _cell(g, id=f"dleg{di}", value="",
                   style=f"{shape}fillColor={fill};strokeColor={stroke};",
                   vertex="1", parent="1")
        _geo(rs, x=28, y=y, w=20, h=20)
        rl = _cell(g, id=f"dlegl{di}", value=xs(lbl),
                   style="text;html=1;strokeColor=none;fillColor=none;"
                         "align=left;verticalAlign=middle;fontSize=10;",
                   vertex="1", parent="1")
        _geo(rl, x=54, y=y, w=148, h=20)
        y += 22

    y += 8
    for ei, (color, lbl) in enumerate(edge_rows):
        ln = _cell(g, id=f"eleg{ei}", value="",
                   style=f"endArrow=none;strokeColor={color};strokeWidth=2;html=1;",
                   edge="1", parent="1")
        eg = ET.SubElement(ln, "mxGeometry", relative="1", **{"as": "geometry"})
        ET.SubElement(eg, "mxPoint", x="28", y=str(y + 9), **{"as": "sourcePoint"})
        ET.SubElement(eg, "mxPoint", x="48", y=str(y + 9), **{"as": "targetPoint"})
        el = _cell(g, id=f"elegl{ei}", value=xs(lbl),
                   style="text;html=1;strokeColor=none;fillColor=none;"
                         "align=left;verticalAlign=middle;fontSize=10;",
                   vertex="1", parent="1")
        _geo(el, x=54, y=y, w=148, h=18)
        y += 18


# ─────────────────────────────────────────────────────────────────────────────
# Main generator
# ─────────────────────────────────────────────────────────────────────────────

def generate_topology_drawio(topology, render, title="Network Diagram"):
    host_nodes = {
        tn.id: {"subnet": tn.subnet or "external", "role": tn.role or "client"}
        for tn in topology.nodes.values() if tn.kind == "host"
    }
    node_pos, containers = layout(host_nodes)
    max_y = max((c["y"] + c["h"] for c in containers), default=PAGE_Y) if containers else PAGE_Y

    root = ET.Element("mxGraphModel",
        dx="1422", dy="762", grid="1", gridSize="10", guides="1",
        tooltips="1", connect="1", arrows="1", fold="1", page="1",
        pageScale="1", pageWidth="1654", pageHeight="1169",
        math="0", shadow="0")
    g = ET.SubElement(root, "root")
    ET.SubElement(g, "mxCell", id="0")
    ET.SubElement(g, "mxCell", id="1", parent="0")

    tc = _cell(g, id="title", value=f"<b>{xs(title)}</b>",
               style="text;html=1;strokeColor=none;fillColor=none;"
                     "align=center;verticalAlign=middle;whiteSpace=wrap;"
                     "rounded=0;fontSize=20;",
               vertex="1", parent="1")
    _geo(tc, x=PAGE_X, y=22, w=900, h=42)

    _add_legend(g, topology)
    _add_capture_box(g, topology)

    cont_ids = draw_subnet_containers(g, containers)

    cell_ids = {}
    abs_pos = {}
    for tn_id, (ax, ay) in node_pos.items():
        tn = topology.nodes[tn_id]
        sub = tn.subnet or "external"
        cont = next(c for c in containers if c["subnet"] == sub)
        rx, ry = ax - cont["x"], ay - cont["y"]
        nid = f"n{len(cell_ids)}"
        cell_ids[tn_id] = nid
        abs_pos[tn_id] = (ax, ay)
        _draw_node(g, nid, cont_ids[sub], rx, ry, tn)

    cy = max_y + CONT_GAP_Y

    # Wi-Fi zone: APs + their associated/seen clients.
    wifi_ids = [tn.id for tn in topology.nodes.values() if tn.kind in ("ap", "wifi_client")]
    if wifi_ids:
        zone_cells, (zx, zy, zw, zh), zone_pos = _draw_zone(
            g, "wifi_zone", "<b>&#128246; Wi-Fi</b>", "#e3f2fd", "#1565c0",
            wifi_ids, topology, PAGE_X, cy)
        cell_ids.update(zone_cells)
        abs_pos.update(zone_pos)
        cy = zy + zh + CONT_GAP_Y

    # RADIUS / 802.1X zone: EAP-TLS supplicant/authenticator peers.
    eap_ids = [tn.id for tn in topology.nodes.values() if tn.kind == "eap_tls_peer"]
    if eap_ids:
        zone_cells, (zx, zy, zw, zh), zone_pos = _draw_zone(
            g, "radius_zone", "<b>&#128272; RADIUS / 802.1X</b>", "#e0f2f1", "#00695c",
            eap_ids, topology, PAGE_X, cy)
        cell_ids.update(zone_cells)
        abs_pos.update(zone_pos)
        cy = zy + zh + CONT_GAP_Y

    # Traffic edges.
    max_bytes = max((e.bytes for e in render.edges), default=1) or 1
    for ei, e in enumerate(render.edges):
        src_id = cell_ids.get(e.src)
        dst_id = cell_ids.get(e.dst)
        if not src_id or not dst_id:
            continue
        style, label = _edge_style_and_label(e, max_bytes)
        tooltip = "\n".join(e.notes) if e.notes else ""
        ec = _cell(g, id=f"e{ei}", value=label, tooltip=tooltip, style=style,
                   edge="1", source=src_id, target=dst_id, parent="1")
        ET.SubElement(ec, "mxGeometry", relative="1", **{"as": "geometry"})

    # "+N more" node summaries for collapsed low-value traffic.
    for node_id, summary in render.node_summaries.items():
        pos = abs_pos.get(node_id)
        cell_id = cell_ids.get(node_id)
        if not pos or not cell_id:
            continue
        ax, ay = pos
        sc = _cell(g, id=f"sum_{cell_id}", value=xs(summary),
                   style="text;html=1;strokeColor=none;fillColor=none;"
                         "align=center;verticalAlign=top;fontSize=8;"
                         "fontColor=#888888;whiteSpace=wrap;",
                   vertex="1", parent="1")
        _geo(sc, x=ax - 20, y=ay + NODE_H + LABEL_RESERVE - 16, w=NODE_W + 40, h=14)

    if getattr(topology, "traceroutes", None):
        draw_traceroute_section(g, topology.traceroutes, cell_ids, cy)

    raw_xml = ET.tostring(root, encoding="unicode")
    raw_xml = raw_xml.translate(_illegal_xml)
    return minidom.parseString(raw_xml).toprettyxml(indent="  ")
