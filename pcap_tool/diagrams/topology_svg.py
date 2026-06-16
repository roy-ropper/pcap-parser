"""Dependency-free SVG preview of the red-team traffic topology.

Mirrors drawio_topology.py's layout (subnet zones from graph/layout.py,
plus Wi-Fi and RADIUS/802.1X zones) and edge colour/label conventions, but
emits plain SVG via xml.etree.ElementTree. ElementTree auto-escapes text
content, so hostnames/SSIDs/banners containing "<", "&", etc. render as
literal text rather than markup — this is what makes it safe to embed via
`<img src=...>` in the web dashboard.
"""

import math
import xml.etree.ElementTree as ET

from ..graph.layout import (
    layout, PAGE_X, PAGE_Y, CONT_TITLE, CONT_GAP_Y, CONT_PAD,
    STRIDE_X, STRIDE_Y, NODES_PER_ROW, LABEL_RESERVE,
    SUBNET_PALETTES, ROLE_FILL_STROKE, FLAG_FILL_STROKE, NODE_W, NODE_H,
)

DEVICE_FILL_STROKE = {
    "server":         ROLE_FILL_STROKE["server"],
    "workstation":    ROLE_FILL_STROKE["host"],
    "client":         ROLE_FILL_STROKE["client"],
    "external":       ROLE_FILL_STROKE["external"],
    "network_device": ("#e1d5e7", "#9673a6"),
    "ap":             ("#cce5ff", "#4a86c8"),
    "unknown":        ("#f5f5f5", "#999999"),
}

EDGE_TAG_PRIORITY = [
    "cleartext_creds", "exfiltration", "lateral_movement", "beaconing",
    "dns_tunneling", "icmp_tunneling", "deauth", "snmp_cleartext",
    "unusual_outbound", "cleartext", "radius_eap_tls", "ssh", "wifi_assoc",
]

# Only these tags earn a visible label — everything else just gets colour.
_LABEL_TAGS = {
    "cleartext_creds", "exfiltration", "lateral_movement",
    "dns_tunneling", "beaconing", "icmp_tunneling", "deauth",
}

# Fixed palette so we can predeclare one arrowhead <marker> per colour.
_ARROW_COLORS = ["#b85450", "#d79b00", "#9673a6", "#00695c", "#6c8ebf", "#cccccc", "#999999"]

_LEGEND_ROWS = [
    ("#b85450", "Cleartext / creds / exfil"),
    ("#d79b00", "Lateral movement"),
    ("#9673a6", "DNS tunneling"),
    ("#00695c", "RADIUS / EAP-TLS"),
    ("#6c8ebf", "SSH"),
    ("#999999", "Top talker (by volume)"),
]


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


def _edge_style(e, max_bytes):
    """Returns (color, stroke_width, dasharray_or_None, label_or_None).

    Labels are only emitted for high-signal tags (_LABEL_TAGS).  Routine
    cleartext/SSH/top-talker edges are coloured but unlabelled so the canvas
    stays readable — colour conveys the risk category without text clutter.
    """
    proto = e.protocols[0] if e.protocols else ""

    for tag in EDGE_TAG_PRIORITY:
        if tag not in e.tags:
            continue
        if tag == "cleartext_creds":
            return "#b85450", 2.5, None, f"⚠ Creds: {proto}"
        if tag == "exfiltration":
            return "#b85450", _log_width(e.bytes, max_bytes, 2, 5), None, "Exfil"
        if tag == "lateral_movement":
            return "#d79b00", 2, None, f"Lateral: {proto}"
        if tag == "beaconing":
            return "#b85450", 1.5, "4,4", "Beaconing"
        if tag == "dns_tunneling":
            domain = _note_value(e.notes, "DNS tunneling suspected")
            return "#9673a6", 2, "3,3", (f"DNS tunnel: {domain[:20]}" if domain else "DNS tunnel?")
        if tag == "icmp_tunneling":
            return "#b85450", 1.5, "5,3", "ICMP tunnel?"
        if tag == "deauth":
            return "#b85450", 1.5, None, "Deauth"
        if tag == "snmp_cleartext":
            return "#d79b00", 1.5, None, None
        if tag == "unusual_outbound":
            return "#b85450", 1.5, None, None
        if tag == "cleartext":
            return "#b85450", 1.5, None, None   # colour only — no label
        if tag == "radius_eap_tls":
            return "#00695c", 1.5, "2,2", None
        if tag == "ssh":
            return "#6c8ebf", 1.5, None, None
        if tag == "wifi_assoc":
            return "#cccccc", 1, None, None

    return "#999999", _log_width(e.bytes, max_bytes, 1, 3), None, None


def _node_label_lines(tn):
    lines = []
    if tn.kind == "host":
        primary = tn.hostname or tn.ip or tn.id
        lines.append((primary, "bold", "#222222"))
        if tn.hostname:
            lines.append((tn.ip or "", "normal", "#555555"))
        lines.append((f"OS: {tn.os_guess or 'Unknown'}", "normal", "#888888"))
    elif tn.kind == "ap":
        lines.append((tn.extra.get("ssid") or "(hidden SSID)", "bold", "#222222"))
        lines.append((tn.mac or "", "normal", "#555555"))
        lines.append((f"{tn.extra.get('enc', 'Open')} · ch{tn.extra.get('channel', 0)}", "normal", "#888888"))
        if tn.extra.get("wps"):
            lines.append(("⚠ WPS", "normal", "#b85450"))
    elif tn.kind == "wifi_client":
        lines.append((tn.mac or "", "bold", "#222222"))
        probed = tn.extra.get("probed_ssids") or []
        if probed:
            lines.append((f"probing: {', '.join(probed[:2])}", "normal", "#888888"))
    elif tn.kind == "eap_tls_peer":
        lines.append((tn.mac or "", "bold", "#222222"))
        lines.append((tn.device_category, "normal", "#888888"))
    else:
        lines.append((tn.id, "bold", "#222222"))

    if tn.is_capture_device:
        lines.append(("\U0001f4e1 Capture host", "normal", "#b8860b"))

    return lines


def _text(parent, x, y, text, **attrs):
    t = ET.SubElement(parent, "text", {"x": str(x), "y": str(y), "font-family": "sans-serif", **attrs})
    t.text = text
    return t


def _text_block(svg, lines, cx, start_y, line_height=12):
    for i, (text, weight, color) in enumerate(lines):
        _text(svg, cx, start_y + i * line_height, text,
              **{"text-anchor": "middle", "font-size": "10", "font-weight": weight, "fill": color})


def _draw_node(svg, tn, x, y):
    fill, stroke = DEVICE_FILL_STROKE.get(tn.device_category, DEVICE_FILL_STROKE["unknown"])
    if tn.max_severity in ("HIGH", "CRITICAL"):
        fill, stroke = FLAG_FILL_STROKE
    stroke_width = "1.5"
    if tn.is_capture_device:
        stroke = "#DAA520"
        stroke_width = "3"
    shape = "ellipse" if tn.device_category in ("ap", "external") else "rect"
    if shape == "rect":
        ET.SubElement(svg, "rect", {
            "x": str(x), "y": str(y), "width": str(NODE_W), "height": str(NODE_H),
            "rx": "6", "fill": fill, "stroke": stroke, "stroke-width": stroke_width,
        })
    else:
        ET.SubElement(svg, "ellipse", {
            "cx": str(x + NODE_W / 2), "cy": str(y + NODE_H / 2),
            "rx": str(NODE_W / 2), "ry": str(NODE_H / 2),
            "fill": fill, "stroke": stroke, "stroke-width": stroke_width,
        })
    _text_block(svg, _node_label_lines(tn), x + NODE_W / 2, y + NODE_H + 14)


def _draw_zone(svg, title, fill, stroke, node_ids, topology, start_x, start_y, node_pos_map, cols=NODES_PER_ROW):
    n = len(node_ids)
    if n == 0:
        return start_y, start_x
    ncols = min(n, cols)
    nrows = math.ceil(n / cols)
    cw = ncols * STRIDE_X + CONT_PAD * 2
    ch = nrows * STRIDE_Y + CONT_PAD * 2 + CONT_TITLE

    ET.SubElement(svg, "rect", {
        "x": str(start_x), "y": str(start_y), "width": str(cw), "height": str(ch),
        "rx": "6", "fill": fill, "stroke": stroke, "fill-opacity": "0.5",
    })
    _text(svg, start_x + 10, start_y + 20, title,
          **{"font-size": "12", "font-weight": "bold", "fill": stroke})

    for i, topo_id in enumerate(node_ids):
        r, c = divmod(i, cols)
        x = start_x + CONT_PAD + c * STRIDE_X
        y = start_y + CONT_TITLE + CONT_PAD + r * STRIDE_Y
        _draw_node(svg, topology.nodes[topo_id], x, y)
        node_pos_map[topo_id] = (x + NODE_W / 2, y + NODE_H / 2)

    return start_y + ch, start_x + cw


def _add_defs(svg):
    defs = ET.SubElement(svg, "defs")
    for color in _ARROW_COLORS:
        marker = ET.SubElement(defs, "marker", {
            "id": f"arrow-{color.lstrip('#')}", "viewBox": "0 0 10 10",
            "refX": "8", "refY": "5", "markerWidth": "6", "markerHeight": "6",
            "orient": "auto-start-reverse",
        })
        ET.SubElement(marker, "path", {"d": "M 0 0 L 10 5 L 0 10 z", "fill": color})


def _add_capture_box(svg, topology, width):
    cd = topology.capture_device or {}
    if cd.get("confidence") == "unknown" or not cd.get("mac"):
        line1 = "Capture device: unknown"
        line2 = cd.get("note", "")
    else:
        ident = cd.get("hostname") or cd.get("ip") or cd.get("mac")
        line1 = f"Capture device: {ident}"
        line2 = f"{cd.get('mac', '')}  (confidence: {cd.get('confidence', '')})"

    bx = width - 340
    ET.SubElement(svg, "rect", {
        "x": str(bx), "y": "12", "width": "320", "height": "40",
        "rx": "6", "fill": "#fffbe6", "stroke": "#d6b656",
    })
    _text(svg, bx + 10, 28, line1, **{"font-size": "11", "font-weight": "bold", "fill": "#333333"})
    _text(svg, bx + 10, 42, line2, **{"font-size": "9", "fill": "#888888"})


def _add_legend(svg):
    x, y = 20, 60
    height = len(_LEGEND_ROWS) * 18 + 24
    ET.SubElement(svg, "rect", {
        "x": str(x - 8), "y": str(y - 20), "width": "220", "height": str(height),
        "rx": "6", "fill": "#f5f5f5", "stroke": "#666666",
    })
    _text(svg, x, y - 4, "Legend", **{"font-size": "11", "font-weight": "bold", "fill": "#333333"})
    for i, (color, label) in enumerate(_LEGEND_ROWS):
        ly = y + i * 18 + 12
        ET.SubElement(svg, "line", {
            "x1": str(x), "y1": str(ly), "x2": str(x + 24), "y2": str(ly),
            "stroke": color, "stroke-width": "3",
        })
        _text(svg, x + 32, ly + 4, label, **{"font-size": "10", "fill": "#333333"})


def generate_topology_svg(topology, render, title="Network Diagram"):
    host_nodes = {
        tn.id: {"subnet": tn.subnet or "external", "role": tn.role or "client"}
        for tn in topology.nodes.values() if tn.kind == "host"
    }
    node_pos, containers = layout(host_nodes)

    max_x = max((c["x"] + c["w"] for c in containers), default=PAGE_X + 400)
    max_y = max((c["y"] + c["h"] for c in containers), default=PAGE_Y + 200) if containers else PAGE_Y + 200

    node_pos_map = {}
    for tn_id, (ax, ay) in node_pos.items():
        node_pos_map[tn_id] = (ax + NODE_W / 2, ay + NODE_H / 2)

    cy = max_y + CONT_GAP_Y

    wifi_ids = [tn.id for tn in topology.nodes.values() if tn.kind in ("ap", "wifi_client")]
    eap_ids = [tn.id for tn in topology.nodes.values() if tn.kind == "eap_tls_peer"]

    # Pre-compute zone extents so we know the overall canvas size before
    # drawing anything (ElementTree elements must be added in document order).
    zone_specs = []
    for ids in (wifi_ids, eap_ids):
        if not ids:
            continue
        n = len(ids)
        ncols = min(n, NODES_PER_ROW)
        nrows = math.ceil(n / NODES_PER_ROW)
        cw = ncols * STRIDE_X + CONT_PAD * 2
        ch = nrows * STRIDE_Y + CONT_PAD * 2 + CONT_TITLE
        zone_specs.append((ids, cy, cw, ch))
        max_x = max(max_x, PAGE_X + cw)
        cy += ch + CONT_GAP_Y

    width = int(max(max_x, 1654)) + 40
    height = int(cy) + 40

    svg = ET.Element("svg", {
        "xmlns": "http://www.w3.org/2000/svg",
        "viewBox": f"0 0 {width} {height}",
        "width": str(width), "height": str(height),
    })
    ET.SubElement(svg, "rect", {"x": "0", "y": "0", "width": str(width), "height": str(height), "fill": "#ffffff"})
    _add_defs(svg)

    _text(svg, width / 2, 30, title, **{"text-anchor": "middle", "font-size": "20", "font-weight": "bold", "fill": "#222222"})

    _add_legend(svg)
    _add_capture_box(svg, topology, width)

    # Subnet containers + host nodes.
    for cont in containers:
        if cont["subnet"] == "external":
            fill, stroke, label = "#fff3e0", "#e65100", "External / Internet"
        else:
            fill, stroke = SUBNET_PALETTES[cont["palette_idx"] % len(SUBNET_PALETTES)]
            label = f"Subnet: {cont['subnet']}"
        ET.SubElement(svg, "rect", {
            "x": str(cont["x"]), "y": str(cont["y"]), "width": str(cont["w"]), "height": str(cont["h"]),
            "rx": "6", "fill": fill, "stroke": stroke, "fill-opacity": "0.5",
        })
        _text(svg, cont["x"] + 10, cont["y"] + 20, label, **{"font-size": "12", "font-weight": "bold", "fill": stroke})

    for tn_id, (ax, ay) in node_pos.items():
        _draw_node(svg, topology.nodes[tn_id], ax, ay)

    # Wi-Fi / RADIUS zones.
    zone_titles = {0: ("\U0001f4f6 Wi-Fi", "#e3f2fd", "#1565c0"),
                   1: ("\U0001f512 RADIUS / 802.1X", "#e0f2f1", "#00695c")}
    for zi, (ids, zy, cw, ch) in enumerate(zone_specs):
        zt, zfill, zstroke = zone_titles.get(zi, ("Zone", "#eeeeee", "#999999"))
        _draw_zone(svg, zt, zfill, zstroke, ids, topology, PAGE_X, zy, node_pos_map)

    # Traffic edges — bundle parallel (src→dst) pairs so only one line is
    # drawn per node pair, picking the highest-priority edge for each pair.
    _tag_rank = {t: i for i, t in enumerate(EDGE_TAG_PRIORITY)}

    def _pair_rank(e):
        return min((_tag_rank.get(t, 99) for t in e.tags), default=99)

    bundled = {}
    for e in render.edges:
        key = (e.src, e.dst)
        if key not in bundled or _pair_rank(e) < _pair_rank(bundled[key]):
            bundled[key] = e

    max_bytes = max((e.bytes for e in bundled.values()), default=1) or 1
    labels_drawn = set()   # avoid duplicate labels at the same midpoint
    labels_budget = 6      # max edge labels on the whole diagram

    # Draw highest-priority edges first so the label budget goes to the worst findings.
    draw_order = sorted(bundled.values(), key=_pair_rank)

    for e in draw_order:
        p1 = node_pos_map.get(e.src)
        p2 = node_pos_map.get(e.dst)
        if not p1 or not p2:
            continue
        color, w, dash, label = _edge_style(e, max_bytes)
        attrs = {
            "x1": str(p1[0]), "y1": str(p1[1]), "x2": str(p2[0]), "y2": str(p2[1]),
            "stroke": color, "stroke-width": f"{w:.1f}", "stroke-opacity": "0.75",
        }
        if dash:
            attrs["stroke-dasharray"] = dash
        if "wifi_assoc" not in e.tags:
            attrs["marker-end"] = f"url(#arrow-{color.lstrip('#')})"
        ET.SubElement(svg, "line", attrs)

        if label and labels_budget > 0:
            mx = round((p1[0] + p2[0]) / 2)
            my = round((p1[1] + p2[1]) / 2)
            # Skip if a label was already placed very close to this midpoint
            slot = (mx // 40, my // 30)
            if slot not in labels_drawn:
                labels_drawn.add(slot)
                labels_budget -= 1
                pad_x = len(label) * 3 + 5
                ET.SubElement(svg, "rect", {
                    "x": str(mx - pad_x), "y": str(my - 9),
                    "width": str(pad_x * 2), "height": "14",
                    "fill": "#ffffff", "fill-opacity": "0.9", "rx": "2",
                })
                _text(svg, mx, my + 3, label,
                      **{"text-anchor": "middle", "font-size": "9", "fill": color})

    # "+N more" node summaries for collapsed low-value traffic.
    for node_id, summary in render.node_summaries.items():
        pos = node_pos_map.get(node_id)
        if not pos:
            continue
        cx, cny = pos
        _text(svg, cx, cny + NODE_H / 2 + LABEL_RESERVE - 6, summary,
              **{"text-anchor": "middle", "font-size": "8", "fill": "#888888"})

    return '<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(svg, encoding="unicode")
