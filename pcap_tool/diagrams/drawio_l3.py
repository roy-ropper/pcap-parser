"""Layer-3 network topology draw.io diagram generator."""

import xml.etree.ElementTree as ET
from xml.dom import minidom
from collections import defaultdict

from ._xml_helpers import _cell, _geo
from ..graph.layout import (
    layout, PAGE_X, PAGE_Y, SUBNET_PALETTES, CONT_TITLE,
    SHAPE_SERVER, SHAPE_PC, SHAPE_CLOUD,
    ROLE_FILL_STROKE, FLAG_FILL_STROKE, NODE_W, NODE_H, LEGEND_W,
)

# ─────────────────────────────────────────────────────────────────────────────
# draw.io generator
# ─────────────────────────────────────────────────────────────────────────────

def generate_drawio(nodes, findings, gateways, traceroutes, title="Network Diagram"):
    """
    Host inventory diagram with:
      - Gateway lines (thin grey, gateways only)
      - Traceroute section below main diagram
    """
    node_pos, containers = layout(nodes)
    # Work out how tall the main diagram area is so we can place traceroute below
    max_y = max((c["y"] + c["h"] for c in containers), default=PAGE_Y) if containers else PAGE_Y

    # Build finding set for quick lookup
    flagged_ips = set()
    for f in findings:
        if f["severity"] in ("HIGH","CRITICAL"):
            flagged_ips.add(f["src"])
            if f["dst"] != "N/A": flagged_ips.add(f["dst"])

    root = ET.Element("mxGraphModel",
        dx="1422", dy="762", grid="1", gridSize="10", guides="1",
        tooltips="1", connect="1", arrows="1", fold="1", page="1",
        pageScale="1", pageWidth="1654", pageHeight="1169",
        math="0", shadow="0")
    g = ET.SubElement(root, "root")
    ET.SubElement(g, "mxCell", id="0")
    ET.SubElement(g, "mxCell", id="1", parent="0")

    # Title
    tc = _cell(g, id="title",
               value=f"<b>{title}</b>",
               style="text;html=1;strokeColor=none;fillColor=none;"
                     "align=center;verticalAlign=middle;whiteSpace=wrap;"
                     "rounded=0;fontSize=20;",
               vertex="1", parent="1")
    _geo(tc, x=PAGE_X, y=22, w=900, h=42)

    _add_legend(g, findings)

    # Subnet containers
    cont_ids = {}
    for ci, cont in enumerate(containers):
        cid = f"cont_{ci}"
        cont_ids[cont["subnet"]] = cid
        if cont["subnet"] == "external":
            fill, stroke = "#fff3e0","#e65100"; fc="#bf360c"
            lbl = "&#x2601;  External / Internet"
        else:
            fill, stroke = SUBNET_PALETTES[cont["palette_idx"] % len(SUBNET_PALETTES)]
            fc = stroke
            lbl = f"Subnet: {cont['subnet']}"

        cc = _cell(g, id=cid, value=f"<b>{lbl}</b>",
                   style=(f"swimlane;startSize={CONT_TITLE};fillColor={fill};"
                          f"strokeColor={stroke};fontColor={fc};fontSize=11;"
                          "fontStyle=1;rounded=1;arcSize=3;swimlaneLine=1;"
                          "align=left;spacingLeft=8;html=1;"),
                   vertex="1", parent="1")
        _geo(cc, x=cont["x"], y=cont["y"], w=cont["w"], h=cont["h"])

    # Nodes — NO edges drawn at all
    for ni, (ip, info) in enumerate(nodes.items()):
        nid = f"n{ni}"
        ax, ay  = node_pos[ip]
        sub     = info["subnet"]
        cont    = next(c for c in containers if c["subnet"] == sub)
        rx, ry  = ax - cont["x"], ay - cont["y"]
        parent  = cont_ids[sub]

        shape = (SHAPE_CLOUD  if not info["is_private"] else
                 SHAPE_SERVER if info["role"] == "server" else SHAPE_PC)

        # Red fill if flagged
        if ip in flagged_ips:
            fill, stroke = FLAG_FILL_STROKE
        else:
            role_k = info["role"] if info["is_private"] else "external"
            fill, stroke = ROLE_FILL_STROKE.get(role_k, ("#fff","#999"))

        hostname = info.get("hostname","")
        macs     = sorted(info["macs"])
        mac_str  = " | ".join(macs) if macs else "MAC: unknown"
        os_str   = info.get("os_guess","Unknown")
        flags    = info.get("flags", set())
        flag_str = "  ".join(sorted(flags)) if flags else ""

        # Label: hostname (bold) / IP / MAC / OS guess
        if hostname:
            label = (f"<b>{hostname}</b><br/>"
                     f"<font style='font-size:9px;'>{ip}</font><br/>"
                     f"<font style='font-size:8px;color:#444;'>{mac_str}</font><br/>"
                     f"<font style='font-size:8px;color:#666;'>OS: {os_str}</font>")
        else:
            label = (f"<b>{ip}</b><br/>"
                     f"<font style='font-size:8px;color:#444;'>{mac_str}</font><br/>"
                     f"<font style='font-size:8px;color:#666;'>OS: {os_str}</font>")

        protos  = sorted(info["protocols"])
        ports   = sorted(info["open_ports"])
        tooltip = (f"Protocols: {', '.join(protos)}\n"
                   f"Open ports (passive): {', '.join(str(p) for p in ports) or 'none seen'}\n"
                   f"OS guess: {os_str}\n"
                   f"Pkts: {info['count']:,}  Bytes: {info['bytes']:,}\n"
                   + (f"⚠ FLAGS: {flag_str}" if flag_str else ""))

        nc = _cell(g, id=nid, value=label, tooltip=tooltip,
                   style=(f"{shape}fillColor={fill};strokeColor={stroke};"
                          "verticalLabelPosition=bottom;verticalAlign=top;"
                          "labelPosition=center;align=center;"
                          "labelBackgroundColor=none;labelBorderColor=none;"
                          "fontSize=9;whiteSpace=wrap;html=1;"),
                   vertex="1", parent=parent)
        # Icon geometry: NODE_W × NODE_H only.
        # The label renders below this box via verticalLabelPosition=bottom.
        # Row spacing (STRIDE_Y) already reserves LABEL_RESERVE px for it,
        # so labels never reach the next row's icons.
        _geo(nc, x=rx, y=ry, w=NODE_W, h=NODE_H)

    # ── Gateway lines: thin grey lines between gateway and every node in subnet ──
    gw_node_ids = {}   # ip -> id  (for gateways that ARE nodes)
    for ip, nid_candidate in zip(
            [ip for ip in nodes],
            [f"n{ni}" for ni in range(len(nodes))]):
        if ip in gateways.values():
            gw_node_ids[ip] = nid_candidate

    # Build reverse lookup: nid for each ip
    node_id_map = {ip: f"n{ni}" for ni, ip in enumerate(nodes)}

    edge_idx = 0
    for subnet, gw_ip in gateways.items():
        if gw_ip not in node_id_map:
            continue
        gw_id = node_id_map[gw_ip]
        # Connect gateway to every other node in the same subnet
        for ip, info in nodes.items():
            if ip == gw_ip:
                continue
            if info["subnet"] != subnet:
                continue
            if ip not in node_id_map:
                continue
            ec = _cell(g, id=f"gwe{edge_idx}", value="",
                       style=("endArrow=none;startArrow=none;"
                              "strokeColor=#bbbbbb;strokeWidth=1;opacity=50;"
                              "dashed=1;dashPattern=4 4;"
                              "rounded=1;html=1;"),
                       edge="1", source=gw_id, target=node_id_map[ip],
                       parent="1")
            ET.SubElement(ec, "mxGeometry", relative="1", **{"as":"geometry"})
            edge_idx += 1

    # ── Traceroute section ─────────────────────────────────────────────────────
    if traceroutes:
        tr_y = max_y + 80   # start below main diagram
        _draw_traceroute_section(g, traceroutes, node_id_map, tr_y)

    raw = ET.tostring(root, encoding="unicode")
    return minidom.parseString(raw).toprettyxml(indent="  ")


def _draw_traceroute_section(g, traceroutes, node_id_map, start_y):
    """
    Draw traceroute hop chains below the main diagram.
    Each trace is rendered as a horizontal chain of hop nodes
    connected by labelled arrows, grouped in a swimlane container.
    """
    HOP_W     = 120
    HOP_H     = 50
    HOP_GAP   = 60
    SECT_PAD  = 20
    SECT_TITLE= 30
    ROW_H     = HOP_H + SECT_PAD * 2 + SECT_TITLE + 20
    cy        = int(start_y)
    SHAPE_ROUTER = "shape=mxgraph.cisco.routers.router;"

    # Section header label
    hdr = _cell(g, id="tr_hdr",
                value="<b>&#128246; Traceroute Paths (reconstructed from ICMP TTL-exceeded)</b>",
                style=("text;html=1;strokeColor=none;fillColor=none;"
                       "align=left;verticalAlign=middle;fontSize=13;"
                       "fontColor=#333;fontStyle=1;"),
                vertex="1", parent="1")
    _geo(hdr, x=PAGE_X, y=cy, w=900, h=28)
    cy += 36

    for ti, trace in enumerate(traceroutes):
        hops     = trace["hops"]
        n_hops   = len(hops)
        if n_hops == 0:
            continue

        src_label = trace.get("src_hostname") or trace["src"]
        dst_label = trace.get("dst_hostname") or trace["dst"]
        title_lbl = (f"<b>Trace {ti+1}:</b>  {src_label}  →  {dst_label}  "
                     f"<font style='font-size:9px;color:#666;'>({n_hops} hop{"s" if n_hops!=1 else ""})</font>")

        # Container width: origin + hops + destination
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

        # Helper: draw a hop node inside the container
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

        # Helper: draw an arrow between two hop nodes
        def hop_edge(eid, src_id, tgt_id, lbl=""):
            ec = _cell(g, id=eid, value=lbl,
                       style=("endArrow=block;endFill=1;"
                              "strokeColor=#607d8b;strokeWidth=1.5;"
                              "fontSize=8;fontColor=#607d8b;"
                              "rounded=1;html=1;"),
                       edge="1", source=src_id, target=tgt_id,
                       parent=cid)
            ET.SubElement(ec, "mxGeometry", relative="1", **{"as":"geometry"})

        # Origin node (the client that ran the trace)
        origin_id = f"tr{ti}_origin"
        origin_lbl = (f"<b>{src_label}</b><br/>"
                      f"<font style='font-size:8px;color:#555;'>{trace['src']}</font>")
        hop_node(origin_id, 0, origin_lbl,
                 "shape=mxgraph.cisco.computers_and_peripherals.pc;",
                 "#fff2cc","#d6b656", f"Traceroute origin: {trace['src']}")

        prev_id = origin_id
        for hi, hop in enumerate(hops):
            hop_ip  = hop["router_ip"]
            hop_hn  = hop.get("hostname", "")
            hop_lbl = (f"<b>Hop {hop['hop_n']}</b><br/>"
                       f"<font style='font-size:8px;'>{hop_hn or hop_ip}</font><br/>"
                       f"<font style='font-size:7px;color:#888;'>{hop_ip if hop_hn else ''}</font>")
            nid = f"tr{ti}_hop{hi}"
            # Check if this hop IP is a known node — if so link style differs
            is_known = hop_ip in node_id_map
            fill   = "#dae8fc" if is_known else "#f5f5f5"
            stroke = "#6c8ebf" if is_known else "#aaaaaa"
            known_note = "\nKnown node in diagram" if is_known else ""
            hop_node(nid, hi+1, hop_lbl, SHAPE_ROUTER, fill, stroke,
                     tooltip=f"Router hop {hop['hop_n']}: {hop_ip}{known_note}")
            hop_edge(f"tr{ti}_e{hi}", prev_id, nid)
            prev_id = nid

        # Destination node
        dst_id  = f"tr{ti}_dst"
        dst_lbl = (f"<b>{dst_label}</b><br/>"
                   f"<font style='font-size:8px;color:#555;'>{trace['dst']}</font>")
        hop_node(dst_id, n_hops+1, dst_lbl,
                 "shape=mxgraph.cisco.storage.cloud;",
                 "#ffe6cc","#d79b00", f"Trace destination: {trace['dst']}")
        hop_edge(f"tr{ti}_efinal", prev_id, dst_id, "")

        cy += ch + 16   # gap between traces



def _add_legend(g, findings):
    sev_counts = defaultdict(int)
    for f in findings: sev_counts[f["severity"]] += 1

    roles = [("server","Server"),("host","Host"),
             ("client","Client"),("external","External")]
    height = 30 + len(roles)*24 + 20 + (60 if findings else 0)

    bg = _cell(g, id="legend_bg", value="<b>Legend</b>",
               style=("rounded=1;html=1;fillColor=#f5f5f5;strokeColor=#666;"
                      "fontColor=#333;align=center;verticalAlign=top;"
                      "spacingTop=6;fontSize=11;"),
               vertex="1", parent="1")
    _geo(bg, x=20, y=100, w=LEGEND_W, h=height)

    for ri, (role, lbl) in enumerate(roles):
        y = 100 + 30 + ri*24
        fill, stroke = ROLE_FILL_STROKE[role]
        rs = _cell(g, id=f"rs{ri}", value="",
                   style=(f"shape=mxgraph.cisco.computers_and_peripherals.pc;"
                          f"fillColor={fill};strokeColor={stroke};"),
                   vertex="1", parent="1")
        _geo(rs, x=28, y=y, w=20, h=20)
        rll = _cell(g, id=f"rll{ri}", value=lbl,
                    style="text;html=1;strokeColor=none;fillColor=none;"
                          "align=left;verticalAlign=middle;fontSize=10;",
                    vertex="1", parent="1")
        _geo(rll, x=54, y=y, w=148, h=20)

    if findings:
        base = 100 + 30 + len(roles)*24 + 14
        # Red flag node indicator
        rs2 = _cell(g, id="rs_flag", value="",
                    style=(f"rounded=1;html=1;"
                           f"fillColor={FLAG_FILL_STROKE[0]};strokeColor={FLAG_FILL_STROKE[1]};"),
                    vertex="1", parent="1")
        _geo(rs2, x=28, y=base, w=20, h=14)
        total = len(findings)
        crit  = sev_counts.get("CRITICAL",0)
        high  = sev_counts.get("HIGH",0)
        rll2 = _cell(g, id="rll_flag",
                     value=f"⚠ Pentest finding ({total} total, {crit} CRIT, {high} HIGH)",
                     style="text;html=1;strokeColor=none;fillColor=none;"
                           "align=left;verticalAlign=middle;fontSize=10;fontColor=#b85450;",
                     vertex="1", parent="1")
        _geo(rll2, x=54, y=base, w=148, h=20)
        note = _cell(g, id="rll_note",
                     value="Hover nodes &amp; see Excel<br/>Pentest Findings sheet",
                     style="text;html=1;strokeColor=none;fillColor=none;"
                           "align=left;verticalAlign=middle;fontSize=9;fontColor=#888;",
                     vertex="1", parent="1")
        _geo(note, x=24, y=base+22, w=165, h=28)

