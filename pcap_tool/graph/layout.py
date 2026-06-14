"""Diagram colour/shape styling constants and node layout algorithm."""

import math
import ipaddress
from collections import defaultdict

# ─────────────────────────────────────────────────────────────────────────────
# Diagram styles & layout
# ─────────────────────────────────────────────────────────────────────────────

SHAPE_SERVER = "shape=mxgraph.cisco.servers.standard_server;"
SHAPE_PC     = "shape=mxgraph.cisco.computers_and_peripherals.pc;"
SHAPE_CLOUD  = "shape=mxgraph.cisco.storage.cloud;"

ROLE_FILL_STROKE = {
    "server":   ("#dae8fc","#6c8ebf"),
    "host":     ("#d5e8d4","#82b366"),
    "client":   ("#fff2cc","#d6b656"),
    "external": ("#ffe6cc","#d79b00"),
}
FLAG_FILL_STROKE = ("#f8cecc","#b85450")  # red tint for flagged nodes

SUBNET_PALETTES = [
    ("#e8f5e9","#2e7d32"),
    ("#e3f2fd","#1565c0"),
    ("#fce4ec","#c62828"),
    ("#f3e5f5","#6a1b9a"),
    ("#fff8e1","#f57f17"),
    ("#e0f7fa","#00695c"),
    ("#fbe9e7","#bf360c"),
    ("#ede7f6","#4527a0"),
]

# ── Layout constants ─────────────────────────────────────────────────────────
# The node is rendered as a Cisco icon (NODE_W × NODE_H) with a text label
# below it.  draw.io's verticalLabelPosition=bottom places the label OUTSIDE
# the icon geometry, so we must account for label height in row spacing.
#
# STRIDE_X = horizontal distance between node top-left corners
# STRIDE_Y = vertical distance between node top-left corners
#          = NODE_H + LABEL_RESERVE + inter-node gap
NODE_W          = 72    # icon width  (also used as label width)
NODE_H          = 60    # icon height only — geometry passed to draw.io
LABEL_RESERVE   = 72    # vertical space reserved for label text (4 lines + padding)
INTER_GAP_X     = 28    # horizontal gap between adjacent node label areas
INTER_GAP_Y     = 18    # vertical gap between bottom of one label and top of next icon
STRIDE_X        = NODE_W + INTER_GAP_X          # 100
STRIDE_Y        = NODE_H + LABEL_RESERVE + INTER_GAP_Y   # 150
CONT_PAD        = 44    # padding inside container border
CONT_TITLE      = 34    # container header height
CONT_GAP_X      = 60    # gap between container boxes horizontally
CONT_GAP_Y      = 50    # gap between container boxes vertically
LEGEND_W        = 185
PAGE_X          = 215
PAGE_Y          = 80
NODES_PER_ROW   = 4
CONTS_PER_ROW   = 3


def layout(nodes):
    subnets = defaultdict(list)
    for ip, info in nodes.items():
        subnets[info["subnet"]].append(ip)

    def skey(s):
        if s == "external": return (1,"")
        try: return (0, str(ipaddress.ip_network(s)))
        except: return (0,s)

    sorted_subs = sorted(subnets, key=skey)
    containers  = []
    node_pos    = {}
    cx, cy      = PAGE_X, PAGE_Y
    row_max_h   = 0
    col         = 0

    for si, sub in enumerate(sorted_subs):
        ips = subnets[sub]

        def isort(ip):
            r = {"server":0,"host":1,"client":2}.get(nodes[ip]["role"],3)
            try: return (r, int(ipaddress.ip_address(ip.split("/")[0])))
            except: return (r, ip)
        ips.sort(key=isort)

        n     = len(ips)
        ncols = min(n, NODES_PER_ROW)
        nrows = math.ceil(n / NODES_PER_ROW)

        # Inner dimensions: each node occupies STRIDE_X × STRIDE_Y
        # but the last node in each row/col doesn't need the trailing gap
        inner_w = ncols * STRIDE_X - INTER_GAP_X
        inner_h = nrows * STRIDE_Y - INTER_GAP_Y
        cw = inner_w + CONT_PAD * 2
        ch = inner_h + CONT_PAD * 2 + CONT_TITLE

        for i, ip in enumerate(ips):
            r2, c2 = divmod(i, NODES_PER_ROW)
            # nx/ny = top-left corner of the icon within the container
            nx = cx + CONT_PAD + c2 * STRIDE_X
            ny = cy + CONT_TITLE + CONT_PAD + r2 * STRIDE_Y
            node_pos[ip] = (int(nx), int(ny))

        containers.append(dict(subnet=sub, palette_idx=si,
                               x=cx, y=cy, w=cw, h=ch, ips=ips))
        row_max_h = max(row_max_h, ch)
        col += 1
        if col >= CONTS_PER_ROW:
            cx = PAGE_X; cy += row_max_h + CONT_GAP_Y; row_max_h = 0; col = 0
        else:
            cx += cw + CONT_GAP_X

    return node_pos, containers
