"""
Hand-rolled minimal Visio (.vsdx) network diagram export.

A .vsdx file is an OOXML zip package. This module builds the minimal set of
parts needed for Visio (and most third-party vsdx viewers, e.g. LibreOffice
Draw) to open a single-page drawing containing plain rectangle shapes (one
per host, colour-coded the same as the draw.io diagrams) and simple line
connectors (one per observed connection), grouped into subnet container
rectangles.

Known limitations (documented for users):
  - Shapes are plain rectangles/lines, not Visio network stencils
    (no Cisco/AWS/Azure shape masters).
  - Single page, fixed layout reused from the draw.io L3 layout algorithm.
  - Some Visio versions may show a "repair" prompt on first open due to the
    minimal part set — accepting the repair produces a usable diagram.
    LibreOffice Draw opens the file directly without prompting.
"""

import io
import re
import html
import zipfile
import xml.etree.ElementTree as ET

from ..graph.layout import (
    layout, ROLE_FILL_STROKE, FLAG_FILL_STROKE, SUBNET_PALETTES,
    NODE_W, NODE_H, LABEL_RESERVE, CONT_TITLE,
)

# draw.io layouts are in CSS pixels; Visio pages are in inches.
PX_TO_IN = 1.0 / 96.0
PAGE_MARGIN_IN = 0.5

_VISIO_NS = "http://schemas.microsoft.com/office/visio/2012/main"
_R_NS = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"


def _strip_html(s):
    s = re.sub(r"<br\s*/?>", "\n", s or "")
    s = re.sub(r"<[^>]+>", "", s)
    return html.unescape(s).strip()


def _xml_decl():
    return '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'


def _content_types():
    return _xml_decl() + (
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Override PartName="/visio/document.xml" ContentType="application/vnd.ms-visio.drawing.main+xml"/>'
        '<Override PartName="/visio/pages/pages.xml" ContentType="application/vnd.ms-visio.pages+xml"/>'
        '<Override PartName="/visio/pages/page1.xml" ContentType="application/vnd.ms-visio.page+xml"/>'
        '<Override PartName="/visio/windows.xml" ContentType="application/vnd.ms-visio.windows+xml"/>'
        '<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>'
        '<Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/>'
        '</Types>'
    )


def _root_rels():
    return _xml_decl() + (
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" Type="http://schemas.microsoft.com/visio/2010/relationships/document" Target="visio/document.xml"/>'
        '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>'
        '<Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties" Target="docProps/app.xml"/>'
        '</Relationships>'
    )


def _core_props(title):
    safe_title = html.escape(title)
    return _xml_decl() + (
        '<cp:coreProperties '
        'xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
        'xmlns:dc="http://purl.org/dc/elements/1.1/" '
        'xmlns:dcterms="http://purl.org/dc/terms/" '
        'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
        f'<dc:title>{safe_title}</dc:title>'
        '<dc:creator>pcap-tool</dc:creator>'
        '</cp:coreProperties>'
    )


def _app_props():
    return _xml_decl() + (
        '<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties">'
        '<Application>pcap-tool</Application>'
        '</Properties>'
    )


def _document_xml():
    return _xml_decl() + (
        f'<VisioDocument xmlns="{_VISIO_NS}" xmlns:r="{_R_NS}">'
        '<DocumentSettings TopPage="1" DefaultTextStyle="0" DefaultLineStyle="0" '
        'DefaultFillStyle="0" DefaultGuideStyle="0"/>'
        '</VisioDocument>'
    )


def _document_rels():
    return _xml_decl() + (
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" Type="http://schemas.microsoft.com/visio/2010/relationships/pages" Target="pages/pages.xml"/>'
        '<Relationship Id="rId2" Type="http://schemas.microsoft.com/visio/2010/relationships/windows" Target="windows.xml"/>'
        '</Relationships>'
    )


def _windows_xml(page_w_in, page_h_in):
    return _xml_decl() + (
        f'<Windows xmlns="{_VISIO_NS}" xmlns:r="{_R_NS}" ClientWidth="1024" ClientHeight="768">'
        f'<Window ID="0" WindowType="Drawing" WindowState="0" WindowLeft="0" WindowTop="0" '
        f'WindowWidth="1024" WindowHeight="768" Page="0" ShowRulers="1" ShowGrid="1" '
        f'ShowPageBreaks="0" ShowGuides="1" GlueSettings="9" SnapSettings="295" '
        f'SnapExtensions="34" SnapAngles="0" TabSplitterPos="0.5" ViewScale="-1" '
        f'ViewCenterX="{page_w_in/2:.4f}" ViewCenterY="{page_h_in/2:.4f}">'
        '<Page ID="0"/>'
        '</Window>'
        '</Windows>'
    )


def _pages_xml(page_w_in, page_h_in, title):
    return _xml_decl() + (
        f'<Pages xmlns="{_VISIO_NS}" xmlns:r="{_R_NS}">'
        f'<Page ID="0" NameU="{html.escape(title)}" Name="{html.escape(title)}" '
        f'ViewScale="-1" ViewCenterX="{page_w_in/2:.4f}" ViewCenterY="{page_h_in/2:.4f}">'
        '<PageSheet>'
        '<Cell N="PageWidth" V="%.4f"/>'
        '<Cell N="PageHeight" V="%.4f"/>'
        '<Cell N="PageScale" V="1" U="IN_F"/>'
        '<Cell N="DrawingScale" V="1" U="IN_F"/>'
        '<Cell N="DrawingSizeType" V="0"/>'
        '<Cell N="DrawingScaleType" V="0"/>'
        '<Cell N="InhibitSnap" V="0"/>'
        '<Cell N="PageLineJumpDirX" V="2"/>'
        '<Cell N="PageLineJumpDirY" V="1"/>'
        '<Cell N="PageShapeSplit" V="1"/>'
        '</PageSheet>'
        '<Rel r:id="rId1"/>'
        '</Page>'
        '</Pages>'
    ) % (page_w_in, page_h_in)


def _pages_rels():
    return _xml_decl() + (
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" Type="http://schemas.microsoft.com/visio/2010/relationships/page" Target="page1.xml"/>'
        '</Relationships>'
    )


def _rect_shape(shape_id, pinx_in, piny_in, w_in, h_in, fill_hex, stroke_hex, text):
    """A plain filled rectangle shape with centred text, in page inches."""
    safe_text = html.escape(text)
    return (
        f'<Shape ID="{shape_id}" Type="Shape">'
        f'<Cell N="PinX" V="{pinx_in:.4f}"/>'
        f'<Cell N="PinY" V="{piny_in:.4f}"/>'
        f'<Cell N="Width" V="{w_in:.4f}"/>'
        f'<Cell N="Height" V="{h_in:.4f}"/>'
        f'<Cell N="LocPinX" V="{w_in/2:.4f}"/>'
        f'<Cell N="LocPinY" V="{h_in/2:.4f}"/>'
        '<Cell N="Angle" V="0"/>'
        f'<Cell N="FillForegnd" V="{fill_hex}"/>'
        '<Cell N="FillPattern" V="1"/>'
        f'<Cell N="LineColor" V="{stroke_hex}"/>'
        '<Cell N="LinePattern" V="1"/>'
        '<Cell N="LineWeight" V="0.01"/>'
        '<Section N="Geometry" IX="0">'
        '<Row T="RelMoveTo" IX="1"><Cell N="X" V="0"/><Cell N="Y" V="0"/></Row>'
        '<Row T="RelLineTo" IX="2"><Cell N="X" V="1"/><Cell N="Y" V="0"/></Row>'
        '<Row T="RelLineTo" IX="3"><Cell N="X" V="1"/><Cell N="Y" V="1"/></Row>'
        '<Row T="RelLineTo" IX="4"><Cell N="X" V="0"/><Cell N="Y" V="1"/></Row>'
        '<Row T="RelLineTo" IX="5"><Cell N="X" V="0"/><Cell N="Y" V="0"/></Row>'
        '</Section>'
        f'<Text>{safe_text}</Text>'
        '</Shape>'
    )


def _connector_shape(shape_id, x1_in, y1_in, x2_in, y2_in):
    """A simple straight-line connector between two absolute page points (inches)."""
    w = abs(x2_in - x1_in) or 0.001
    h = abs(y2_in - y1_in) or 0.001
    pinx = (x1_in + x2_in) / 2
    piny = (y1_in + y2_in) / 2
    # Geometry coordinates are relative to the shape's bounding box,
    # with (0,0) at the bottom-left corner of that box.
    x1r = 0.0 if x1_in <= x2_in else w
    x2r = w if x1_in <= x2_in else 0.0
    y1r = 0.0 if y1_in <= y2_in else h
    y2r = h if y1_in <= y2_in else 0.0
    return (
        f'<Shape ID="{shape_id}" Type="Shape">'
        f'<Cell N="PinX" V="{pinx:.4f}"/>'
        f'<Cell N="PinY" V="{piny:.4f}"/>'
        f'<Cell N="Width" V="{w:.4f}"/>'
        f'<Cell N="Height" V="{h:.4f}"/>'
        f'<Cell N="LocPinX" V="{w/2:.4f}"/>'
        f'<Cell N="LocPinY" V="{h/2:.4f}"/>'
        '<Cell N="Angle" V="0"/>'
        '<Cell N="LineColor" V="#999999"/>'
        '<Cell N="LinePattern" V="1"/>'
        '<Cell N="LineWeight" V="0.0075"/>'
        '<Cell N="NoFill" V="1"/>'
        '<Section N="Geometry" IX="0">'
        '<Row T="NoFill" IX="0"><Cell N="X" V="1"/></Row>'
        f'<Row T="MoveTo" IX="1"><Cell N="X" V="{x1r:.4f}"/><Cell N="Y" V="{y1r:.4f}"/></Row>'
        f'<Row T="LineTo" IX="2"><Cell N="X" V="{x2r:.4f}"/><Cell N="Y" V="{y2r:.4f}"/></Row>'
        '</Section>'
        '</Shape>'
    )


def _page1_xml(nodes, edges, findings, gateways, title):
    node_pos, containers = layout(nodes)

    if containers:
        max_x_px = max(c["x"] + c["w"] for c in containers)
        max_y_px = max(c["y"] + c["h"] for c in containers)
    else:
        max_x_px, max_y_px = 800, 600

    page_w_in = max_x_px * PX_TO_IN + PAGE_MARGIN_IN * 2
    page_h_in = max_y_px * PX_TO_IN + PAGE_MARGIN_IN * 2

    def to_in_x(px):
        return px * PX_TO_IN + PAGE_MARGIN_IN

    def to_in_y_top(px):
        """Convert a draw.io y (distance from top, px) to Visio y (distance from bottom, in)."""
        return page_h_in - (px * PX_TO_IN + PAGE_MARGIN_IN)

    flagged_ips = {f["src"] for f in findings if f.get("src") in nodes}
    flagged_ips |= {f["dst"] for f in findings if f.get("dst") in nodes}

    shapes_xml = []
    shape_id = 1

    # Subnet container rectangles (drawn first, behind nodes/connectors)
    for cont in containers:
        if cont["subnet"] == "external":
            fill, stroke = "#fff3e0", "#e65100"
            label = "External / Internet"
        else:
            fill, stroke = SUBNET_PALETTES[cont["palette_idx"] % len(SUBNET_PALETTES)]
            label = f"Subnet: {cont['subnet']}"

        w_in = cont["w"] * PX_TO_IN
        h_in = cont["h"] * PX_TO_IN
        pinx = to_in_x(cont["x"]) + w_in / 2
        piny = to_in_y_top(cont["y"]) - h_in / 2
        shapes_xml.append(_rect_shape(shape_id, pinx, piny, w_in, h_in, fill, stroke, label))
        shape_id += 1

    # Node centre points (page inches), for connectors
    node_centres = {}
    for ip, (ax, ay) in node_pos.items():
        info = nodes[ip]
        w_in = NODE_W * PX_TO_IN
        h_in = (NODE_H + LABEL_RESERVE) * PX_TO_IN
        pinx = to_in_x(ax) + w_in / 2
        piny = to_in_y_top(ay) - h_in / 2
        node_centres[ip] = (pinx, piny)

    # Connectors (drawn before nodes so node fills cover the line ends)
    for (src, dst) in edges:
        if src not in node_centres or dst not in node_centres:
            continue
        x1, y1 = node_centres[src]
        x2, y2 = node_centres[dst]
        shapes_xml.append(_connector_shape(shape_id, x1, y1, x2, y2))
        shape_id += 1

    # Node rectangles
    for ip, (ax, ay) in node_pos.items():
        info = nodes[ip]
        if ip in flagged_ips:
            fill, stroke = FLAG_FILL_STROKE
        else:
            role_k = info["role"] if info["is_private"] else "external"
            fill, stroke = ROLE_FILL_STROKE.get(role_k, ("#ffffff", "#999999"))

        hostname = info.get("hostname", "")
        macs = sorted(info["macs"])
        mac_str = " | ".join(macs) if macs else "MAC: unknown"
        os_str = info.get("os_guess", "Unknown")

        lines = []
        if hostname:
            lines.append(hostname)
        lines.append(ip)
        lines.append(mac_str)
        lines.append(f"OS: {os_str}")
        text = "\n".join(lines)

        pinx, piny = node_centres[ip]
        w_in = NODE_W * PX_TO_IN
        h_in = (NODE_H + LABEL_RESERVE) * PX_TO_IN
        shapes_xml.append(_rect_shape(shape_id, pinx, piny, w_in, h_in, fill, stroke, text))
        shape_id += 1

    body = "".join(shapes_xml)
    return _xml_decl() + (
        f'<PageContents xmlns="{_VISIO_NS}" xmlns:r="{_R_NS}">'
        f'<Shapes>{body}</Shapes>'
        '</PageContents>'
    ), page_w_in, page_h_in


def generate_vsdx(nodes, edges, findings, gateways, title="Network Diagram", output_path=None):
    """
    Build a Visio (.vsdx) network diagram from the same node/edge graph used
    for the draw.io diagrams.

    If `output_path` is given, the file is written there and `True` is
    returned. Otherwise an `io.BytesIO` containing the .vsdx is returned
    (for streaming via Flask's `send_file`).
    """
    page1, page_w_in, page_h_in = _page1_xml(nodes, edges, findings, gateways, title)

    parts = {
        "[Content_Types].xml": _content_types(),
        "_rels/.rels": _root_rels(),
        "docProps/core.xml": _core_props(title),
        "docProps/app.xml": _app_props(),
        "visio/document.xml": _document_xml(),
        "visio/_rels/document.xml.rels": _document_rels(),
        "visio/windows.xml": _windows_xml(page_w_in, page_h_in),
        "visio/pages/pages.xml": _pages_xml(page_w_in, page_h_in, title),
        "visio/pages/_rels/pages.xml.rels": _pages_rels(),
        "visio/pages/page1.xml": page1,
    }

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, content in parts.items():
            zf.writestr(name, content.encode("utf-8"))

    if output_path:
        with open(output_path, "wb") as f:
            f.write(buf.getvalue())
        return True

    buf.seek(0)
    return buf
