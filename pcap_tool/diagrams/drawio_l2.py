"""Layer-2 / Wi-Fi topology draw.io diagram generator."""

import xml.etree.ElementTree as ET
from xml.dom import minidom
from collections import defaultdict

from ._xml_helpers import _cell, _geo

def generate_l2_drawio(wifi_data, nodes, arp_table, title="L2 / Wi-Fi Topology"):
    """
    Produce a Layer-2 / Wi-Fi topology draw.io diagram.

    Wi-Fi section  (from 802.11 management frames):
      - One swimlane per AP: SSID / BSSID / channel / encryption label
      - AP node with Cisco wireless icon, colour-coded by encryption strength
        Open=red, WPA1=amber, WPA2=green, WPA3=blue
      - Associated client nodes inside the AP lane, connected by lines
      - WPS badge on APs advertising Wi-Fi Protected Setup
      - Deauthentication event count + reason shown as a warning banner
      - Channel labelled with band (2.4 / 5 / 6 GHz)

    Unassociated clients section:
      - Clients seen probing but not associated to any AP

    Wired L2 section  (from ARP / MAC table):
      - One swimlane per /24 subnet
      - Each host: IP / hostname / MAC(s)
      - ARP anomaly (multiple MACs for same IP) flagged in red

    Legend at top-left explains all colours.
    """

    # ── XML-safe string helper ────────────────────────────────────────────────
    # Strip characters that are illegal in XML 1.0 (anything < 0x09,
    # 0x0B, 0x0C, 0x0E-0x1F).  We do NOT use a regex with \x00 in the
    # source because that literal can be corrupted by binary editors;
    # instead we build the translation table programmatically.
    _illegal_xml = str.maketrans(
        "", "",
        "".join(chr(i) for i in
                list(range(0, 9)) + [11, 12] + list(range(14, 32)))
    )

    def xs(s):
        """Return s safe for embedding in draw.io XML cell values (html=1)."""
        if not isinstance(s, str):
            s = str(s)
        s = s.translate(_illegal_xml)
        # ET handles attribute escaping, but for HTML embedded in value=""
        # we need to escape & < > ourselves.
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    # ── Cisco shape strings ───────────────────────────────────────────────────
    SHAPE_AP     = "shape=mxgraph.cisco.wireless.wireless_access_point;"
    SHAPE_PC     = "shape=mxgraph.cisco.computers_and_peripherals.pc;"
    SHAPE_LAPTOP = "shape=mxgraph.cisco.computers_and_peripherals.workstation;"
    SHAPE_SERVER = "shape=mxgraph.cisco.servers.standard_server;"

    # ── Colour scheme (fill, stroke) ──────────────────────────────────────────
    ENC_COLOURS = {
        "Open":    ("#f8cecc", "#b85450"),   # red   — no encryption
        "WPA":     ("#ffe6cc", "#d79b00"),   # amber — deprecated
        "WPA2":    ("#d5e8d4", "#82b366"),   # green — current standard
        "WPA3":    ("#dae8fc", "#6c8ebf"),   # blue  — latest (SAE/OWE)
        "WPA2+FT": ("#d5e8d4", "#82b366"),
        "WPA3+FT": ("#dae8fc", "#6c8ebf"),
    }
    ENC_DEFAULT    = ("#f5f5f5", "#666666")
    CLI_ASSOC_FILL = "#fff2cc";  CLI_ASSOC_STR = "#d6b656"
    CLI_UA_FILL    = "#f5f5f5";  CLI_UA_STR    = "#aaaaaa"
    WIRED_FILL     = "#e3f2fd";  WIRED_STR     = "#1565c0"
    ANOMALY_FILL   = "#f8cecc";  ANOMALY_STR   = "#b85450"

    # ── Layout constants ──────────────────────────────────────────────────────
    PX = 30         # page left margin
    PY = 80         # first content Y (below title)
    AP_W    = 330   # AP swimlane width
    AP_H0   = 140   # base height before clients
    CLI_H   = 44    # per-client row height
    CLI_PAD = 6
    AP_GAPX = 28
    AP_GAPY = 50
    APS_ROW = 4
    AP_ICO_W = 64; AP_ICO_H = 52
    CLI_ICO_W = 48; CLI_ICO_H = 36
    WIRED_W  = 270
    WIRED_H0 = 36   # header height
    HOST_H   = 48
    HOST_PAD = 6
    SEG_GAPX = 26
    SEG_GAPY = 40
    SEGS_ROW = 4

    aps     = wifi_data.get("aps",     [])
    clients = wifi_data.get("clients", [])
    events  = wifi_data.get("events",  [])

    # Precompute: MAC → (ip, hostname) from the nodes dict
    mac_to_ip = {}
    mac_to_hn = {}
    for ip, info in nodes.items():
        for mac in info.get("macs", set()):
            mac_to_ip[mac] = ip
            if info.get("hostname"):
                mac_to_hn[mac] = info["hostname"]

    # Deauth / disassoc events grouped by BSSID
    deauths_by_bssid = defaultdict(list)
    for ev in events:
        if ev.get("frame_type") in ("Deauthentication", "Disassociation"):
            b = ev.get("bssid", "") or ev.get("dst_mac", "")
            if b:
                deauths_by_bssid[b].append(ev)

    # ── XML scaffold ─────────────────────────────────────────────────────────
    root = ET.Element("mxGraphModel",
        dx="1422", dy="762", grid="1", gridSize="10", guides="1",
        tooltips="1", connect="1", arrows="1", fold="1", page="1",
        pageScale="1", pageWidth="1654", pageHeight="1169",
        math="0", shadow="0")
    g = ET.SubElement(root, "root")
    ET.SubElement(g, "mxCell", id="0")
    ET.SubElement(g, "mxCell", id="1", parent="0")

    _cid = [0]
    def cid():
        _cid[0] += 1
        return f"l2c{_cid[0]}"

    # ── Title ─────────────────────────────────────────────────────────────────
    tc = _cell(g, id=cid(),
               value=f"<b>&#128246; {xs(title)}</b>",
               style=("text;html=1;strokeColor=none;fillColor=none;"
                      "align=left;verticalAlign=middle;whiteSpace=wrap;"
                      "rounded=0;fontSize=18;fontColor=#1A2744;"),
               vertex="1", parent="1")
    _geo(tc, x=PX, y=16, w=900, h=40)

    # ── Legend ────────────────────────────────────────────────────────────────
    legend_rows = [
        ("Open network — no encryption",     "#f8cecc", "#b85450"),
        ("WPA (deprecated TKIP/CCMP)",        "#ffe6cc", "#d79b00"),
        ("WPA2 — current standard",           "#d5e8d4", "#82b366"),
        ("WPA3 — latest (SAE / OWE)",         "#dae8fc", "#6c8ebf"),
        ("Associated client",                 "#fff2cc", "#d6b656"),
        ("Unassociated / probing client",     "#f5f5f5", "#aaaaaa"),
        ("Wired host (from ARP table)",       "#e3f2fd", "#1565c0"),
        ("ARP anomaly — possible MITM",       "#f8cecc", "#b85450"),
    ]
    ROW_H   = 22
    LEG_H   = 28 + len(legend_rows) * ROW_H + 8
    leg_id  = cid()
    lc = _cell(g, id=leg_id, value="<b>Legend</b>",
               style=("swimlane;startSize=24;fillColor=#f5f5f5;"
                      "strokeColor=#aaaaaa;fontColor=#333;fontSize=10;"
                      "fontStyle=1;rounded=1;arcSize=3;html=1;"),
               vertex="1", parent="1")
    _geo(lc, x=PX, y=PY, w=240, h=LEG_H)
    for li, (lbl, fill, stroke) in enumerate(legend_rows):
        sw = _cell(g, id=cid(), value="",
                   style=(f"rounded=1;arcSize=50;fillColor={fill};"
                          f"strokeColor={stroke};strokeWidth=1.5;html=1;"),
                   vertex="1", parent=leg_id)
        _geo(sw, x=8, y=28 + li * ROW_H + 4, w=16, h=14)
        lt = _cell(g, id=cid(), value=xs(lbl),
                   style=("text;html=1;strokeColor=none;fillColor=none;"
                          "align=left;verticalAlign=middle;fontSize=9;"),
                   vertex="1", parent=leg_id)
        _geo(lt, x=30, y=28 + li * ROW_H + 3, w=206, h=16)

    cur_y = PY + LEG_H + 30   # Y cursor below legend

    # ════════════════════════════════════════════════════════════════════════
    # SECTION 1 — Wi-Fi Access Points
    # ════════════════════════════════════════════════════════════════════════
    def ch_band(ch):
        """Return human-readable channel + band string."""
        try:
            c = int(ch)
            if 1 <= c <= 14:   return f"ch {c}  (2.4 GHz)"
            if 36 <= c <= 177: return f"ch {c}  (5 GHz)"
            if c > 177:        return f"ch {c}  (6 GHz)"
        except (TypeError, ValueError):
            pass
        return f"ch {ch}" if ch else "ch ?"

    if aps:
        # Section header
        sh = _cell(g, id=cid(),
                   value="<b>&#128246; Wi-Fi Access Points &amp; Associated Clients</b>",
                   style=("text;html=1;strokeColor=none;fillColor=none;"
                          "align=left;verticalAlign=middle;fontSize=13;"
                          "fontColor=#1A2744;fontStyle=1;"),
                   vertex="1", parent="1")
        _geo(sh, x=PX, y=cur_y, w=900, h=26)
        cur_y += 32

        ap_cx = PX; ap_cy = cur_y; col = 0; row_max_h = 0

        for ap in aps:
            bssid   = ap.get("bssid", "??")
            ssid    = ap.get("ssid", "") or "(hidden SSID)"
            channel = ap.get("channel", 0)
            enc     = ap.get("enc", "Open")
            wps     = ap.get("wps", False)
            beacons = ap.get("beacons", 0)
            ap_clis = ap.get("clients", [])      # list of client MACs
            deauths = deauths_by_bssid.get(bssid, [])
            n_dauth = len(deauths)

            fill, stroke = ENC_COLOURS.get(enc, ENC_DEFAULT)

            # Compute container height
            extra_h = CLI_H * len(ap_clis) + (32 if n_dauth else 0)
            cont_h  = AP_H0 + extra_h

            # Encryption icon
            enc_ico = {"Open": "&#128274;",
                       "WPA":  "&#9888;",
                       "WPA2": "&#9989;",
                       "WPA3": "&#9989;&#9989;"}.get(enc, "&#128275;")
            wps_txt   = "  &#9888; WPS!" if wps else ""
            dauth_txt = f"  &#128308; {n_dauth} deauth" if n_dauth else ""

            cont_val = (f"<b>{xs(ssid)}</b><br/>"
                        f"<font style='font-size:9px;color:#444;'>{xs(bssid)}</font><br/>"
                        f"<font style='font-size:9px;'>{enc_ico} {xs(enc)}"
                        f"{wps_txt}{dauth_txt}"
                        f"  &middot;  {xs(ch_band(channel))}</font>")

            cont_id = cid()
            cc = _cell(g, id=cont_id, value=cont_val,
                       style=(f"swimlane;startSize=54;fillColor={fill};"
                              f"strokeColor={stroke};strokeWidth=2;"
                              "fontColor=#333;fontSize=10;"
                              "rounded=1;arcSize=3;swimlaneLine=1;html=1;"
                              "spacingLeft=6;align=left;verticalAlign=top;"),
                       vertex="1", parent="1")
            _geo(cc, x=ap_cx, y=ap_cy, w=AP_W, h=cont_h)

            # AP icon node
            ap_nid = cid()
            ap_tip = (f"BSSID: {xs(bssid)}\nSSID: {xs(ssid)}\n"
                      f"Encryption: {xs(enc)}\nChannel: {channel}\n"
                      f"WPS: {'YES - risk!' if wps else 'no'}\n"
                      f"Beacons seen: {beacons}\nDeauth frames: {n_dauth}")
            an = _cell(g, id=ap_nid,
                       value=(f"<b>AP</b><br/>"
                              f"<font style='font-size:8px;'>&#9901; {beacons} beacons</font>"),
                       tooltip=ap_tip,
                       style=(f"{SHAPE_AP}fillColor={fill};strokeColor={stroke};"
                              "strokeWidth=2;verticalLabelPosition=bottom;"
                              "verticalAlign=top;labelPosition=center;"
                              "align=center;fontSize=9;html=1;"),
                       vertex="1", parent=cont_id)
            _geo(an, x=(AP_W - AP_ICO_W) // 2, y=58, w=AP_ICO_W, h=AP_ICO_H)

            # Deauth warning banner
            if n_dauth:
                reasons = sorted({ev.get("detail", "") for ev in deauths})
                rsn_str = xs(" | ".join(r for r in reasons if r)[:80])
                dw = _cell(g, id=cid(),
                           value=(f"<b>&#128308; {n_dauth} deauth / disassoc frame(s)</b>"
                                  + (f"<br/><font style='font-size:8px;'>{rsn_str}</font>"
                                     if rsn_str else "")),
                           style=("text;html=1;strokeColor=#b85450;fillColor=#f8cecc;"
                                  "align=center;verticalAlign=middle;fontSize=9;"
                                  "rounded=1;arcSize=8;"),
                           vertex="1", parent=cont_id)
                dw_y = AP_H0 - 36 + CLI_H * len(ap_clis)
                _geo(dw, x=6, y=dw_y, w=AP_W - 12, h=26)

            # Associated client nodes
            for ci2, cli_mac in enumerate(sorted(ap_clis)):
                cli_ip = mac_to_ip.get(cli_mac, "")
                cli_hn = mac_to_hn.get(cli_mac, "")
                top    = xs(cli_hn or cli_ip or cli_mac)
                parts  = []
                if cli_hn and cli_ip: parts.append(cli_ip)
                parts.append(cli_mac)
                bot = xs(" | ".join(parts)) if top != xs(cli_mac) else ""

                cli_val = (f"<b>{top}</b>"
                           + (f"<br/><font style='font-size:8px;color:#444;'>"
                              f"{bot}</font>" if bot else ""))
                cli_tip = (f"MAC: {xs(cli_mac)}\nIP: {xs(cli_ip or 'unknown')}"
                           f"\nHostname: {xs(cli_hn or 'unknown')}")
                cy_off = AP_H0 - 10 + ci2 * (CLI_H + CLI_PAD)
                cli_nid = cid()
                cn = _cell(g, id=cli_nid, value=cli_val, tooltip=cli_tip,
                           style=(f"{SHAPE_PC}fillColor={CLI_ASSOC_FILL};"
                                  f"strokeColor={CLI_ASSOC_STR};"
                                  "verticalLabelPosition=right;verticalAlign=middle;"
                                  "labelPosition=right;align=left;"
                                  "fontSize=9;html=1;"),
                           vertex="1", parent=cont_id)
                _geo(cn, x=CLI_PAD, y=cy_off, w=CLI_ICO_W, h=CLI_ICO_H)

                # Edge: AP icon → client
                ec = _cell(g, id=cid(), value="",
                           style=("endArrow=none;startArrow=none;"
                                  "strokeColor=#bbbbbb;strokeWidth=1;"
                                  "opacity=60;dashed=0;rounded=1;html=1;"),
                           edge="1", source=ap_nid, target=cli_nid,
                           parent=cont_id)
                ET.SubElement(ec, "mxGeometry", relative="1", **{"as": "geometry"})

            # Advance layout
            row_max_h = max(row_max_h, cont_h)
            col += 1
            if col >= APS_ROW:
                ap_cx = PX; ap_cy += row_max_h + AP_GAPY
                row_max_h = 0; col = 0
            else:
                ap_cx += AP_W + AP_GAPX

        cur_y = ap_cy + row_max_h + AP_GAPY + 10

    else:
        # Placeholder when no Wi-Fi frames in capture
        ph = _cell(g, id=cid(),
                   value=("<i>No 802.11 management frames found in this capture.<br/>"
                          "Capture in monitor mode:  "
                          "airmon-ng start wlan0 &amp;&amp; "
                          "tcpdump -i wlan0mon -w wifi.pcap</i>"),
                   style=("text;html=1;strokeColor=#aaaaaa;fillColor=#f9f9f9;"
                          "align=center;verticalAlign=middle;fontSize=10;"
                          "rounded=1;arcSize=5;"),
                   vertex="1", parent="1")
        _geo(ph, x=PX, y=cur_y + 32, w=680, h=52)
        cur_y += 100

    # ════════════════════════════════════════════════════════════════════════
    # SECTION 2 — Unassociated / probing clients
    # ════════════════════════════════════════════════════════════════════════
    ap_macs = {mac for ap in aps for mac in ap.get("clients", [])}
    unassoc  = [c for c in clients if c.get("mac") and c["mac"] not in ap_macs]

    if unassoc:
        ush = _cell(g, id=cid(),
                    value="<b>&#128270; Unassociated / Probing Clients</b>",
                    style=("text;html=1;strokeColor=none;fillColor=none;"
                           "align=left;verticalAlign=middle;fontSize=13;"
                           "fontColor=#1A2744;fontStyle=1;"),
                    vertex="1", parent="1")
        _geo(ush, x=PX, y=cur_y, w=900, h=26)
        cur_y += 32

        ua_cont_h = 32 + len(unassoc) * (CLI_ICO_H + CLI_PAD)
        ua_id = cid()
        uc = _cell(g, id=ua_id,
                   value="<b>&#128270; Probing — no association seen</b>",
                   style=("swimlane;startSize=28;fillColor=#f5f5f5;"
                          f"strokeColor={CLI_UA_STR};strokeWidth=1.5;"
                          "fontColor=#444;fontSize=10;fontStyle=1;"
                          "rounded=1;arcSize=3;html=1;"),
                   vertex="1", parent="1")
        max_ua_w = min(AP_W * APS_ROW + AP_GAPX * (APS_ROW - 1), 1200)
        _geo(uc, x=PX, y=cur_y, w=max_ua_w, h=ua_cont_h)

        for ui, cli in enumerate(sorted(unassoc, key=lambda c: c.get("mac", ""))):
            mac    = cli.get("mac", "")
            cli_ip = mac_to_ip.get(mac, "")
            cli_hn = mac_to_hn.get(mac, "")
            # Only include non-empty, non-null SSIDs in probed list
            probed = sorted(
                xs(s) for s in cli.get("probed_ssids", set())
                if s and s.strip()
            )
            top = xs(cli_hn or cli_ip or mac)
            bot_parts = []
            if cli_hn or cli_ip:
                bot_parts.append(mac)
            if probed:
                probe_str = ", ".join(probed[:3])
                if len(probed) > 3:
                    probe_str += f" +{len(probed)-3}"
                bot_parts.append(f"Probing: {probe_str}")
            bot = xs(" | ".join(bot_parts))

            uval = (f"<b>{top}</b>"
                    + (f"<br/><font style='font-size:8px;color:#555;'>"
                       f"{bot}</font>" if bot else ""))
            utip = (f"MAC: {xs(mac)}\nIP: {xs(cli_ip or 'unknown')}"
                    f"\nHostname: {xs(cli_hn or 'unknown')}"
                    f"\nProbed SSIDs: {xs(', '.join(probed) or 'wildcard only')}")

            ui_node = _cell(g, id=cid(), value=uval, tooltip=utip,
                            style=(f"{SHAPE_LAPTOP}fillColor={CLI_UA_FILL};"
                                   f"strokeColor={CLI_UA_STR};"
                                   "verticalLabelPosition=right;verticalAlign=middle;"
                                   "labelPosition=right;align=left;"
                                   "fontSize=9;html=1;"),
                            vertex="1", parent=ua_id)
            _geo(ui_node, x=CLI_PAD, y=32 + ui * (CLI_ICO_H + CLI_PAD),
                 w=CLI_ICO_W, h=CLI_ICO_H)

        cur_y += ua_cont_h + AP_GAPY

    # ════════════════════════════════════════════════════════════════════════
    # SECTION 3 — Wired L2 segments from ARP / node MAC data
    # ════════════════════════════════════════════════════════════════════════
    wired_by_subnet = defaultdict(list)
    for ip, info in nodes.items():
        if not info.get("is_private"):
            continue
        macs = sorted(info.get("macs", set()))
        if not macs:
            continue
        subnet  = info.get("subnet", "unknown")
        anomaly = len(arp_table.get(ip, set())) > 1
        wired_by_subnet[subnet].append({
            "ip":       ip,
            "macs":     macs,
            "hostname": info.get("hostname", ""),
            "os_guess": info.get("os_guess", "Unknown"),
            "role":     info.get("role", "client"),
            "anomaly":  anomaly,
        })

    if wired_by_subnet:
        wsh = _cell(g, id=cid(),
                    value="<b>&#128279; Wired L2 Segments (ARP / MAC Table)</b>",
                    style=("text;html=1;strokeColor=none;fillColor=none;"
                           "align=left;verticalAlign=middle;fontSize=13;"
                           "fontColor=#1A2744;fontStyle=1;"),
                    vertex="1", parent="1")
        _geo(wsh, x=PX, y=cur_y, w=900, h=26)
        cur_y += 32

        seg_cx = PX; seg_cy = cur_y; scol = 0; srow_max = 0

        for subnet, hosts in sorted(wired_by_subnet.items()):
            n_hosts  = len(hosts)
            seg_h    = WIRED_H0 + n_hosts * (HOST_H + HOST_PAD) + HOST_PAD
            seg_id   = cid()
            sc = _cell(g, id=seg_id,
                       value=f"<b>Subnet {xs(subnet)}</b>",
                       style=(f"swimlane;startSize=28;fillColor={WIRED_FILL};"
                              f"strokeColor={WIRED_STR};strokeWidth=1.5;"
                              f"fontColor={WIRED_STR};fontSize=10;fontStyle=1;"
                              "rounded=1;arcSize=3;html=1;"),
                       vertex="1", parent="1")
            _geo(sc, x=seg_cx, y=seg_cy, w=WIRED_W, h=seg_h)

            for hi, host in enumerate(sorted(hosts, key=lambda h: h["ip"])):
                ip      = host["ip"]
                macs    = host["macs"]
                hn      = host["hostname"]
                os_g    = host["os_guess"]
                anomaly = host["anomaly"]

                top = xs(hn or ip)
                bot_parts = []
                if hn:
                    bot_parts.append(ip)
                for m in macs[:2]:
                    bot_parts.append(m)
                if len(macs) > 2:
                    bot_parts.append(f"+{len(macs)-2}")
                bot = xs(" | ".join(bot_parts))

                hfill  = ANOMALY_FILL if anomaly else WIRED_FILL
                hstroke = ANOMALY_STR if anomaly else WIRED_STR
                anom_txt = ("<br/><font style='font-size:8px;color:#b85450;'>"
                            "&#9888; ARP anomaly!</font>") if anomaly else ""

                hval = (f"<b>{'&#9888; ' if anomaly else ''}{top}</b>"
                        + anom_txt
                        + (f"<br/><font style='font-size:8px;color:#444;'>"
                           f"{bot}</font>" if bot else ""))
                htip = (f"IP: {xs(ip)}\nMAC(s): {xs(', '.join(macs))}"
                        f"\nHostname: {xs(hn or 'unknown')}\nOS: {xs(os_g)}"
                        + ("\n&#9888; ARP ANOMALY — possible MITM!" if anomaly else ""))

                hshape = (SHAPE_SERVER if host["role"] == "server" else SHAPE_PC)
                hn_node = _cell(g, id=cid(), value=hval, tooltip=htip,
                                style=(f"{hshape}fillColor={hfill};"
                                       f"strokeColor={hstroke};"
                                       "verticalLabelPosition=right;verticalAlign=middle;"
                                       "labelPosition=right;align=left;"
                                       "fontSize=9;html=1;"),
                                vertex="1", parent=seg_id)
                _geo(hn_node, x=HOST_PAD,
                     y=WIRED_H0 + hi * (HOST_H + HOST_PAD),
                     w=44, h=38)

            srow_max = max(srow_max, seg_h)
            scol += 1
            if scol >= SEGS_ROW:
                seg_cx = PX; seg_cy += srow_max + SEG_GAPY
                srow_max = 0; scol = 0
            else:
                seg_cx += WIRED_W + SEG_GAPX

    # ── Render to XML ─────────────────────────────────────────────────────────
    raw_xml = ET.tostring(root, encoding="unicode")
    # Final safety pass: strip any XML-illegal control characters that
    # may have survived from packet data (e.g. null bytes in malformed SSIDs).
    raw_xml = raw_xml.translate(_illegal_xml)
    return minidom.parseString(raw_xml).toprettyxml(indent="  ")

