"""802.11 Wi-Fi frame parsing — SSIDs, clients, APs, probe requests, deauth events."""

import struct

# ─────────────────────────────────────────────────────────────────────────────
# 802.11 Wi-Fi frame parser — SSIDs, clients, APs, probe requests
# ─────────────────────────────────────────────────────────────────────────────

def extract_wifi_events(packets):
    """
    Parse 802.11 management frames (link-type 127 = RADIOTAP, or raw 802.11).
    Extracts:
      • Beacon frames      → AP BSSID, SSID, channel, capabilities, rates
      • Probe Requests     → client MAC, requested SSID (or wildcard)
      • Probe Responses    → AP BSSID, SSID, responding to client
      • Association Req/Resp → client↔AP association
      • Deauthentication   → reason code (useful: detect deauth attacks)
      • Authentication     → open/shared key sequence

    Returns dict with keys:
      "aps"      → list of AP dicts  {bssid, ssid, channel, enc, rates, clients}
      "clients"  → list of client dicts  {mac, probed_ssids, associated_bssid}
      "events"   → list of event dicts   {type, src_mac, dst_mac, bssid, ssid, ...}
    """
    # Frame type/subtype constants
    MGMT   = 0x00
    SUBTYPE = {
        0x00: "Association Request",
        0x01: "Association Response",
        0x02: "Reassociation Request",
        0x03: "Reassociation Response",
        0x04: "Probe Request",
        0x05: "Probe Response",
        0x08: "Beacon",
        0x0A: "Disassociation",
        0x0B: "Authentication",
        0x0C: "Deauthentication",
    }

    DEAUTH_REASONS = {
        1: "Unspecified", 2: "Previous auth no longer valid",
        3: "Leaving BSS", 4: "Inactivity", 5: "AP overloaded",
        6: "Class 2 frame from non-auth STA",
        7: "Class 3 frame from non-assoc STA",
        8: "Leaving BSS (re-assoc)", 9: "STA not authenticated",
        14: "MIC failure (TKIP)", 15: "4-way handshake timeout",
        16: "Group key handshake timeout", 17: "IE mismatch",
        23: "IEEE 802.1X auth failed",
    }

    def _mac_str(b):
        if len(b) < 6: return "??:??:??:??:??:??"
        return ":".join(f"{x:02x}" for x in b[:6])

    def _parse_ie(payload, offset):
        """
        Parse 802.11 Information Elements starting at offset.
        Returns dict: {ssid, channel, rates, enc, ht_cap, rsn, wpa}
        """
        result = {"ssid": "", "channel": 0, "rates": [], "enc": "Open",
                  "rsn": False, "wpa": False, "wps": False}
        while offset + 2 <= len(payload):
            ie_id  = payload[offset]
            ie_len = payload[offset + 1]
            offset += 2
            if offset + ie_len > len(payload):
                break
            ie_data = payload[offset:offset + ie_len]
            offset += ie_len

            if ie_id == 0:                  # SSID
                try:
                    result["ssid"] = ie_data.decode("utf-8", errors="replace")
                except Exception:
                    result["ssid"] = ie_data.hex()

            elif ie_id == 3 and ie_len >= 1:  # DS Parameter Set (channel)
                result["channel"] = ie_data[0]

            elif ie_id == 1 or ie_id == 50:   # Supported/Extended Rates
                rates = []
                for b in ie_data:
                    rate = (b & 0x7F) * 0.5
                    rates.append(f"{rate:.0f}")
                result["rates"].extend(rates)

            elif ie_id == 48:               # RSN (WPA2/WPA3)
                # RSN IE layout (IEEE 802.11-2020):
                #   [0:2]  Version (2)
                #   [2:6]  Group Cipher Suite (4)
                #   [6:8]  Pairwise Cipher Count (2)
                #   [8:8+cnt*4]  Pairwise Cipher Suite List
                #   [8+cnt*4:8+cnt*4+2]  AKM Suite Count (2)
                #   then AKM Suite List
                result["rsn"] = True
                result["enc"] = "WPA2"
                if ie_len >= 8:
                    pcnt = struct.unpack("<H", ie_data[6:8])[0]
                    akm_off = 8 + pcnt * 4          # start of AKM count field
                    if akm_off + 2 <= ie_len:
                        akm_cnt = struct.unpack("<H", ie_data[akm_off:akm_off+2])[0]
                        for i in range(min(akm_cnt, 8)):  # cap to avoid runaway
                            off2 = akm_off + 2 + i * 4
                            if off2 + 4 <= ie_len:
                                akm_type = ie_data[off2 + 3]
                                if akm_type in (8, 9, 18):   # SAE / OWE = WPA3
                                    result["enc"] = "WPA3"
                                elif akm_type in (1, 2) and result["enc"] != "WPA3":
                                    result["enc"] = "WPA2"
                                elif akm_type in (3, 4):     # FT variants
                                    if result["enc"] != "WPA3":
                                        result["enc"] += "+FT"

            elif ie_id == 221 and ie_data[:4] == bytes([0x00, 0x50, 0xF2, 0x01]):
                result["wpa"] = True  # WPA1 vendor IE
                if result["enc"] == "Open":
                    result["enc"] = "WPA"

            elif ie_id == 221 and ie_data[:4] == bytes([0x00, 0x50, 0xF2, 0x04]):
                result["wps"] = True   # WPS vendor IE

        result["rates"] = sorted(set(result["rates"]), key=float)
        return result

    aps      = {}   # bssid → ap dict
    clients  = {}   # mac → client dict
    events   = []

    for p in packets:
        # Only packets dissected from an actual 802.11/radiotap link type are
        # tagged "_wifi" — skip everything else (e.g. Ethernet/IP frames whose
        # _raw_frame would otherwise be misread as bogus 802.11 management
        # frames, producing garbage SSIDs/MACs).
        if not p.get("_wifi"):
            continue

        raw = p.get("_raw_frame", b"")
        if not raw:
            continue

        # Handle Radiotap header (link-type 127)
        radiotap_len = 0
        if len(raw) >= 4 and struct.unpack("<H", raw[2:4])[0] >= 8:
            # Radiotap: version=0, pad=0, len at offset 2
            ver = raw[0]
            if ver == 0:
                try:
                    radiotap_len = struct.unpack("<H", raw[2:4])[0]
                except Exception:
                    pass

        dot11 = raw[radiotap_len:]
        if len(dot11) < 10:
            continue

        fc     = struct.unpack("<H", dot11[0:2])[0]
        ftype  = (fc >> 2) & 0x03
        fsub   = (fc >> 4) & 0x0F

        if ftype != MGMT:
            continue   # only management frames for now

        subtype_name = SUBTYPE.get(fsub, f"Mgmt-{fsub:#x}")

        # Extract addresses (offsets 4, 10, 16 in 802.11 header)
        if len(dot11) < 24:
            continue
        duration = struct.unpack("<H", dot11[2:4])[0]
        addr1 = _mac_str(dot11[4:10])    # destination
        addr2 = _mac_str(dot11[10:16])   # source / transmitter
        addr3 = _mac_str(dot11[16:22])   # BSSID
        seq   = struct.unpack("<H", dot11[22:24])[0]
        body  = dot11[24:]

        ts_us = p.get("ts_us", 0)

        if fsub == 0x08 or fsub == 0x05:  # Beacon or Probe Response
            if len(body) < 12:
                continue
            # Fixed parameters: Timestamp(8), Beacon Interval(2), Capability(2)
            cap_info = struct.unpack("<H", body[10:12])[0]
            ie_info  = _parse_ie(body, 12)
            bssid    = addr2   # transmitter = AP in beacon
            ssid     = ie_info["ssid"]
            channel  = ie_info["channel"]
            enc      = ie_info["enc"]
            wps      = ie_info["wps"]

            if bssid not in aps:
                aps[bssid] = {
                    "bssid": bssid, "ssid": ssid, "channel": channel,
                    "enc": enc, "wps": wps,
                    "rates": ", ".join(ie_info["rates"]) + " Mbps",
                    "clients": set(), "probe_responses": 0, "beacons": 0,
                }
            ap = aps[bssid]
            if ssid and not ap["ssid"]: ap["ssid"] = ssid
            if channel:                 ap["channel"] = channel
            if enc != "Open":           ap["enc"] = enc
            if wps:                     ap["wps"] = True
            if fsub == 0x08:            ap["beacons"] += 1
            else:                       ap["probe_responses"] += 1

            events.append(dict(
                frame_type  = subtype_name,
                src_mac     = bssid,
                dst_mac     = addr1,
                bssid       = addr3,
                ssid        = ssid,
                channel     = channel,
                enc         = enc,
                detail      = f"ch={channel} enc={enc}" + (" WPS!" if wps else ""),
                ts_us       = ts_us,
            ))

        elif fsub == 0x04:  # Probe Request
            ie_info = _parse_ie(body, 0)
            ssid    = ie_info["ssid"]   # empty = wildcard
            client_mac = addr2

            if client_mac not in clients:
                clients[client_mac] = {
                    "mac": client_mac, "probed_ssids": set(),
                    "associated_bssid": "", "assoc_ssid": "",
                }
            cl = clients[client_mac]
            if ssid:
                cl["probed_ssids"].add(ssid)

            events.append(dict(
                frame_type  = "Probe Request",
                src_mac     = client_mac,
                dst_mac     = "ff:ff:ff:ff:ff:ff",
                bssid       = addr3,
                ssid        = ssid or "(wildcard)",
                channel     = 0,
                enc         = "",
                detail      = f"Probing: {ssid or 'any'!r}",
                ts_us       = ts_us,
            ))

        elif fsub in (0x00, 0x02):  # Association / Reassociation Request
            ie_info    = _parse_ie(body, 4)   # skip cap+listen interval
            client_mac = addr2
            bssid      = addr3
            ssid       = ie_info["ssid"]

            if client_mac not in clients:
                clients[client_mac] = {"mac": client_mac, "probed_ssids": set(),
                                        "associated_bssid": "", "assoc_ssid": ""}
            clients[client_mac]["associated_bssid"] = bssid
            clients[client_mac]["assoc_ssid"]       = ssid

            if bssid in aps:
                aps[bssid]["clients"].add(client_mac)

            events.append(dict(
                frame_type  = "Association Request",
                src_mac     = client_mac,
                dst_mac     = addr1,
                bssid       = bssid,
                ssid        = ssid,
                channel     = 0,
                enc         = "",
                detail      = f"{client_mac} → {ssid!r}",
                ts_us       = ts_us,
            ))

        elif fsub == 0x0C:  # Deauthentication
            reason_code = struct.unpack("<H", body[0:2])[0] if len(body) >= 2 else 0
            reason_str  = DEAUTH_REASONS.get(reason_code, f"Reason {reason_code}")
            events.append(dict(
                frame_type  = "Deauthentication",
                src_mac     = addr2,
                dst_mac     = addr1,
                bssid       = addr3,
                ssid        = "",
                channel     = 0,
                enc         = "",
                detail      = f"Reason: {reason_str}",
                ts_us       = ts_us,
            ))

        elif fsub == 0x0A:  # Disassociation
            reason_code = struct.unpack("<H", body[0:2])[0] if len(body) >= 2 else 0
            reason_str  = DEAUTH_REASONS.get(reason_code, f"Reason {reason_code}")
            events.append(dict(
                frame_type  = "Disassociation",
                src_mac     = addr2,
                dst_mac     = addr1,
                bssid       = addr3,
                ssid        = "",
                channel     = 0,
                enc         = "",
                detail      = f"Reason: {reason_str}",
                ts_us       = ts_us,
            ))

    # Convert client set→list for JSON-ability
    for ap in aps.values():
        ap["clients"] = sorted(ap["clients"])

    return {
        "aps":     sorted(aps.values(),     key=lambda x: x["ssid"]),
        "clients": sorted(clients.values(), key=lambda x: x["mac"]),
        "events":  events,
    }

