"""PCAP / PCAPng file parsing and packet dissection."""

import struct, socket

from .constants import (
    ETH_TYPE_IP, ETH_TYPE_IP6, ETH_TYPE_ARP, ETH_TYPE_EAPOL,
    PROTO_TCP, PROTO_UDP, PROTO_ICMP, PROTO_ICMP6,
    WELL_KNOWN, HTTP_PORTS,
)

# ─────────────────────────────────────────────────────────────────────────────
# PCAP / PCAPng parser
# ─────────────────────────────────────────────────────────────────────────────

def parse_pcap(path):
    """Yield enriched packet dicts."""
    with open(path, "rb") as f:
        magic_bytes = f.read(4)
        if len(magic_bytes) < 4:
            return

        # Detect byte order from raw magic bytes (RFC-correct approach).
        # A correctly-formed PCAP file starts with:
        #   A1 B2 C3 D4  → native/little-endian
        #   A1 B2 3C 4D  → native/little-endian, nanosecond timestamps
        #   D4 C3 B2 A1  → big-endian  (or malformed LE written with wrong pack fmt)
        #   4D 3C B2 A1  → big-endian, nanosecond timestamps
        #   0A 0D 0D 0A  → PCAPng
        _LE_MAGIC    = b"\xa1\xb2\xc3\xd4"
        _LE_NS_MAGIC = b"\xa1\xb2\x3c\x4d"
        _BE_MAGIC    = b"\xd4\xc3\xb2\xa1"
        _BE_NS_MAGIC = b"\x4d\x3c\xb2\xa1"
        _NG_MAGIC    = b"\x0a\x0d\x0d\x0a"

        if magic_bytes in (_LE_MAGIC, _LE_NS_MAGIC):
            endian = "<"
        elif magic_bytes == _NG_MAGIC:
            yield from _parse_pcapng(path)
            return
        elif magic_bytes in (_BE_MAGIC, _BE_NS_MAGIC):
            # Validate by checking version field: PCAP version is always 2.4.
            # Some tools incorrectly write the BE magic bytes but store all
            # fields in little-endian order (a common libpcap bug on LE hosts).
            # If the version reads as (2, 4) in LE but nonsense in BE, treat as LE.
            rest4 = f.read(4)       # version major + minor (2+2 bytes)
            if len(rest4) >= 4:
                vmaj_le, vmin_le = struct.unpack("<HH", rest4)
                vmaj_be, vmin_be = struct.unpack(">HH", rest4)
                if vmaj_le in (1, 2) and vmin_le in (0, 4):
                    endian = "<"    # version sane as LE → file is actually LE
                elif vmaj_be in (1, 2) and vmin_be in (0, 4):
                    endian = ">"    # version sane as BE → genuinely big-endian
                else:
                    endian = "<"    # fallback: assume LE (most common)
                # Re-open to rewind — simpler than tracking position
                f.seek(4)          # skip magic, re-read from after magic
            else:
                endian = "<"
        else:
            raise ValueError(f"Unrecognised PCAP magic: {magic_bytes.hex()}")
        rest = f.read(20)
        # Link type is at bytes 20-23 of global header (index 16-19 of this 20-byte chunk)
        ltype = 1   # default: Ethernet
        if len(rest) >= 20:
            try:
                ltype = struct.unpack(endian + "I", rest[16:20])[0]
            except Exception:
                pass
        while True:
            rec = f.read(16)
            if len(rec) < 16:
                break
            _, ts_us, incl_len, _ = struct.unpack(endian + "IIII", rec)
            raw = f.read(incl_len)
            r = _dissect(raw, ltype, ts_us)
            if r:
                yield r


def _parse_pcapng(path):
    with open(path, "rb") as f:
        endian = "<"
        ltypes = {}
        while True:
            hdr = f.read(8)
            if len(hdr) < 8:
                break
            btype, blen = struct.unpack(endian + "II", hdr)
            body = f.read(blen - 12)
            f.read(4)
            if btype == 0x0A0D0D0A:
                endian = "<" if struct.unpack("<I", body[:4])[0] == 0x1A2B3C4D else ">"
            elif btype == 0x00000001:
                ltypes[len(ltypes)] = struct.unpack(endian + "H", body[:2])[0]
            elif btype == 0x00000006:
                iid = struct.unpack(endian + "I", body[:4])[0]
                ts_hi, ts_lo, cap_len, _ = struct.unpack(endian + "IIII", body[4:20])
                r = _dissect(body[20:20+cap_len], ltypes.get(iid,1), ts_lo)
                if r: yield r
            elif btype == 0x00000003:
                cap_len = struct.unpack(endian+"I", body[:4])[0]
                r = _dissect(body[4:4+cap_len], ltypes.get(0,1), 0)
                if r: yield r


def _mac(b):
    return ":".join(f"{x:02x}" for x in b)


def _dissect(raw, ltype, ts_us=0):
    try:
        smac = dmac = "ff:ff:ff:ff:ff:ff"
        vlan_id = None  # populated for 802.1Q tagged Ethernet frames

        # ── 802.11 / Wi-Fi link types ─────────────────────────────────────
        # ltype 127 = LINKTYPE_IEEE802_11_RADIOTAP
        # ltype 105 = LINKTYPE_IEEE802_11 (raw, no radiotap)
        if ltype in (105, 127):
            # Must have at least some bytes to be meaningful
            if not raw:
                return None
            # 802.1X/EAP-TLS over Wi-Fi: an unencrypted Data frame carrying an
            # EAPOL LLC/SNAP payload — short-circuit to an EAPOL packet dict
            # so extract_eap_tls_streams() can reassemble the TLS handshake.
            eapol = _dissect_80211_eapol(raw, ltype, ts_us)
            if eapol:
                return eapol
            # Return a synthetic "wifi" packet that extract_wifi_events can read
            return dict(src_ip="", dst_ip="", src_mac="", dst_mac="",
                        src_port=0, dst_port=0, proto="WiFi-802.11",
                        length=len(raw), resource="", ttl=None, ts_us=ts_us,
                        win_size=0, app_payload=b"",
                        arp_sender_mac=None, arp_sender_ip=None,
                        _raw_frame=raw, _wifi=True)

        if ltype == 1:
            if len(raw) < 14: return None
            dmac  = _mac(raw[0:6])
            smac  = _mac(raw[6:12])
            etype = struct.unpack(">H", raw[12:14])[0]
            off   = 14
            vlan_id = None
            while etype in (0x8100, 0x88A8, 0x9100) and off+4 <= len(raw):
                # 802.1Q / QinQ: TCI[0:12] = VLAN ID (12 bits, lower 12 of 16-bit TCI)
                tci = struct.unpack(">H", raw[off:off+2])[0]
                if vlan_id is None:     # keep outermost (first) VLAN tag only
                    vlan_id = tci & 0x0FFF
                etype = struct.unpack(">H", raw[off+2:off+4])[0]; off += 4
            payload = raw[off:]
        elif ltype in (101,228): etype = ETH_TYPE_IP;  payload = raw
        elif ltype == 229:       return None  # raw IPv6 — excluded
        elif ltype == 113:
            if len(raw) < 16: return None
            etype = struct.unpack(">H", raw[14:16])[0]; payload = raw[16:]
        else:
            return None

        if   etype == ETH_TYPE_IP:  r = _ipv4(payload, ts_us)
        elif etype == ETH_TYPE_IP6: return None   # IPv6 excluded — IPv4 only
        elif etype == ETH_TYPE_ARP: r = _arp(payload)
        elif etype == ETH_TYPE_EAPOL:
            r = dict(src_ip="", dst_ip="", src_mac="", dst_mac="",
                     src_port=0, dst_port=0, proto="EAPOL",
                     length=len(raw), resource="", ttl=None, ts_us=ts_us,
                     win_size=0, app_payload=payload,
                     arp_sender_mac=None, arp_sender_ip=None)
        else: return None

        if r:
            r["src_mac"] = smac
            r["dst_mac"] = dmac
            r["_raw_frame"] = raw   # store for WiFi correlation if needed
            if vlan_id is not None:
                r["vlan_id"] = vlan_id
        return r
    except Exception:
        return None


def _dissect_80211_eapol(raw, ltype, ts_us):
    """
    If `raw` is an unencrypted 802.11 Data frame carrying an EAPOL (802.1X)
    payload over an LLC/SNAP header, return an EAPOL packet dict with
    src_mac/dst_mac taken from the 802.11 transmitter/receiver addresses.
    Otherwise return None (not EAPOL, encrypted, or not a data frame).
    """
    try:
        off = 0
        if ltype == 127:   # radiotap header precedes the 802.11 frame
            if len(raw) < 4:
                return None
            off = struct.unpack("<H", raw[2:4])[0]
        if len(raw) < off + 24:
            return None
        fc0, fc1 = raw[off], raw[off+1]
        ftype   = (fc0 >> 2) & 0x3
        subtype = (fc0 >> 4) & 0xF
        if ftype != 2:        # not a Data frame
            return None
        if fc1 & 0x40:        # Protected Frame bit set — encrypted, can't read LLC
            return None
        hdr_len = 26 if (subtype & 0x8) else 24   # QoS Data frames add a 2-byte QoS field
        if len(raw) < off + hdr_len + 8:
            return None
        addr1 = _mac(raw[off+4:off+10])    # receiver
        addr2 = _mac(raw[off+10:off+16])   # transmitter
        llc = raw[off+hdr_len:off+hdr_len+8]
        if llc[:2] != b"\xaa\xaa":          # DSAP/SSAP for SNAP
            return None
        ethertype = struct.unpack(">H", llc[6:8])[0]
        if ethertype != ETH_TYPE_EAPOL:
            return None
        eapol_bytes = raw[off+hdr_len+8:]
        return dict(src_ip="", dst_ip="", src_mac=addr2, dst_mac=addr1,
                    src_port=0, dst_port=0, proto="EAPOL",
                    length=len(raw), resource="", ttl=None, ts_us=ts_us,
                    win_size=0, app_payload=eapol_bytes,
                    arp_sender_mac=None, arp_sender_ip=None,
                    _raw_frame=raw)
    except Exception:
        return None


def _ipv4(d, ts_us):
    if len(d) < 20: return None
    ihl = (d[0] & 0x0F) * 4
    ttl = d[8]
    r = _transport(socket.inet_ntoa(d[12:16]), socket.inet_ntoa(d[16:20]),
                   d[9], d[ihl:], len(d), ts_us)
    if r: r["ttl"] = ttl
    return r


def _ipv6(d, ts_us):
    if len(d) < 40: return None
    r = _transport(socket.inet_ntop(socket.AF_INET6, d[8:24]),
                   socket.inet_ntop(socket.AF_INET6, d[24:40]),
                   d[6], d[40:], len(d), ts_us)
    if r: r["ttl"] = d[7]  # hop limit
    return r


def _arp(d):
    if len(d) < 28: return None
    return dict(src_ip=socket.inet_ntoa(d[14:18]),
                dst_ip=socket.inet_ntoa(d[24:28]),
                src_mac="", dst_mac="",
                src_port=0, dst_port=0, proto="ARP",
                length=len(d), resource="", ttl=None,
                ts_us=0, win_size=0, app_payload=b"",
                # ARP: capture sender MAC for ARP anomaly detection
                arp_sender_mac=_mac(d[8:14]),
                arp_sender_ip=socket.inet_ntoa(d[14:18]))


def _transport(src, dst, proto, data, pkt_len, ts_us):
    sp = dp = win = 0
    resource = ""
    app_payload = b""
    if proto == PROTO_TCP:
        name = "TCP"
        if len(data) >= 4:
            sp, dp = struct.unpack(">HH", data[:4])
            name = WELL_KNOWN.get(("TCP",dp)) or WELL_KNOWN.get(("TCP",sp)) or "TCP"
        if len(data) >= 14:
            win = struct.unpack(">H", data[14:16])[0]
        tcp_hdr_len = ((data[12] >> 4) * 4) if len(data) > 12 else 20
        app_payload = data[tcp_hdr_len:] if len(data) > tcp_hdr_len else b""
        if dp in HTTP_PORTS or sp in HTTP_PORTS:
            resource = _http_host(app_payload)
    elif proto == PROTO_UDP:
        name = "UDP"
        if len(data) >= 4:
            sp, dp = struct.unpack(">HH", data[:4])
            name = WELL_KNOWN.get(("UDP",dp)) or WELL_KNOWN.get(("UDP",sp)) or "UDP"
        app_payload = data[8:] if len(data) > 8 else b""
    elif proto == PROTO_ICMP:
        name = "ICMP"
        app_payload = data   # full ICMP datagram (type+code+checksum+body)
    elif proto == PROTO_ICMP6: name = "ICMPv6"
    else:                      name = f"IP/{proto}"
    return dict(src_ip=src, dst_ip=dst, src_mac="", dst_mac="",
                src_port=sp, dst_port=dp, proto=name,
                length=pkt_len, resource=resource,
                ttl=None, ts_us=ts_us, win_size=win,
                app_payload=app_payload,
                arp_sender_mac=None, arp_sender_ip=None)


def _http_host(payload):
    try:
        text = payload.decode("ascii", errors="ignore")
        for line in text.split("\r\n"):
            if line.lower().startswith("host:"):
                return line.split(":",1)[1].strip()
    except Exception:
        pass
    return ""


