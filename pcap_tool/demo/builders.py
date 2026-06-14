"""Byte-level packet/pcap builders used to construct synthetic captures.

These are deliberately minimal, hand-rolled (`struct.pack`-based) frame
builders — no scapy/dpkt dependency. They're used by the pytest suite
(via `tests/conftest.py`) and by `pcap_tool.demo.scenario` to build the
"download a sample capture" demo files served from the web dashboard.
"""

import socket
import struct


# ── Ethernet / IP / transport frame builders ────────────────────────────────

def eth_frame(dst_mac="aa:aa:aa:aa:aa:aa", src_mac="bb:bb:bb:bb:bb:bb",
               ethertype=0x0800, payload=b""):
    def mac_bytes(m):
        return bytes(int(x, 16) for x in m.split(":"))
    return mac_bytes(dst_mac) + mac_bytes(src_mac) + struct.pack(">H", ethertype) + payload


def ipv4_packet(src_ip, dst_ip, proto, payload, ttl=64):
    total_len = 20 + len(payload)
    hdr = struct.pack(">BBHHHBBH4s4s",
                       0x45, 0, total_len, 0, 0x4000, ttl, proto, 0,
                       socket.inet_aton(src_ip), socket.inet_aton(dst_ip))
    return hdr + payload


def tcp_segment(sport, dport, payload=b"", flags=0x18, win=8192, seq=1, ack=1):
    # data offset = 5 (20-byte header, no options)
    hdr = struct.pack(">HHIIBBHHH", sport, dport, seq, ack, (5 << 4), flags, win, 0, 0)
    return hdr + payload


def udp_segment(sport, dport, payload=b""):
    length = 8 + len(payload)
    hdr = struct.pack(">HHHH", sport, dport, length, 0)
    return hdr + payload


def icmp_packet(icmp_type, code, payload=b"", seq=1, ident=1):
    hdr = struct.pack(">BBHHH", icmp_type, code, 0, ident, seq)
    return hdr + payload


def arp_packet(sender_mac, sender_ip, target_mac, target_ip, op=1):
    def mac_bytes(m):
        return bytes(int(x, 16) for x in m.split(":"))
    return struct.pack(">HHBBH", 1, 0x0800, 6, 4, op) + \
        mac_bytes(sender_mac) + socket.inet_aton(sender_ip) + \
        mac_bytes(target_mac) + socket.inet_aton(target_ip)


def eth_ip_tcp(src_mac, dst_mac, src_ip, dst_ip, sport, dport, payload=b"",
               flags=0x18, ttl=64):
    return eth_frame(dst_mac, src_mac, 0x0800,
                      ipv4_packet(src_ip, dst_ip, 6, tcp_segment(sport, dport, payload, flags), ttl))


def eth_ip_udp(src_mac, dst_mac, src_ip, dst_ip, sport, dport, payload=b"", ttl=64):
    return eth_frame(dst_mac, src_mac, 0x0800,
                      ipv4_packet(src_ip, dst_ip, 17, udp_segment(sport, dport, payload), ttl))


def eth_ip_icmp(src_mac, dst_mac, src_ip, dst_ip, icmp_type, code=0, payload=b"", seq=1, ttl=64):
    return eth_frame(dst_mac, src_mac, 0x0800,
                      ipv4_packet(src_ip, dst_ip, 1, icmp_packet(icmp_type, code, payload, seq), ttl))


def eth_arp(src_mac, dst_mac, sender_mac, sender_ip, target_mac, target_ip, op=1):
    return eth_frame(dst_mac, src_mac, 0x0806,
                      arp_packet(sender_mac, sender_ip, target_mac, target_ip, op))


# ── DNS query / response builders ───────────────────────────────────────────

def dns_question(name, qtype=1, qclass=1):
    qname = b"".join(bytes([len(label)]) + label.encode() for label in name.split(".")) + b"\x00"
    return qname + struct.pack(">HH", qtype, qclass)


def dns_query_frame(src_mac, dst_mac, src_ip, dst_ip, sport, qname,
                     txid=0x1234, dport=53, qtype=1):
    """A DNS query (QR=0) for `qname`, wrapped in Ethernet/IP/UDP."""
    hdr = struct.pack(">HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    payload = hdr + dns_question(qname, qtype=qtype)
    return eth_ip_udp(src_mac, dst_mac, src_ip, dst_ip, sport, dport, payload)


def dns_response_frame(src_mac, dst_mac, src_ip, dst_ip, sport, dport, qname,
                        txid=0x1234, rcode=0, answer_ip=None, ttl=300):
    """A DNS response, wrapped in Ethernet/IP/UDP.

    `sport`/`dport` are the DNS server's source port (53) and the original
    client port respectively. If `rcode == 0` and `answer_ip` is given, a
    single A-record answer is included; otherwise ANCOUNT=0 (e.g. NXDOMAIN).
    """
    question = dns_question(qname)
    if rcode == 0 and answer_ip:
        ancount = 1
        answer = (b"\xc0\x0c" + struct.pack(">HH", 1, 1) + struct.pack(">I", ttl)
                  + struct.pack(">H", 4) + socket.inet_aton(answer_ip))
    else:
        ancount = 0
        answer = b""
    flags = 0x8180 | (rcode & 0x000F)
    hdr = struct.pack(">HHHHHH", txid, flags, 1, ancount, 0, 0)
    payload = hdr + question + answer
    return eth_ip_udp(src_mac, dst_mac, src_ip, dst_ip, sport, dport, payload)


# ── 802.11 / radiotap WiFi frame builders ───────────────────────────────────

def _mac_bytes(m):
    return bytes(int(x, 16) for x in m.split(":"))


def wifi_beacon_frame(ssid, bssid="aa:bb:cc:dd:ee:ff", channel=6):
    """A radiotap-wrapped 802.11 Beacon frame advertising `ssid`."""
    radiotap = struct.pack("<BBHI", 0, 0, 8, 0)
    fc = struct.pack("<H", 0x0080)  # mgmt, beacon
    bcast = b"\xff" * 6
    bssid_b = _mac_bytes(bssid)
    mac_hdr = fc + b"\x00\x00" + bcast + bssid_b + bssid_b + b"\x00\x00"
    fixed = b"\x00" * 8 + struct.pack("<H", 100) + struct.pack("<H", 0x0421)
    ssid_b = ssid.encode()
    ssid_ie = bytes([0, len(ssid_b)]) + ssid_b
    ds_ie = bytes([3, 1, channel])
    return radiotap + mac_hdr + fixed + ssid_ie + ds_ie


def wifi_deauth_frame(client_mac, bssid="aa:bb:cc:dd:ee:ff", reason=7):
    """A radiotap-wrapped 802.11 Deauthentication frame from `bssid` to
    `client_mac` with the given reason code."""
    radiotap = struct.pack("<BBHI", 0, 0, 8, 0)
    fc = struct.pack("<H", 0x00C0)  # mgmt, deauthentication
    bssid_b = _mac_bytes(bssid)
    client_b = _mac_bytes(client_mac)
    mac_hdr = fc + b"\x00\x00" + client_b + bssid_b + bssid_b + b"\x00\x00"
    body = struct.pack("<H", reason)
    return radiotap + mac_hdr + body


# ── PCAP file builders ───────────────────────────────────────────────────────

def pcap_bytes(frames, endian="<", nanosecond=False, ltype=1):
    """Build a classic (non-pcapng) .pcap file from a list of frames.

    Each item in `frames` is either raw frame `bytes` (recorded with
    timestamp 0,0) or a `(ts_sec, ts_usec, frame_bytes)` tuple for explicit
    per-frame timestamps (needed e.g. to build evenly-spaced "beaconing"
    traffic).
    """
    magic = {
        ("<", False): 0xA1B2C3D4,
        (">", False): 0xD4C3B2A1,
        ("<", True):  0xA1B23C4D,
        (">", True):  0x4D3CB2A1,
    }[(endian, nanosecond)]
    hdr = struct.pack(endian + "IHHiIII", magic, 2, 4, 0, 0, 65535, ltype)
    out = hdr
    for item in frames:
        if isinstance(item, tuple):
            ts_sec, ts_usec, frame = item
        else:
            ts_sec, ts_usec, frame = 0, 0, item
        out += struct.pack(endian + "IIII", ts_sec, ts_usec, len(frame), len(frame))
        out += frame
    return out


def write_pcap(path, frames, **kwargs):
    with open(path, "wb") as f:
        f.write(pcap_bytes(frames, **kwargs))
    return str(path)


# ── ASN.1 DER helpers for synthetic X.509 certificates ──────────────────────

def _asn1_len(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def asn1_tlv(tag, value):
    return bytes([tag]) + _asn1_len(len(value)) + value


def asn1_oid(dotted):
    parts = [int(x) for x in dotted.split(".")]
    first = parts[0] * 40 + parts[1]
    out = [first]
    for p in parts[2:]:
        if p == 0:
            out.append(0)
            continue
        chunk = []
        while p:
            chunk.insert(0, p & 0x7F)
            p >>= 7
        for i in range(len(chunk) - 1):
            chunk[i] |= 0x80
        out.extend(chunk)
    return asn1_tlv(0x06, bytes(out))


def _rdn(oid, value):
    atv = asn1_oid(oid) + asn1_tlv(0x0C, value.encode())
    return asn1_tlv(0x31, asn1_tlv(0x30, atv))


def _name(cn):
    return asn1_tlv(0x30, _rdn("2.5.4.3", cn))


def _utctime(dt):
    return asn1_tlv(0x17, dt.strftime("%y%m%d%H%M%SZ").encode())


def _validity(not_before, not_after):
    return asn1_tlv(0x30, _utctime(not_before) + _utctime(not_after))


def _rsa_pubkey_info(n_bytes, e_bytes=b"\x01\x00\x01"):
    rsa_seq = asn1_tlv(0x30, asn1_tlv(0x02, n_bytes) + asn1_tlv(0x02, e_bytes))
    bitstring = asn1_tlv(0x03, b"\x00" + rsa_seq)
    alg = asn1_tlv(0x30, asn1_oid("1.2.840.113549.1.1.1") + asn1_tlv(0x05, b""))
    return asn1_tlv(0x30, alg + bitstring)


def make_certificate_der(subject_cn, issuer_cn, not_before, not_after,
                          key_bits=2048, sans=None):
    """Build a structurally-valid (but not cryptographically signed) DER X.509
    certificate, for exercising the hand-rolled ASN.1 parser in
    extractors/tls.py without a `cryptography` dependency."""
    n_len = key_bits // 8
    n_bytes = bytes([0x80]) + b"\xff" * (n_len - 1)   # MSB set -> key_bits exactly
    serial = asn1_tlv(0x02, b"\x01")
    sig_alg = asn1_tlv(0x30, asn1_oid("1.2.840.113549.1.1.11"))
    issuer = _name(issuer_cn)
    validity = _validity(not_before, not_after)
    subject = _name(subject_cn)
    spki = _rsa_pubkey_info(n_bytes)
    body = serial + sig_alg + issuer + validity + subject + spki
    if sans:
        san_seq = b"".join(asn1_tlv(0x82, s.encode()) for s in sans)
        ext_value = asn1_tlv(0x30, san_seq)
        ext = asn1_tlv(0x30, asn1_oid("2.5.29.17") + asn1_tlv(0x04, ext_value))
        exts = asn1_tlv(0x30, ext)
        body += asn1_tlv(0xA3, exts)
    tbs = asn1_tlv(0x30, body)
    sig_value = asn1_tlv(0x03, b"\x00" + b"\x00" * 16)
    return asn1_tlv(0x30, tbs + sig_alg + sig_value)


# ── TLS record / handshake builders ──────────────────────────────────────────

def tls_client_hello_record(sni_host=None):
    exts = b""
    if sni_host:
        host = sni_host.encode()
        sni_ext = (struct.pack(">H", 0)
                   + struct.pack(">H", 2 + 1 + 2 + len(host))
                   + struct.pack(">H", 1 + 2 + len(host))
                   + b"\x00" + struct.pack(">H", len(host)) + host)
        exts += sni_ext
    ch_body = (struct.pack(">H", 0x0303) + b"\x00" * 32 + b"\x00"
               + struct.pack(">H", 2) + struct.pack(">H", 0x1301)
               + b"\x01" + b"\x00"
               + struct.pack(">H", len(exts)) + exts)
    hs = b"\x01" + struct.pack(">I", len(ch_body))[1:] + ch_body
    return b"\x16" + b"\x03\x03" + struct.pack(">H", len(hs)) + hs


def tls_certificate_record(der_certs):
    cert_list = b"".join(struct.pack(">I", len(d))[1:] + d for d in der_certs)
    body = struct.pack(">I", len(cert_list))[1:] + cert_list
    hs = b"\x0b" + struct.pack(">I", len(body))[1:] + body
    return b"\x16" + b"\x03\x03" + struct.pack(">H", len(hs)) + hs


# ── EAPOL/EAP-TLS frame builder ───────────────────────────────────────────────

def eapol_eap_tls_frame(src_mac, dst_mac, tls_bytes, eap_type=13, code=1, ident=1):
    """Build an Ethernet frame carrying a single-fragment EAPOL/EAP-TLS message
    (no "more fragments" / length-included flags)."""
    type_data = b"\x00" + tls_bytes   # flags byte = 0
    eap_body = struct.pack(">BBH", code, ident, 5 + len(type_data)) + bytes([eap_type]) + type_data
    eapol = struct.pack(">BBH", 1, 0, len(eap_body)) + eap_body
    return eth_frame(dst_mac, src_mac, 0x888E, eapol)


# ── PCAPNG file builders ─────────────────────────────────────────────────────

def _pcapng_block(btype, body):
    blen = 12 + len(body)   # 8-byte header (type+totallen) + body + 4-byte trailing totallen
    return struct.pack("<II", btype, blen) + body + struct.pack("<I", blen)


def pcapng_bytes(frames, ltype=1):
    """Build a minimal pcapng file: SHB + IDB + one EPB per frame."""
    out = b""
    # Section Header Block (SHB)
    shb_body = struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)
    out += _pcapng_block(0x0A0D0D0A, shb_body)

    # Interface Description Block (IDB)
    idb_body = struct.pack("<HH", ltype, 0) + struct.pack("<I", 65535)
    out += _pcapng_block(0x00000001, idb_body)

    # Enhanced Packet Blocks (EPB)
    for frame in frames:
        padded_len = (len(frame) + 3) & ~3
        padded = frame + b"\x00" * (padded_len - len(frame))
        body = struct.pack("<IIIII", 0, 0, 0, len(frame), len(frame)) + padded
        out += _pcapng_block(0x00000006, body)

    return out


def write_pcapng(path, frames, ltype=1):
    with open(path, "wb") as f:
        f.write(pcapng_bytes(frames, ltype=ltype))
    return str(path)
