"""TLS/SSL handshake parsing, X.509 certificate parsing, and TLS session extraction."""

import struct, socket, datetime, hashlib
from collections import defaultdict

# ─────────────────────────────────────────────────────────────────────────────
# TLS constants
# ─────────────────────────────────────────────────────────────────────────────

TLS_VERSIONS = {
    0x0300: "SSLv3",
    0x0301: "TLS 1.0",
    0x0302: "TLS 1.1",
    0x0303: "TLS 1.2",
    0x0304: "TLS 1.3",
}

# Cipher suites — subset covering weak/interesting ones + common ones
CIPHER_SUITES = {
    0x0000: "TLS_NULL_WITH_NULL_NULL",
    0x0001: "TLS_RSA_WITH_NULL_MD5",
    0x0002: "TLS_RSA_WITH_NULL_SHA",
    0x0004: "TLS_RSA_WITH_RC4_128_MD5",
    0x0005: "TLS_RSA_WITH_RC4_128_SHA",
    0x000A: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    0x002F: "TLS_RSA_WITH_AES_128_CBC_SHA",
    0x0033: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
    0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
    0x0039: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
    0x003C: "TLS_RSA_WITH_AES_128_CBC_SHA256",
    0x003D: "TLS_RSA_WITH_AES_256_CBC_SHA256",
    0x009C: "TLS_RSA_WITH_AES_128_GCM_SHA256",
    0x009D: "TLS_RSA_WITH_AES_256_GCM_SHA384",
    0x009E: "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
    0x009F: "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
    0xC009: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
    0xC00A: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
    0xC013: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    0xC014: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    0xC02B: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    0xC02C: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    0xC030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    0xCCA8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    0xCCA9: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    0xCCAA: "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    # TLS 1.3 suites
    0x1301: "TLS_AES_128_GCM_SHA256",
    0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256",
    # SCSV
    0x00FF: "TLS_EMPTY_RENEGOTIATION_INFO_SCSV",
    0x5600: "TLS_FALLBACK_SCSV",
}

WEAK_CIPHERS = {
    "NULL", "RC4", "DES", "EXPORT", "anon", "MD5",
    "RC2", "IDEA", "SEED", "CAMELLIA_128_CBC", "3DES"
}

ALERT_DESCS = {
    0:"close_notify", 10:"unexpected_message", 20:"bad_record_mac",
    21:"decryption_failed", 22:"record_overflow", 30:"decompression_failure",
    40:"handshake_failure", 41:"no_certificate", 42:"bad_certificate",
    43:"unsupported_certificate", 44:"certificate_revoked",
    45:"certificate_expired", 46:"certificate_unknown",
    47:"illegal_parameter", 48:"unknown_ca", 49:"access_denied",
    50:"decode_error", 51:"decrypt_error", 60:"export_restriction",
    70:"protocol_version", 71:"insufficient_security", 80:"internal_error",
    86:"inappropriate_fallback", 90:"user_canceled",
    100:"no_renegotiation", 110:"unsupported_extension",
    112:"unrecognized_name", 113:"bad_certificate_status_response",
    115:"unknown_psk_identity", 116:"certificate_required", 120:"no_application_protocol",
}

TLS_HS_TYPES = {
    0:"HelloRequest", 1:"ClientHello", 2:"ServerHello",
    4:"NewSessionTicket", 8:"EncryptedExtensions",
    11:"Certificate", 12:"ServerKeyExchange",
    13:"CertificateRequest", 14:"ServerHelloDone",
    15:"CertificateVerify", 16:"ClientKeyExchange", 20:"Finished",
}

# Extension types
EXT_SNI       = 0x0000
EXT_ALPN      = 0x0010
EXT_SUPPORTED = 0x002B   # supported_versions (TLS 1.3)
EXT_SIG_ALGS  = 0x000D

# ─────────────────────────────────────────────────────────────────────────────
# ASN.1 / X.509 minimal parser (no external libs)
# ─────────────────────────────────────────────────────────────────────────────

def _asn1_read_len(data, off):
    """Read ASN.1 length at offset. Returns (length, new_offset)."""
    if off >= len(data):
        return 0, off
    b = data[off]; off += 1
    if b < 0x80:
        return b, off
    n = b & 0x7F
    if off + n > len(data):
        return 0, off + n
    ln = int.from_bytes(data[off:off+n], "big")
    return ln, off + n

def _asn1_next(data, off):
    """Read next ASN.1 TLV. Returns (tag, value_bytes, next_offset)."""
    if off + 2 > len(data):
        return 0, b"", off
    tag = data[off]; off += 1
    ln, off = _asn1_read_len(data, off)
    end = off + ln
    val = data[off:end]
    return tag, val, end

def _asn1_seq_children(data):
    """Iterate children of an ASN.1 SEQUENCE/SET body."""
    off = 0
    while off < len(data):
        tag, val, off = _asn1_next(data, off)
        if tag == 0:
            break
        yield tag, val

def _oid_to_str(data):
    """Decode ASN.1 OID bytes to dotted string."""
    if not data:
        return ""
    try:
        oid = [data[0] // 40, data[0] % 40]
        i, cur = 1, 0
        while i < len(data):
            b = data[i]; i += 1
            cur = (cur << 7) | (b & 0x7F)
            if not (b & 0x80):
                oid.append(cur); cur = 0
        return ".".join(str(x) for x in oid)
    except Exception:
        return ""

# Common OID → friendly name
OID_NAMES = {
    "2.5.4.3":  "CN", "2.5.4.6":  "C", "2.5.4.7":  "L",
    "2.5.4.8":  "ST","2.5.4.10": "O", "2.5.4.11": "OU",
    "2.5.4.12": "title", "2.5.29.17": "SAN",
    "1.2.840.113549.1.1.1":  "rsaEncryption",
    "1.2.840.113549.1.1.11": "sha256WithRSAEncryption",
    "1.2.840.10040.4.1": "dsa",
    "1.2.840.10045.2.1": "ecPublicKey",
    "1.3.132.0.34": "secp384r1",
    "1.3.132.0.35": "secp521r1",
    "1.2.840.10045.3.1.7": "secp256r1 (P-256)",
    "1.2.840.10045.3.1.34": "secp384r1 (P-384)",
    "2.5.29.19": "basicConstraints",
    "2.5.29.15": "keyUsage",
    "2.5.29.37": "extKeyUsage",
}

def _parse_dn(data):
    """Parse X.509 Distinguished Name, return dict of RDN components."""
    result = {}
    for tag, rdn_set in _asn1_seq_children(data):
        for _, atv in _asn1_seq_children(rdn_set):
            tag2, oid_bytes, rest = _asn1_next(atv, 0)
            oid = _oid_to_str(oid_bytes)
            name = OID_NAMES.get(oid, oid)
            tag3, val_bytes, _ = _asn1_next(atv, rest - len(atv) + len(oid_bytes) + 2)
            # Reparse properly
            off2 = 0
            _, oid_raw, off2 = _asn1_next(atv, 0)
            oid_str = _oid_to_str(oid_raw)
            fname   = OID_NAMES.get(oid_str, oid_str)
            _, str_raw, _ = _asn1_next(atv, off2)
            try:
                val = str_raw.decode("utf-8", errors="replace").strip()
            except Exception:
                val = str_raw.hex()
            result[fname] = val
    return result

def _parse_utctime(data):
    """Parse ASN.1 UTCTime or GeneralizedTime → datetime or None."""
    try:
        s = data.decode("ascii").strip("\x00")
        if len(s) == 13:   # YYMMDDHHmmssZ
            return datetime.datetime.strptime(s, "%y%m%d%H%M%SZ")
        elif len(s) == 15: # YYYYMMDDHHmmssZ
            return datetime.datetime.strptime(s, "%Y%m%d%H%M%SZ")
    except Exception:
        pass
    return None

def _parse_validity(data):
    """Parse Validity SEQUENCE → (not_before, not_after) as datetime."""
    nb = na = None
    off = 0
    for _ in range(2):
        tag, val, off = _asn1_next(data, off)
        dt = _parse_utctime(val)
        if nb is None: nb = dt
        else:          na = dt
    return nb, na

def _parse_pubkey_info(data):
    """Parse SubjectPublicKeyInfo → (key_type_str, key_size_bits)."""
    try:
        off = 0
        tag, alg_seq, off = _asn1_next(data, 0)   # AlgorithmIdentifier SEQUENCE
        _, oid_bytes, _ = _asn1_next(alg_seq, 0)
        oid = _oid_to_str(oid_bytes)
        alg_name = OID_NAMES.get(oid, oid)

        tag2, bitstring, off2 = _asn1_next(data, off)   # BIT STRING
        key_bytes = bitstring[1:]   # strip unused-bits byte

        if "rsa" in alg_name.lower():
            # RSA key is a SEQUENCE of (n, e)
            _, rsa_seq, _ = _asn1_next(key_bytes, 0)
            _, n_bytes, _ = _asn1_next(rsa_seq, 0)
            key_size = (len(n_bytes) - (1 if n_bytes[0] == 0 else 0)) * 8
            return f"RSA", key_size
        elif "ec" in alg_name.lower():
            # ECDSA — size from curve OID
            _, params, _ = _asn1_next(alg_seq, len(oid_bytes) + 2)
            curve_oid = _oid_to_str(params) if params else ""
            curve_name = OID_NAMES.get(curve_oid, curve_oid)
            bits = 256 if "256" in curve_name else (384 if "384" in curve_name else (521 if "521" in curve_name else 0))
            return f"ECDSA ({curve_name})", bits
        return alg_name, 0
    except Exception:
        return "Unknown", 0

def _parse_extensions(data):
    """Parse certificate extensions body, extract SAN."""
    sans = []
    try:
        off = 0
        while off < len(data):
            tag, ext_seq, off = _asn1_next(data, off)
            if tag == 0: break
            eoff = 0
            _, oid_bytes, eoff = _asn1_next(ext_seq, eoff)
            oid = _oid_to_str(oid_bytes)
            if oid == "2.5.29.17":   # SAN
                # next may be critical bool, then octet string
                tag2, val2, eoff2 = _asn1_next(ext_seq, eoff)
                if tag2 == 0x01:     # boolean (critical flag)
                    tag2, val2, eoff2 = _asn1_next(ext_seq, eoff2)
                # val2 is OCTET STRING containing the SAN SEQUENCE
                _, san_seq, _ = _asn1_next(val2, 0)
                soff = 0
                while soff < len(san_seq):
                    stag, sval, soff = _asn1_next(san_seq, soff)
                    if stag == 0x82:   # dNSName
                        try: sans.append(sval.decode("ascii","replace"))
                        except: pass
                    elif stag == 0x87 and len(sval) == 4:   # iPAddress v4
                        try: sans.append(socket.inet_ntoa(sval))
                        except: pass
    except Exception:
        pass
    return sans

def _parse_certificate(cert_bytes):
    """
    Parse a DER-encoded X.509 certificate.
    Returns dict with subject, issuer, sans, validity, key_type, key_bits.
    """
    result = {
        "subject": "", "issuer": "", "sans": [],
        "not_before": None, "not_after": None,
        "key_type": "Unknown", "key_bits": 0,
        "serial": "",
        "der_bytes": cert_bytes,
        "fingerprint_sha256": hashlib.sha256(cert_bytes).hexdigest(),
        "fingerprint_sha1": hashlib.sha1(cert_bytes).hexdigest(),
    }
    try:
        tag, tbs_outer, _ = _asn1_next(cert_bytes, 0)   # Certificate SEQUENCE
        if tag != 0x30:
            return result
        off = 0
        # TBSCertificate
        tag2, tbs, off = _asn1_next(tbs_outer, off)
        # Parse TBSCertificate fields
        tbs_off = 0
        # Optional version [0] EXPLICIT
        tag3, v0, tbs_off = _asn1_next(tbs, tbs_off)
        if tag3 == 0xA0:   # version
            tag3, v0, tbs_off = _asn1_next(tbs, tbs_off)
        # serialNumber INTEGER
        if tag3 == 0x02:
            result["serial"] = v0.hex()[:40]
            tag3, v0, tbs_off = _asn1_next(tbs, tbs_off)
        # signature AlgorithmIdentifier was already consumed by the read above
        # (tag3 == 0x30 at this point); do not read again here.
        # issuer Name
        tag3, issuer_bytes, tbs_off = _asn1_next(tbs, tbs_off)
        issuer_dn = _parse_dn(issuer_bytes)
        result["issuer"] = issuer_dn.get("CN","") or issuer_dn.get("O","") or str(issuer_dn)
        # validity
        tag3, validity_bytes, tbs_off = _asn1_next(tbs, tbs_off)
        nb, na = _parse_validity(validity_bytes)
        result["not_before"] = nb
        result["not_after"]  = na
        # subject Name
        tag3, subject_bytes, tbs_off = _asn1_next(tbs, tbs_off)
        subject_dn = _parse_dn(subject_bytes)
        result["subject"] = subject_dn.get("CN","") or subject_dn.get("O","") or str(subject_dn)
        result["subject_dn"] = subject_dn
        # SubjectPublicKeyInfo
        tag3, spki_bytes, tbs_off = _asn1_next(tbs, tbs_off)
        kt, kb = _parse_pubkey_info(spki_bytes)
        result["key_type"] = kt
        result["key_bits"] = kb
        # Extensions (optional, [3])
        while tbs_off < len(tbs):
            tag3, ext_outer, tbs_off = _asn1_next(tbs, tbs_off)
            if tag3 == 0xA3:    # [3] extensions
                tag4, exts_seq, _ = _asn1_next(ext_outer, 0)
                sans = _parse_extensions(exts_seq)
                result["sans"] = sans
    except Exception:
        pass
    return result

# ─────────────────────────────────────────────────────────────────────────────
# TLS record parser
# ─────────────────────────────────────────────────────────────────────────────

def _parse_tls_records(payload):
    """
    Yield TLS records from a raw TCP app_payload.
    Each record: (content_type, version, data_bytes)
    content_type: 20=ChangeCipherSpec, 21=Alert, 22=Handshake, 23=AppData
    """
    off = 0
    while off + 5 <= len(payload):
        ct  = payload[off]
        ver = struct.unpack(">H", payload[off+1:off+3])[0]
        ln  = struct.unpack(">H", payload[off+3:off+5])[0]
        off += 5
        if ct not in (20, 21, 22, 23):
            break   # not TLS
        if off + ln > len(payload):
            break
        yield ct, ver, payload[off:off+ln]
        off += ln

def _parse_client_hello(data):
    """Parse ClientHello handshake body. Returns dict of extracted fields."""
    result = {
        "client_version": 0, "session_id": "",
        "cipher_suites": [], "sni": "", "alpn": [], "tls13_offered": False,
    }
    try:
        off = 0
        result["client_version"] = struct.unpack(">H", data[off:off+2])[0]; off += 2
        off += 32   # random
        sid_len = data[off]; off += 1
        result["session_id"] = data[off:off+sid_len].hex(); off += sid_len
        cs_len = struct.unpack(">H", data[off:off+2])[0]; off += 2
        for i in range(0, cs_len, 2):
            cs = struct.unpack(">H", data[off+i:off+i+2])[0]
            result["cipher_suites"].append(cs)
        off += cs_len
        comp_len = data[off]; off += 1
        off += comp_len   # compression methods
        if off + 2 > len(data):
            return result
        ext_total = struct.unpack(">H", data[off:off+2])[0]; off += 2
        ext_end = off + ext_total
        while off + 4 <= ext_end:
            ext_type = struct.unpack(">H", data[off:off+2])[0]
            ext_len  = struct.unpack(">H", data[off+2:off+4])[0]
            ext_data = data[off+4:off+4+ext_len]; off += 4 + ext_len
            if ext_type == EXT_SNI and len(ext_data) >= 5:
                sni_list_len = struct.unpack(">H", ext_data[0:2])[0]
                sni_type = ext_data[2]
                sni_name_len = struct.unpack(">H", ext_data[3:5])[0]
                result["sni"] = ext_data[5:5+sni_name_len].decode("ascii","replace")
            elif ext_type == EXT_ALPN and len(ext_data) >= 4:
                proto_list_len = struct.unpack(">H", ext_data[0:2])[0]
                poff = 2
                while poff < 2 + proto_list_len:
                    plen = ext_data[poff]; poff += 1
                    result["alpn"].append(ext_data[poff:poff+plen].decode("ascii","replace"))
                    poff += plen
            elif ext_type == EXT_SUPPORTED:
                # supported_versions — if 0x0304 present, TLS 1.3 is offered
                vlist_len = ext_data[0] if ext_data else 0
                for i in range(1, 1+vlist_len, 2):
                    if ext_data[i:i+2] == b"\x03\x04":
                        result["tls13_offered"] = True
    except Exception:
        pass
    return result

def _parse_server_hello(data):
    """Parse ServerHello handshake body."""
    result = {"server_version": 0, "cipher_suite": 0, "session_id": "", "tls13_negotiated": False}
    try:
        off = 0
        result["server_version"] = struct.unpack(">H", data[off:off+2])[0]; off += 2
        off += 32   # random
        sid_len = data[off]; off += 1
        result["session_id"] = data[off:off+sid_len].hex(); off += sid_len
        result["cipher_suite"] = struct.unpack(">H", data[off:off+2])[0]; off += 2
        off += 1   # compression method
        if off + 2 <= len(data):
            ext_total = struct.unpack(">H", data[off:off+2])[0]; off += 2
            ext_end = off + ext_total
            while off + 4 <= ext_end:
                ext_type = struct.unpack(">H", data[off:off+2])[0]
                ext_len  = struct.unpack(">H", data[off+2:off+4])[0]
                ext_data = data[off+4:off+4+ext_len]; off += 4 + ext_len
                if ext_type == EXT_SUPPORTED and len(ext_data) == 2:
                    ver = struct.unpack(">H", ext_data)[0]
                    if ver == 0x0304:
                        result["tls13_negotiated"] = True
                        result["server_version"] = 0x0304
    except Exception:
        pass
    return result

def _parse_certificates(data):
    """Parse Certificate handshake body. Returns list of parsed cert dicts."""
    certs = []
    try:
        off = 0
        total_len = struct.unpack(">I", b"\x00" + data[0:3])[0]; off += 3
        end = min(off + total_len, len(data))
        while off + 3 <= end:
            cert_len = struct.unpack(">I", b"\x00" + data[off:off+3])[0]; off += 3
            cert_bytes = data[off:off+cert_len]; off += cert_len
            parsed = _parse_certificate(cert_bytes)
            certs.append(parsed)
    except Exception:
        pass
    return certs

# ─────────────────────────────────────────────────────────────────────────────
# Shared handshake/certificate walker
# ─────────────────────────────────────────────────────────────────────────────

def walk_tls_handshake(byte_stream):
    """
    Walk a raw byte stream of TLS records (from a TCP stream or a
    reassembled EAP-TLS exchange) and extract handshake-level details.

    Returns a dict: sni, client_version_offered, alpn, tls_version,
    cipher_suite_id, cipher_suite, certs (list of parsed cert dicts,
    each including der_bytes/fingerprint_sha256/fingerprint_sha1),
    handshake_complete, alerts (list of "Level: Description" strings).
    """
    result = {
        "sni": "", "client_version_offered": "", "alpn": "",
        "tls_version": "", "cipher_suite_id": 0, "cipher_suite": "",
        "certs": [], "handshake_complete": False, "alerts": [],
    }
    try:
        for ct, ver, rec_data in _parse_tls_records(byte_stream):
            if ct == 22:   # Handshake
                hs_off = 0
                while hs_off + 4 <= len(rec_data):
                    hs_type = rec_data[hs_off]
                    hs_len  = struct.unpack(">I", b"\x00" + rec_data[hs_off+1:hs_off+4])[0]
                    hs_data = rec_data[hs_off+4:hs_off+4+hs_len]
                    hs_off += 4 + hs_len

                    if hs_type == 1:   # ClientHello
                        ch = _parse_client_hello(hs_data)
                        if not result["sni"]:
                            result["sni"] = ch.get("sni","")
                        if not result["client_version_offered"]:
                            cv = ch.get("client_version",0)
                            if ch.get("tls13_offered"):
                                result["client_version_offered"] = "TLS 1.3 (offered)"
                            else:
                                result["client_version_offered"] = TLS_VERSIONS.get(cv, f"0x{cv:04x}")
                        if not result["alpn"]:
                            result["alpn"] = ", ".join(ch.get("alpn",[]))

                    elif hs_type == 2:   # ServerHello
                        sh = _parse_server_hello(hs_data)
                        sv = sh.get("server_version",0)
                        if sh.get("tls13_negotiated"):
                            result["tls_version"] = "TLS 1.3"
                        else:
                            result["tls_version"] = TLS_VERSIONS.get(sv, f"0x{sv:04x}")
                        cs_id = sh.get("cipher_suite",0)
                        result["cipher_suite_id"] = cs_id
                        result["cipher_suite"] = CIPHER_SUITES.get(cs_id, f"0x{cs_id:04x}")

                    elif hs_type == 11:   # Certificate
                        certs = _parse_certificates(hs_data)
                        if certs:
                            result["certs"].extend(certs)

                    elif hs_type == 20:   # Finished
                        result["handshake_complete"] = True

            elif ct == 21 and len(rec_data) >= 2:   # Alert
                level = {1:"Warning",2:"Fatal"}.get(rec_data[0],"?")
                desc  = ALERT_DESCS.get(rec_data[1], f"code {rec_data[1]}")
                alert_str = f"{level}: {desc}"
                if alert_str not in result["alerts"]:
                    result["alerts"].append(alert_str)
    except Exception:
        pass
    return result

# ─────────────────────────────────────────────────────────────────────────────
# Session correlator — main entry point
# ─────────────────────────────────────────────────────────────────────────────

def extract_tls_sessions(packets):
    """
    Walk all packets, find TLS handshakes, parse them, and return
    a list of per-session dicts suitable for the Excel sheet.

    Session key: (client_ip, server_ip, server_port)
    — we use server_port because the client port changes per connection
      but the server port identifies the service.
    """
    # Accumulate handshake fragments per TCP stream
    # key = (src_ip, dst_ip, sport, dport)  (canonical: lower IP first)
    streams = defaultdict(bytearray)   # raw payload accumulation
    sessions = {}    # (client_ip, server_ip, srv_port) -> session dict

    def _skey(p):
        """Canonical stream key: always client→server direction."""
        return (p["src_ip"], p["dst_ip"], p["src_port"], p["dst_port"])

    TLS_PORTS = {443, 8443, 4443, 993, 995, 465, 587, 636, 3269, 8883, 5671, 5672}

    for p in packets:
        proto = p.get("proto","")
        payload = p.get("app_payload", b"")
        if not payload or len(payload) < 6:
            continue

        sp, dp = p.get("src_port",0), p.get("dst_port",0)
        src, dst = p.get("src_ip",""), p.get("dst_ip","")

        # Only process TCP on TLS ports, OR packets that look like TLS
        is_tls_port = sp in TLS_PORTS or dp in TLS_PORTS
        looks_like_tls = (len(payload) >= 5 and
                          payload[0] in (20,21,22,23) and
                          payload[1] == 0x03 and
                          payload[2] in (0x00,0x01,0x02,0x03,0x04))
        if not (is_tls_port or looks_like_tls):
            continue

        # Determine session key: client is whoever initiated (higher port usually)
        if dp in TLS_PORTS or dp < sp:
            client_ip, server_ip, srv_port = src, dst, dp
        else:
            client_ip, server_ip, srv_port = dst, src, sp

        sess_key = (client_ip, server_ip, srv_port)
        if sess_key not in sessions:
            sessions[sess_key] = {
                "client_ip": client_ip,
                "server_ip": server_ip,
                "server_port": srv_port,
                "sni": "",
                "client_version_offered": "",
                "tls_version": "",
                "cipher_suite_id": 0,
                "cipher_suite": "",
                "alpn": "",
                "cert_subject": "",
                "cert_issuer": "",
                "cert_sans": "",
                "cert_not_before": "",
                "cert_not_after": "",
                "cert_key_type": "",
                "cert_key_bits": 0,
                "cert_expired": False,
                "cert_expiring_soon": False,
                "weak_cipher": False,
                "weak_version": False,
                "alerts": [],
                "handshake_complete": False,
                "certs": [],
                "issues": [],
            }
        sess = sessions[sess_key]

        # Parse TLS records from this packet's payload
        hs = walk_tls_handshake(payload)

        if hs["sni"] and not sess["sni"]:
            sess["sni"] = hs["sni"]
        if hs["client_version_offered"] and not sess["client_version_offered"]:
            sess["client_version_offered"] = hs["client_version_offered"]
        if hs["alpn"] and not sess["alpn"]:
            sess["alpn"] = hs["alpn"]
        if hs["tls_version"]:
            sess["tls_version"] = hs["tls_version"]
        if hs["cipher_suite_id"]:
            sess["cipher_suite_id"] = hs["cipher_suite_id"]
            sess["cipher_suite"] = hs["cipher_suite"]
        if hs["handshake_complete"]:
            sess["handshake_complete"] = True
        for alert_str in hs["alerts"]:
            if alert_str not in sess["alerts"]:
                sess["alerts"].append(alert_str)

        if hs["certs"] and not sess["cert_subject"]:
            sess["certs"] = hs["certs"]
            leaf = hs["certs"][0]
            sess["cert_subject"]   = leaf.get("subject","")
            sess["cert_issuer"]    = leaf.get("issuer","")
            sess["cert_sans"]      = ", ".join(leaf.get("sans",[]))[:200]
            sess["cert_key_type"]  = leaf.get("key_type","")
            sess["cert_key_bits"]  = leaf.get("key_bits",0)
            nb = leaf.get("not_before")
            na = leaf.get("not_after")
            if nb: sess["cert_not_before"] = nb.strftime("%Y-%m-%d")
            if na:
                sess["cert_not_after"] = na.strftime("%Y-%m-%d")
                now = datetime.datetime.utcnow()
                sess["cert_expired"]       = na < now
                sess["cert_expiring_soon"] = (na - now).days < 30 and not sess["cert_expired"]

    # ── Post-process: flag issues ─────────────────────────────────────────────
    now = datetime.datetime.utcnow()
    for sess in sessions.values():
        issues = []
        cs = sess["cipher_suite"]
        ver = sess["tls_version"]

        # Weak cipher suite
        if any(w in cs for w in WEAK_CIPHERS):
            sess["weak_cipher"] = True
            issues.append(f"Weak cipher: {cs}")

        # NULL / anon
        if "NULL" in cs or "anon" in cs.lower():
            issues.append("NULL or anonymous cipher — no encryption/auth")

        # Weak TLS version
        if ver in ("SSLv3","TLS 1.0","TLS 1.1"):
            sess["weak_version"] = True
            issues.append(f"Deprecated protocol: {ver}")

        # Cert expired
        if sess["cert_expired"]:
            issues.append("Certificate EXPIRED")

        # Cert expiring soon
        if sess["cert_expiring_soon"]:
            issues.append("Certificate expiring within 30 days")

        # Weak key
        kt = sess["cert_key_type"]
        kb = sess["cert_key_bits"]
        if "RSA" in kt and kb and kb < 2048:
            issues.append(f"Weak RSA key: {kb}-bit (minimum 2048)")
        if "RSA" in kt and kb and kb < 4096:
            if kb < 2048:
                pass  # already flagged
        if "ECDSA" in kt and kb and kb < 256:
            issues.append(f"Weak EC key: {kb}-bit")

        # Alerts
        for alert in sess["alerts"]:
            if "Fatal" in alert:
                issues.append(f"TLS alert — {alert}")

        # No SNI (possible direct IP connection or misconfigured client)
        # Trigger if: negotiated TLS version known (ServerHello seen) and no SNI
        if not sess["sni"] and ver and (sess["handshake_complete"] or sess.get("cipher_suite")):
            issues.append("No SNI — direct IP or misconfigured client")

        sess["issues"] = issues

    return list(sessions.values())
