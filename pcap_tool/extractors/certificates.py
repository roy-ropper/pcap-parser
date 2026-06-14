"""
Certificate extraction — unifies X.509 certificates seen in ordinary TCP TLS
handshakes with those seen in 802.1X/EAP-TLS (and PEAP/EAP-TTLS outer-handshake)
exchanges, e.g. WPA2/3-Enterprise WiFi or wired 802.1X authentication.

Known limitation: EAP-TLS/PEAP/TTLS reassembly only covers the *outer*
(unencrypted) handshake where the certificate exchange happens — this is
correct for a passive tool since the inner tunnel (phase 2 credentials) cannot
be decrypted without the private key. 802.11 EAPOL parsing requires the
capture to include the 802.1X exchange in monitor mode (or a wired 802.1X
capture for Ethernet captures).
"""

import datetime

from .tls import walk_tls_handshake

# EAP types whose Type-Data carries TLS records in the outer handshake
_EAP_TLS_TYPES = {13, 21, 25}   # EAP-TLS, EAP-TTLS, PEAP


def _parse_eapol_eap_tls(app_payload):
    """
    If `app_payload` (an EAPOL frame body) is an EAP-Packet carrying
    EAP-TLS/EAP-TTLS/PEAP Type-Data, return (more_fragments, tls_fragment_bytes).
    Otherwise return None.
    """
    if len(app_payload) < 4:
        return None
    ptype = app_payload[1]
    if ptype != 0:   # not EAP-Packet
        return None
    body = app_payload[4:]
    if len(body) < 5:
        return None
    code = body[0]
    if code not in (1, 2):   # only Request/Response carry a Type + Type-Data
        return None
    eap_type = body[4]
    if eap_type not in _EAP_TLS_TYPES:
        return None
    type_data = body[5:]
    if not type_data:
        return None
    flags = type_data[0]
    more  = bool(flags & 0x40)
    off = 1
    if flags & 0x80:   # Length field present (4 bytes)
        off += 4
    return more, type_data[off:]


def extract_eap_tls_streams(packets):
    """
    Reassemble EAP-TLS/PEAP/TTLS outer-handshake fragments from EAPOL packets
    and walk each completed message group for certificates.

    Returns a list of dicts:
      {supplicant_mac, authenticator_mac, sni, tls_version, cipher_suite,
       certs, handshake_complete, alerts}
    """
    frag_buf = {}    # (src_mac, dst_mac) -> bytearray
    pairs = {}       # frozenset({mac_a, mac_b}) -> stream dict
    supplicants = {} # frozenset({mac_a, mac_b}) -> (supplicant_mac, authenticator_mac)

    for p in packets:
        if p.get("proto") != "EAPOL":
            continue
        smac, dmac = p.get("src_mac", ""), p.get("dst_mac", "")
        if not smac or not dmac:
            continue
        parsed = _parse_eapol_eap_tls(p.get("app_payload", b""))
        if parsed is None:
            continue
        more, frag = parsed

        dir_key = (smac, dmac)
        buf = frag_buf.setdefault(dir_key, bytearray())
        buf.extend(frag)

        if more:
            continue   # wait for remaining fragments

        message = bytes(buf)
        frag_buf[dir_key] = bytearray()
        if not message:
            continue

        hs = walk_tls_handshake(message)

        pair_key = frozenset((smac, dmac))
        if pair_key not in pairs:
            pairs[pair_key] = {
                "supplicant_mac": "", "authenticator_mac": "",
                "sni": "", "tls_version": "", "cipher_suite": "",
                "certs": [], "handshake_complete": False, "alerts": [],
            }
        stream = pairs[pair_key]

        if hs["sni"] and pair_key not in supplicants:
            supplicants[pair_key] = (smac, dmac)

        if hs["sni"] and not stream["sni"]:
            stream["sni"] = hs["sni"]
        if hs["tls_version"]:
            stream["tls_version"] = hs["tls_version"]
        if hs["cipher_suite"]:
            stream["cipher_suite"] = hs["cipher_suite"]
        if hs["handshake_complete"]:
            stream["handshake_complete"] = True
        if hs["certs"]:
            stream["certs"].extend(hs["certs"])
        for alert_str in hs["alerts"]:
            if alert_str not in stream["alerts"]:
                stream["alerts"].append(alert_str)

    results = []
    for pair_key, stream in pairs.items():
        supplicant_mac, authenticator_mac = supplicants.get(pair_key, (None, None))
        if supplicant_mac is None:
            macs = sorted(pair_key)
            supplicant_mac, authenticator_mac = macs[0], macs[-1] if len(macs) > 1 else macs[0]
        stream["supplicant_mac"] = supplicant_mac
        stream["authenticator_mac"] = authenticator_mac
        if stream["certs"]:
            results.append(stream)

    return results


def extract_certificates(packets, tls_sessions, wifi_data=None):
    """
    Build a unified, deduplicated list of certificates seen across all TLS
    sessions and EAP-TLS/PEAP/TTLS streams.

    Returns a list of dicts:
      {source, context, sni, subject, issuer, sans, not_before, not_after,
       key_type, key_bits, fingerprint_sha256, fingerprint_sha1, der_bytes,
       expired, expiring_soon}
    """
    bssid_to_ssid = {}
    if wifi_data:
        for ap in wifi_data.get("aps", []):
            if ap.get("bssid") and ap.get("ssid"):
                bssid_to_ssid[ap["bssid"]] = ap["ssid"]

    now = datetime.datetime.utcnow()
    seen = set()
    out = []

    def _add(source, context, sni, cert):
        fp = cert.get("fingerprint_sha256", "")
        if fp and fp in seen:
            return
        if fp:
            seen.add(fp)

        nb, na = cert.get("not_before"), cert.get("not_after")
        expired = bool(na and na < now)
        expiring_soon = bool(na and not expired and (na - now).days < 30)

        out.append(dict(
            source=source,
            context=context,
            sni=sni,
            subject=cert.get("subject", ""),
            issuer=cert.get("issuer", ""),
            sans=", ".join(cert.get("sans", []))[:200],
            not_before=nb.strftime("%Y-%m-%d") if nb else "",
            not_after=na.strftime("%Y-%m-%d") if na else "",
            key_type=cert.get("key_type", ""),
            key_bits=cert.get("key_bits", 0),
            fingerprint_sha256=fp,
            fingerprint_sha1=cert.get("fingerprint_sha1", ""),
            der_bytes=cert.get("der_bytes", b""),
            expired=expired,
            expiring_soon=expiring_soon,
        ))

    for sess in tls_sessions:
        context = f"{sess['client_ip']} → {sess['server_ip']}:{sess['server_port']}"
        for cert in sess.get("certs", []):
            _add("TLS", context, sess.get("sni", ""), cert)

    for stream in extract_eap_tls_streams(packets):
        ssid = bssid_to_ssid.get(stream["authenticator_mac"], "")
        context = f"{stream['supplicant_mac']} ↔ {stream['authenticator_mac']}"
        if ssid:
            context += f" (SSID: {ssid})"
        for cert in stream.get("certs", []):
            _add("EAP-TLS", context, stream.get("sni", ""), cert)

    return out
