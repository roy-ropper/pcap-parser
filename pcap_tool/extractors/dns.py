"""DNS/mDNS, DHCP, and NetBIOS Name Service parsing and event extraction."""

import struct, socket

def _parse_dns(data, setter):
    """
    Parse DNS / mDNS wire format.
    Extracts hostname→IP mappings (A, AAAA), PTR records, SRV, TXT.
    Calls setter(ip, name, priority) for every resolved mapping.
    Also handles mDNS reverse PTR (x.x.x.x.in-addr.arpa → hostname).
    """
    try:
        if len(data) < 12:
            return
        flags    = struct.unpack(">H", data[2:4])[0]
        is_resp  = (flags >> 15) & 1
        qd_count = struct.unpack(">H", data[4:6])[0]
        an_count = struct.unpack(">H", data[6:8])[0]
        ar_count = struct.unpack(">H", data[10:12])[0]   # additional records

        # Process ALL record sections: answers + additional records
        # (mDNS puts A records in the Additional section after PTR answers)
        total_answers = an_count + ar_count

        if not is_resp and an_count == 0 and ar_count == 0:
            return   # pure query with no piggybacked answers — skip for hostname resolution

        offset = 12
        # Skip questions
        for _ in range(qd_count):
            offset = _dns_skip_name(data, offset)
            if offset + 4 > len(data): return
            offset += 4   # QTYPE + QCLASS

        def _process_section(count):
            nonlocal offset
            for _ in range(count):
                if offset + 2 > len(data): break
                name, offset = _dns_read_name(data, offset)
                if offset + 10 > len(data): break
                rtype = struct.unpack(">H", data[offset:offset+2])[0]
                # Skip class (2), TTL (4)
                rdlen = struct.unpack(">H", data[offset+8:offset+10])[0]
                offset += 10
                if offset + rdlen > len(data): break
                rdata = data[offset:offset+rdlen]
                offset += rdlen

                if rtype == 1 and rdlen == 4:       # A record
                    try:
                        ip = socket.inet_ntoa(rdata)
                        setter(ip, name.rstrip("."), 1)
                    except Exception: pass

                elif rtype == 28 and rdlen == 16:   # AAAA record
                    try:
                        ip = socket.inet_ntop(socket.AF_INET6, rdata)
                        setter(ip, name.rstrip("."), 1)
                    except Exception: pass

                elif rtype == 12:                   # PTR record
                    try:
                        ptr_name, _ = _dns_read_name(data, offset - rdlen)
                        # Reverse PTR: x.x.x.x.in-addr.arpa → hostname
                        if ".in-addr.arpa" in name.lower():
                            # Decode reversed IP: 4.3.2.1.in-addr.arpa → 1.2.3.4
                            parts = name.lower().replace(".in-addr.arpa","").split(".")
                            if len(parts) == 4:
                                fwd_ip = ".".join(reversed(parts))
                                setter(fwd_ip, ptr_name.rstrip("."), 2)
                        elif ".ip6.arpa" not in name.lower():
                            # mDNS service PTR: _http._tcp.local → service name
                            # The PTR target is the device hostname
                            pass   # handled by SRV below
                    except Exception: pass

                elif rtype == 33:                   # SRV record
                    try:
                        if rdlen >= 6:
                            srv_target, _ = _dns_read_name(data, offset - rdlen + 6)
                            # SRV target is the canonical hostname — no IP yet
                            pass
                    except Exception: pass

        _process_section(an_count)
        _process_section(ar_count)

    except Exception:
        pass


def _extract_dns_events(packets):
    """
    Extract every DNS and mDNS query/response event from a packet list.
    Returns list of dicts:
      { client_ip, server_ip, direction, proto, query_name, qtype,
        answer_ip, answer_name, ttl, is_response, flags_desc, ts_us }

    Record types decoded: A(1), AAAA(28), CNAME(5), PTR(12), MX(15), NS(2),
                          SRV(33), TXT(16), SOA(6), ANY(255)
    """
    RTYPES = {
        1:"A", 2:"NS", 5:"CNAME", 6:"SOA", 12:"PTR", 15:"MX",
        16:"TXT", 28:"AAAA", 33:"SRV", 41:"OPT", 255:"ANY",
        65:"HTTPS", 64:"SVCB",
    }

    events = []

    for p in packets:
        proto   = p.get("proto","")
        payload = p.get("app_payload", b"")
        if proto not in ("DNS","mDNS") or not payload or len(payload) < 12:
            continue

        src_ip = p.get("src_ip","")
        dst_ip = p.get("dst_ip","")
        sp     = p.get("src_port",0)
        dp     = p.get("dst_port",0)
        ts_us  = p.get("ts_us",0)

        # mDNS: src=client, dst=224.0.0.251. For regular DNS:
        # query: client→53, response: 53→client
        is_mdns = (proto == "mDNS")

        try:
            txid     = struct.unpack(">H", payload[0:2])[0]
            flags    = struct.unpack(">H", payload[2:4])[0]
            is_resp  = (flags >> 15) & 1
            qd_count = struct.unpack(">H", payload[4:6])[0]
            an_count = struct.unpack(">H", payload[6:8])[0]
            ns_count = struct.unpack(">H", payload[8:10])[0]
            ar_count = struct.unpack(">H", payload[10:12])[0]

            # Decode flags
            rcode    = flags & 0x000F
            opcode   = (flags >> 11) & 0x000F
            aa       = (flags >> 10) & 1
            tc       = (flags >> 9) & 1
            rd       = (flags >> 8) & 1
            ra       = (flags >> 7) & 1

            flags_parts = []
            if is_resp:   flags_parts.append("Response")
            else:         flags_parts.append("Query")
            if aa:        flags_parts.append("AA")
            if rd:        flags_parts.append("RD")
            if ra:        flags_parts.append("RA")
            if tc:        flags_parts.append("TC")
            rcodes = {0:"NOERROR",1:"FORMERR",2:"SERVFAIL",3:"NXDOMAIN",
                      4:"NOTIMP",5:"REFUSED"}
            rcode_str = rcodes.get(rcode, f"RCODE{rcode}")
            if rcode: flags_parts.append(rcode_str)
            flags_desc = " | ".join(flags_parts)

            client_ip = src_ip if not is_resp else dst_ip
            server_ip = dst_ip if not is_resp else src_ip
            if is_mdns:
                client_ip = src_ip
                server_ip = "224.0.0.251 (mDNS)"

            offset = 12

            # ── Parse questions ────────────────────────────────────────────
            questions = []
            for _ in range(qd_count):
                if offset >= len(payload): break
                qname, offset = _dns_read_name(payload, offset)
                if offset + 4 > len(payload): break
                qt  = struct.unpack(">H", payload[offset:offset+2])[0]
                qc  = struct.unpack(">H", payload[offset+2:offset+4])[0]
                offset += 4
                qt_str = RTYPES.get(qt, str(qt))
                questions.append((qname.rstrip("."), qt_str))

            # ── Parse answer records ───────────────────────────────────────
            def parse_rrs(count):
                nonlocal offset
                records = []
                for _ in range(count):
                    if offset + 2 > len(payload): break
                    rname, offset = _dns_read_name(payload, offset)
                    if offset + 10 > len(payload): break
                    rtype  = struct.unpack(">H", payload[offset:offset+2])[0]
                    rclass = struct.unpack(">H", payload[offset+2:offset+4])[0]
                    rttl   = struct.unpack(">I", payload[offset+4:offset+8])[0]
                    rdlen  = struct.unpack(">H", payload[offset+8:offset+10])[0]
                    offset += 10
                    if offset + rdlen > len(payload): break
                    rdata  = payload[offset:offset+rdlen]
                    offset += rdlen

                    rtype_str = RTYPES.get(rtype, str(rtype))
                    answer_ip   = ""
                    answer_name = ""
                    answer_val  = ""

                    if rtype == 1 and rdlen == 4:    # A
                        try: answer_ip = socket.inet_ntoa(rdata)
                        except: pass
                        answer_val = answer_ip

                    elif rtype == 28 and rdlen == 16: # AAAA
                        try: answer_ip = socket.inet_ntop(socket.AF_INET6, rdata)
                        except: pass
                        answer_val = answer_ip

                    elif rtype in (5, 12, 2):         # CNAME, PTR, NS
                        try:
                            n, _ = _dns_read_name(payload, offset - rdlen)
                            answer_name = n.rstrip(".")
                            answer_val  = answer_name
                        except: pass

                    elif rtype == 15 and rdlen >= 3:  # MX
                        pref = struct.unpack(">H", rdata[:2])[0]
                        try:
                            exch, _ = _dns_read_name(payload, offset - rdlen + 2)
                            answer_val = f"[pref={pref}] {exch.rstrip('.')}"
                            answer_name = exch.rstrip(".")
                        except: pass

                    elif rtype == 16:                 # TXT
                        parts = []
                        pos2 = 0
                        while pos2 < len(rdata):
                            slen = rdata[pos2]; pos2 += 1
                            parts.append(rdata[pos2:pos2+slen].decode("utf-8","replace"))
                            pos2 += slen
                        answer_val = "; ".join(parts)[:200]

                    elif rtype == 33 and rdlen >= 6:  # SRV
                        pri = struct.unpack(">H", rdata[0:2])[0]
                        wt  = struct.unpack(">H", rdata[2:4])[0]
                        pt  = struct.unpack(">H", rdata[4:6])[0]
                        try:
                            tgt, _ = _dns_read_name(payload, offset - rdlen + 6)
                            answer_val = f"{tgt.rstrip('.')}:{pt} (pri={pri})"
                        except: pass

                    elif rtype == 41:                 # OPT (EDNS0) — skip silently
                        continue

                    records.append({
                        "rname": rname.rstrip("."),
                        "rtype": rtype_str,
                        "ttl":   rttl,
                        "answer_ip":   answer_ip,
                        "answer_name": answer_name,
                        "answer_val":  answer_val,
                    })
                return records

            answers    = parse_rrs(an_count)
            auth_rrs   = parse_rrs(ns_count)
            addl_rrs   = parse_rrs(ar_count)

            # ── Emit one event row per question×answer pair ───────────────
            if not questions:
                # Unsolicited announcement (mDNS) — no question, just answers
                for ans in answers + addl_rrs:
                    if ans["rtype"] in ("A","AAAA","PTR","CNAME"):
                        events.append(dict(
                            client_ip   = client_ip,
                            server_ip   = server_ip,
                            proto       = proto,
                            query_name  = ans["rname"],
                            qtype       = ans["rtype"],
                            answer_ip   = ans["answer_ip"],
                            answer_name = ans["answer_name"],
                            answer_val  = ans["answer_val"],
                            ttl         = ans["ttl"],
                            rcode       = rcode_str,
                            is_response = bool(is_resp),
                            flags_desc  = flags_desc,
                            ts_us       = ts_us,
                        ))
            else:
                for qname, qt_str in questions:
                    # Find matching answers (same name or any answer if no match)
                    matching = [a for a in answers if a["rname"].lower() == qname.lower()
                                or a["rname"].lower().endswith("." + qname.lower())]
                    if not matching:
                        matching = answers or [None]
                    for ans in matching:
                        events.append(dict(
                            client_ip   = client_ip,
                            server_ip   = server_ip,
                            proto       = proto,
                            query_name  = qname,
                            qtype       = qt_str,
                            answer_ip   = ans["answer_ip"]   if ans else "",
                            answer_name = ans["answer_name"] if ans else "",
                            answer_val  = ans["answer_val"]  if ans else "",
                            ttl         = ans["ttl"]         if ans else 0,
                            rcode       = rcode_str,
                            is_response = bool(is_resp),
                            flags_desc  = flags_desc,
                            ts_us       = ts_us,
                        ))

        except Exception:
            continue

    return events


def _dns_read_name(data, offset):
    labels = []; jumped = False; orig = offset
    visited = set()
    try:
        while offset < len(data):
            if offset in visited: break
            visited.add(offset)
            ln = data[offset]
            if ln == 0:
                if not jumped: orig = offset + 1
                break
            elif (ln & 0xC0) == 0xC0:
                if offset + 1 >= len(data): break
                ptr = ((ln & 0x3F) << 8) | data[offset+1]
                if not jumped: orig = offset + 2
                offset = ptr; jumped = True
            else:
                offset += 1
                labels.append(data[offset:offset+ln].decode("ascii","replace"))
                offset += ln
    except Exception:
        pass
    return ".".join(labels), orig


def _dns_skip_name(data, offset):
    try:
        while offset < len(data):
            ln = data[offset]
            if ln == 0: return offset + 1
            elif (ln & 0xC0) == 0xC0: return offset + 2
            else: offset += ln + 1
    except Exception:
        pass
    return offset


def _parse_dhcp(data, setter):
    """Extract DHCP Options 12/15/81 hostnames/FQDNs and correlate with yiaddr/ciaddr.

    Priority 1.5 is used for full FQDNs (opt 81, or opt 12+15 combined) so they
    rank above bare-hostname DHCP opt-12 (priority 2) but below authoritative DNS (1).
    """
    try:
        if len(data) < 240: return
        yiaddr = socket.inet_ntoa(data[16:20])
        ciaddr = socket.inet_ntoa(data[12:16])
        i = 240
        hostname = None
        domain_suffix = None
        client_fqdn = None
        while i < len(data):
            opt = data[i]; i += 1
            if opt == 255: break
            if opt == 0: continue
            if i >= len(data): break
            ln = data[i]; i += 1
            val = data[i:i+ln]; i += ln
            if opt == 12:
                hostname = val.decode("ascii", "replace").strip("\x00").strip()
            elif opt == 15:
                domain_suffix = val.decode("ascii", "replace").strip("\x00").strip().lower()
            elif opt == 81 and ln >= 3:
                # RFC 4702: flags(1) + RCODE1(1) + RCODE2(1) + FQDN
                flags = val[0]
                e_bit = (flags >> 2) & 1  # 1 = DNS wire format, 0 = ASCII
                try:
                    if e_bit:
                        name, _ = _dns_read_name(val, 3)
                        if name:
                            client_fqdn = name.rstrip(".")
                    else:
                        raw = val[3:].decode("ascii", "replace").strip("\x00").strip()
                        if raw:
                            client_fqdn = raw
                except Exception:
                    pass

        ips = [ip for ip in (yiaddr, ciaddr)
               if ip and ip not in ("0.0.0.0", "255.255.255.255")]

        if client_fqdn:
            for ip in ips:
                setter(ip, client_fqdn, 1.5)
        elif hostname and domain_suffix and "." not in hostname:
            fqdn = f"{hostname}.{domain_suffix}"
            for ip in ips:
                setter(ip, fqdn, 1.5)
        elif hostname:
            for ip in ips:
                setter(ip, hostname, 2)
    except Exception:
        pass


def _parse_nbns(data, src_ip, setter):
    """
    Extract NetBIOS name from NBNS packets (both registrations and responses).

    NBNS wire format (RFC 1002 Section 4.2):
      Header:  12 bytes (TXID, FLAGS, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT)
      Questions: QDCOUNT × (QNAME + QTYPE[2] + QCLASS[2])
      Answers:   ANCOUNT × (NAME + TYPE[2] + CLASS[2] + TTL[4] + RDLEN[2] + RDATA)

    QNAME/NAME encoding: a single label of length 0x20 (32 bytes) containing
    the Level-2 half-ASCII encoded 16-character NetBIOS name, followed by
    a null terminator byte (0x00).

    For registrations (QD=1, AN=0): name is in the question QNAME.
    For responses    (QD=0, AN=1): name is in the answer NAME.
    """
    try:
        if len(data) < 12:
            return
        qd_count = struct.unpack(">H", data[4:6])[0]
        an_count = struct.unpack(">H", data[6:8])[0]
        offset   = 12

        def _read_nbns_name(buf, off):
            """
            Read a NetBIOS encoded name at buf[off].
            Returns (decoded_name_str, new_offset) or ("", new_offset_past_name).
            """
            if off >= len(buf):
                return "", off
            ln = buf[off]; off += 1
            if ln == 0x20:                  # standard 32-byte NBNS label
                if off + 32 > len(buf):
                    return "", off + 32
                raw  = buf[off:off+32]
                name = _decode_nbns_name(raw).strip()
                off += 32
                # null terminator
                if off < len(buf) and buf[off] == 0:
                    off += 1
                return name, off
            elif ln == 0:                   # already at null terminator
                return "", off
            else:
                # skip non-standard label length gracefully
                off += min(ln, len(buf) - off)
                if off < len(buf) and buf[off] == 0:
                    off += 1
                return "", off

        # ── Questions ────────────────────────────────────────────────────────
        for _ in range(qd_count):
            if offset >= len(data):
                break
            name, offset = _read_nbns_name(data, offset)
            offset += 4   # QTYPE + QCLASS
            if name and name not in ("*", "__MSBROWSE__", ""):
                setter(src_ip, name, 3)

        # ── Answers ──────────────────────────────────────────────────────────
        for _ in range(an_count):
            if offset >= len(data):
                break
            name, offset = _read_nbns_name(data, offset)
            if offset + 10 > len(data):
                break
            rtype  = struct.unpack(">H", data[offset:offset+2])[0]
            offset += 8   # TYPE + CLASS + TTL
            rdlen  = struct.unpack(">H", data[offset:offset+2])[0]
            offset += 2
            rdata  = data[offset:offset+rdlen]
            offset += rdlen
            # Extract owner IP from NB record RDATA (2-byte flags + 4-byte IP)
            if name and rtype == 0x0020 and rdlen >= 6:
                try:
                    owner_ip = socket.inet_ntoa(rdata[2:6])
                    if owner_ip and owner_ip not in ("0.0.0.0",):
                        setter(owner_ip, name, 3)
                    else:
                        setter(src_ip, name, 3)
                except Exception:
                    setter(src_ip, name, 3)
            elif name and name not in ("*", "__MSBROWSE__", ""):
                setter(src_ip, name, 3)

    except Exception:
        pass


def _decode_nbns_name(raw):
    """
    Decode a Level-2 half-ASCII encoded NetBIOS name.
    Each original byte is split into two nibbles, each stored as (nibble + 0x41).
    So to decode: take pairs of bytes (A, B) → char = ((A-0x41)<<4) | (B-0x41)
    The name is padded to 16 chars (15 + suffix byte); strip trailing spaces.
    """
    try:
        chars = []
        for i in range(0, min(len(raw), 32), 2):
            a, b = raw[i], raw[i+1]
            # Validate: both bytes must be in range 0x41–0x50 (A–P)
            if not (0x41 <= a <= 0x50 and 0x41 <= b <= 0x50):
                break
            c = ((a - 0x41) << 4) | (b - 0x41)
            # Include all printable ASCII including space (0x20)
            if 0x20 <= c < 0x7f:
                chars.append(chr(c))
            else:
                break   # non-printable → stop (suffix byte or corruption)
        # Strip trailing spaces (padding) but keep internal spaces
        return "".join(chars).rstrip()
    except Exception:
        return ""



def _decode_nbns_payload(payload):
    """
    Decode NetBIOS Name Service packets (UDP 137) — both queries and responses.
    Returns list of human-readable NetBIOS names found, properly decoded from
    the Level-2 half-ASCII encoding (each byte pair encodes one character).
    """
    names = []
    try:
        if len(payload) < 12:
            return names
        qd_count = struct.unpack(">H", payload[4:6])[0]
        an_count = struct.unpack(">H", payload[6:8])[0]
        total    = qd_count + an_count
        offset   = 12
        for _ in range(total):
            if offset >= len(payload):
                break
            # Length byte of the encoded name label (should be 0x20 = 32)
            ln = payload[offset]
            offset += 1
            if ln == 0x20 and offset + 32 <= len(payload):
                raw  = payload[offset:offset+32]
                name = _decode_nbns_name(raw).strip()
                if name and name not in ("*", ""):
                    names.append(name)
                offset += 32
                # null terminator
                if offset < len(payload) and payload[offset] == 0:
                    offset += 1
                # skip QTYPE + QCLASS (4 bytes) or RTYPE+RCLASS+TTL+RDLEN (10 bytes)
                offset += 4
            else:
                break
    except Exception:
        pass
    return names



# Public API name (backward-compat alias)
extract_dns_events = _extract_dns_events
