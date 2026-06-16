"""Network naming context extractor — DHCP leases, LLMNR, discovered domains.

Public API: ``extract_network_names(packets, dns_events=None)``
"""

import socket
import struct
from collections import defaultdict

from .dns import _dns_read_name


def _parse_dhcp_lease(data):
    """Parse a raw BOOTP/DHCP payload and return a lease dict or None.

    Extracts:
    - chaddr (client MAC at offset 28)
    - yiaddr (offered IP)
    - ciaddr (current client IP, used in REQUEST/INFORM)
    - Option 12 (Hostname)
    - Option 15 (Domain Suffix)
    - Option 81 (Client FQDN — RFC 4702)
    """
    try:
        if len(data) < 240:
            return None

        yiaddr = socket.inet_ntoa(data[16:20])
        ciaddr = socket.inet_ntoa(data[12:16])
        chaddr_bytes = data[28:34]
        mac = ":".join(f"{b:02x}" for b in chaddr_bytes)
        if mac in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
            mac = None

        hostname = None
        domain_suffix = None
        client_fqdn = None

        i = 240
        while i < len(data):
            opt = data[i]; i += 1
            if opt == 255:
                break
            if opt == 0:
                continue
            if i >= len(data):
                break
            ln = data[i]; i += 1
            val = data[i:i+ln]; i += ln

            if opt == 12:
                hostname = val.decode("ascii", "replace").strip("\x00").strip()
            elif opt == 15:
                domain_suffix = val.decode("ascii", "replace").strip("\x00").strip().lower()
            elif opt == 81 and ln >= 3:
                flags = val[0]
                e_bit = (flags >> 2) & 1
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

        ip = None
        if yiaddr and yiaddr not in ("0.0.0.0",):
            ip = yiaddr
        elif ciaddr and ciaddr not in ("0.0.0.0",):
            ip = ciaddr
        if ip is None:
            return None

        fqdn = None
        effective_hostname = None

        if client_fqdn:
            fqdn = client_fqdn
            effective_hostname = client_fqdn.split(".")[0]
        elif hostname:
            effective_hostname = hostname
            if domain_suffix and "." not in hostname:
                fqdn = f"{hostname}.{domain_suffix}"

        return {
            "mac": mac,
            "ip": ip,
            "hostname": effective_hostname,
            "domain_suffix": domain_suffix,
            "fqdn": fqdn,
        }
    except Exception:
        return None


def _parse_llmnr_packet(data, src_ip, ts_us, events):
    """Parse an LLMNR (DNS wire format over UDP/5355) packet and append events."""
    try:
        if len(data) < 12:
            return
        flags = struct.unpack(">H", data[2:4])[0]
        qr = (flags >> 15) & 1
        qd_count = struct.unpack(">H", data[4:6])[0]
        an_count = struct.unpack(">H", data[6:8])[0]

        offset = 12
        qnames = []
        for _ in range(qd_count):
            if offset >= len(data):
                break
            name, offset = _dns_read_name(data, offset)
            if offset + 4 > len(data):
                break
            offset += 4  # QTYPE + QCLASS
            if name:
                qnames.append(name.rstrip("."))

        answer_ips = []
        if qr == 1:
            for _ in range(an_count):
                if offset + 10 > len(data):
                    break
                _, offset = _dns_read_name(data, offset)
                if offset + 10 > len(data):
                    break
                rtype = struct.unpack(">H", data[offset:offset+2])[0]
                rdlen = struct.unpack(">H", data[offset+8:offset+10])[0]
                offset += 10
                if offset + rdlen > len(data):
                    break
                rdata = data[offset:offset+rdlen]
                offset += rdlen
                if rtype == 1 and rdlen == 4:
                    try:
                        answer_ips.append(socket.inet_ntoa(rdata))
                    except Exception:
                        pass

        for qname in qnames:
            events.append({
                "src_ip": src_ip,
                "query": qname,
                "is_response": bool(qr),
                "responder_ip": src_ip if qr else None,
                "answer_ip": answer_ips[0] if (qr and answer_ips) else None,
                "ts_us": ts_us,
            })
    except Exception:
        pass


def _infer_domains_from_dns(dns_events):
    """Extract recurring internal domain suffixes from DNS query names."""
    suffix_counts = defaultdict(int)
    for ev in (dns_events or []):
        qname = ev.get("query_name", "")
        if not qname or "." not in qname:
            continue
        labels = qname.rstrip(".").split(".")
        if len(labels) >= 2:
            suffix = ".".join(labels[-2:]).lower()
            # Only consider plausible internal TLDs
            tld = labels[-1].lower()
            if tld in ("local", "lan", "internal", "corp", "ad", "home",
                       "intranet", "net", "org", "com"):
                suffix_counts[suffix] += 1
    # Return suffixes seen in at least 3 queries
    return {s for s, c in suffix_counts.items() if c >= 3}


def extract_network_names(packets, dns_events=None):
    """Extract network naming context from DHCP and LLMNR packets.

    Args:
        packets:    raw packet list from parse_pcap()
        dns_events: optional list from extract_dns_events(), used to infer
                    domain suffixes from recurring DNS query patterns

    Returns a dict with keys:
        discovered_domains  – sorted list of unique domain/workgroup names
        dhcp_leases         – list of {mac, ip, hostname, domain_suffix, fqdn}
        llmnr_queries       – list of LLMNR events (queries + responses)
        fqdns               – {ip: fqdn} for nodes where both hostname+domain known
    """
    leases = {}     # ip -> lease dict (last OFFER/ACK wins)
    domains = set()
    llmnr_events = []

    for p in packets:
        proto = p.get("proto", "")
        payload = p.get("app_payload", b"")
        if not payload:
            continue

        if proto == "DHCP":
            lease = _parse_dhcp_lease(payload)
            if lease:
                ip = lease["ip"]
                # Merge: prefer lease with FQDN over one without
                existing = leases.get(ip)
                if existing is None or (lease["fqdn"] and not existing["fqdn"]):
                    leases[ip] = lease
                if lease["domain_suffix"]:
                    domains.add(lease["domain_suffix"])

        elif proto == "LLMNR":
            _parse_llmnr_packet(payload, p.get("src_ip", ""), p.get("ts_us", 0), llmnr_events)

    # Infer additional domains from DNS query patterns
    domains.update(_infer_domains_from_dns(dns_events))

    fqdns = {ip: lease["fqdn"] for ip, lease in leases.items() if lease.get("fqdn")}

    return {
        "discovered_domains": sorted(domains),
        "dhcp_leases": list(leases.values()),
        "llmnr_queries": llmnr_events,
        "fqdns": fqdns,
    }
