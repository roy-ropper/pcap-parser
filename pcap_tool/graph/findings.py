"""Pentest "unusual behaviour" findings derived from the network graph."""

import ipaddress
import math
import re
from collections import defaultdict, Counter

from ..constants import (
    CLEARTEXT_PROTOS, SUSPICIOUS_PORTS, LATERAL_PROTOS,
    PORT_SCAN_PORT_THRESHOLD, PORT_SCAN_HOST_THRESHOLD, PORT_SCAN_WINDOW_US,
    EXFIL_BYTES_THRESHOLD,
    DNS_TUNNEL_LABEL_LEN, DNS_TUNNEL_ENTROPY, DNS_TUNNEL_NXDOMAIN_THRESHOLD,
    ICMP_TUNNEL_PAYLOAD_THRESHOLD, ICMP_TUNNEL_PACKET_THRESHOLD,
)

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")


def _shannon_entropy(s):
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((c/length) * math.log2(c/length) for c in counts.values())


def compute_findings(nodes, edges, arp_table, conn_times, packets):
    findings = []

    # 1. Cleartext credential protocols
    for (src, dst), info in edges.items():
        ct = info["protocols"] & CLEARTEXT_PROTOS
        if ct:
            for proto in ct:
                findings.append(dict(
                    severity="HIGH",
                    category="Cleartext Protocol",
                    src=src, dst=dst,
                    detail=f"{proto} — credentials/data sent in cleartext",
                    recommendation="Upgrade to encrypted equivalent (SSH, HTTPS, LDAPS, IMAPS…)",
                ))

    # 2. Suspicious ports
    for (src, dst), info in edges.items():
        for port in info["ports"]:
            if port in SUSPICIOUS_PORTS:
                findings.append(dict(
                    severity="HIGH",
                    category="Suspicious Port",
                    src=src, dst=dst,
                    detail=f"Port {port} — {SUSPICIOUS_PORTS[port]}",
                    recommendation="Investigate — possible backdoor, C2, or misconfiguration",
                ))

    # 3. ARP anomalies (same IP, multiple MACs)
    for ip, macs in arp_table.items():
        if len(macs) > 1:
            findings.append(dict(
                severity="CRITICAL",
                category="ARP Anomaly / Possible MITM",
                src=ip, dst="N/A",
                detail=f"IP {ip} seen with MACs: {', '.join(sorted(macs))}",
                recommendation="Investigate for ARP spoofing / MITM attack",
            ))

    # 4. Unusual outbound (internal→external on non-standard ports)
    standard_out = {80,443,53,123,25,465,587,993,995,143,110,22}
    for (src, dst), info in edges.items():
        try:
            src_addr = ipaddress.ip_address(src.split("/")[0])
            dst_addr = ipaddress.ip_address(dst.split("/")[0])
        except ValueError:
            continue
        if src_addr.is_private and not dst_addr.is_private:
            odd_ports = info["ports"] - standard_out
            if odd_ports:
                findings.append(dict(
                    severity="MEDIUM",
                    category="Unusual Outbound",
                    src=src, dst=dst,
                    detail=f"Internal→External on non-standard port(s): {sorted(odd_ports)}",
                    recommendation="Verify legitimate — possible exfil or C2 beaconing",
                ))

    # 5. Beaconing detection (very regular inter-arrival times)
    for (src, dst), times in conn_times.items():
        if len(times) < 6:
            continue
        times_s = sorted(times)
        intervals = [times_s[i+1]-times_s[i] for i in range(len(times_s)-1)]
        intervals = [x for x in intervals if x > 0]
        if not intervals:
            continue
        mean = sum(intervals)/len(intervals)
        if mean == 0:
            continue
        variance = sum((x-mean)**2 for x in intervals)/len(intervals)
        cv = (variance**0.5) / mean  # coefficient of variation
        if cv < 0.15 and len(times) >= 8:  # very regular
            findings.append(dict(
                severity="MEDIUM",
                category="Potential Beaconing",
                src=src, dst=dst,
                detail=(f"{len(times)} connections, avg interval "
                        f"{mean/1e6:.1f}s, CoV={cv:.3f} (very regular)"),
                recommendation="Investigate for C2 callback / malware beaconing",
            ))

    # 6. Internal SMB/lateral movement between workstations
    for (src, dst), info in edges.items():
        if info["protocols"] & {"SMB","RDP","VNC"}:
            try:
                s = ipaddress.ip_address(src.split("/")[0])
                d = ipaddress.ip_address(dst.split("/")[0])
            except ValueError:
                continue
            if s.is_private and d.is_private:
                role_d = nodes.get(dst,{}).get("role","")
                if role_d == "client":   # workstation→workstation
                    findings.append(dict(
                        severity="MEDIUM",
                        category="Lateral Movement Indicator",
                        src=src, dst=dst,
                        detail=f"{', '.join(info['protocols'] & {'SMB','RDP','VNC'})} to a client workstation",
                        recommendation="Verify — unusual for workstations to accept SMB/RDP from peers",
                    ))

    # 7. SNMPv1/v2 (community strings in cleartext at scale)
    snmp_hosts = set()
    for (src, dst), info in edges.items():
        if "SNMP" in info["protocols"]:
            snmp_hosts.add(dst)
    if snmp_hosts:
        findings.append(dict(
            severity="MEDIUM",
            category="SNMP Cleartext",
            src="Multiple", dst=", ".join(sorted(snmp_hosts)[:5]),
            detail=f"SNMPv1/v2 traffic detected ({len(snmp_hosts)} hosts). Community strings in cleartext.",
            recommendation="Migrate to SNMPv3 with authentication and encryption",
        ))

    # 8. Port-scan detection (vertical: many ports on one host; horizontal:
    # one port across many hosts)
    src_dst_ports = defaultdict(lambda: defaultdict(set))   # src -> dst -> {ports}
    src_port_dsts = defaultdict(lambda: defaultdict(set))   # src -> port -> {dsts}
    for (src, dst), info in edges.items():
        for port in info["ports"]:
            src_dst_ports[src][dst].add(port)
            src_port_dsts[src][port].add(dst)

    for src, dst_map in src_dst_ports.items():
        for dst, ports in dst_map.items():
            if len(ports) >= PORT_SCAN_PORT_THRESHOLD:
                times = conn_times.get((src, dst), [])
                span = (max(times) - min(times)) if len(times) >= 2 else 0
                if not times or span <= PORT_SCAN_WINDOW_US:
                    shown = sorted(ports)[:20]
                    findings.append(dict(
                        severity="HIGH",
                        category="Port Scan",
                        src=src, dst=dst,
                        detail=f"{len(ports)} distinct ports probed (vertical scan): "
                               f"{shown}{'…' if len(ports) > 20 else ''}",
                        recommendation="Investigate source host for port-scanning activity (nmap, masscan, etc.)",
                    ))

    for src, port_map in src_port_dsts.items():
        for port, dsts in port_map.items():
            if len(dsts) >= PORT_SCAN_HOST_THRESHOLD:
                findings.append(dict(
                    severity="HIGH",
                    category="Port Scan",
                    src=src, dst="Multiple",
                    detail=f"Port {port} probed across {len(dsts)} hosts (horizontal scan): "
                           f"{sorted(dsts)[:10]}{'…' if len(dsts) > 10 else ''}",
                    recommendation="Investigate source host for network sweep activity",
                ))

    # 9. Top talkers / possible exfiltration (internal -> external, large transfer)
    for (src, dst), info in edges.items():
        try:
            s = ipaddress.ip_address(src.split("/")[0])
            d = ipaddress.ip_address(dst.split("/")[0])
        except ValueError:
            continue
        if s.is_private and not d.is_private and info["bytes"] >= EXFIL_BYTES_THRESHOLD:
            findings.append(dict(
                severity="MEDIUM",
                category="Possible Exfiltration / Top Talker",
                src=src, dst=dst,
                detail=f"{info['bytes']/1e6:.1f} MB transferred internal→external "
                       f"over {', '.join(sorted(info['protocols']))}",
                recommendation="Review destination and data sensitivity — large outbound transfer",
            ))

    # 11. ICMP tunneling (repeated oversized ICMP payloads between a pair)
    icmp_oversized = defaultdict(int)
    for p in packets:
        if p.get("proto") == "ICMP" and len(p.get("app_payload", b"")) > ICMP_TUNNEL_PAYLOAD_THRESHOLD:
            icmp_oversized[(p["src_ip"], p["dst_ip"])] += 1

    for (src, dst), cnt in icmp_oversized.items():
        if cnt >= ICMP_TUNNEL_PACKET_THRESHOLD:
            findings.append(dict(
                severity="MEDIUM",
                category="ICMP Tunneling Indicator",
                src=src, dst=dst,
                detail=f"{cnt} ICMP packets with payload > {ICMP_TUNNEL_PAYLOAD_THRESHOLD} bytes",
                recommendation="Investigate for ICMP tunneling (e.g. icmpsh, ptunnel)",
            ))

    return findings


def compute_llmnr_findings(llmnr_events, nodes, gateways):
    """Finding #14 — LLMNR Poisoning Indicator.

    Fires when an LLMNR response is seen from a host that is NOT the captured
    network's gateway AND whose reported hostname does not match the name it is
    claiming to answer for (the classic Responder/Inveigh pattern: any host
    that answers an LLMNR query for a name it doesn't legitimately own).
    """
    findings = []
    gateway_ips = set((gateways or {}).values())
    seen = set()

    for ev in (llmnr_events or []):
        if not ev.get("is_response"):
            continue
        responder_ip = ev.get("src_ip", "")
        query_name = ev.get("query", "")
        answer_ip = ev.get("answer_ip")

        if not responder_ip or not query_name or not answer_ip:
            continue
        if responder_ip in gateway_ips:
            continue

        # Check whether the responder legitimately owns the queried name
        node = nodes.get(responder_ip, {})
        hostname = node.get("hostname", "") or ""
        bare = hostname.split(".")[0].lower()
        claimed = query_name.lower().split(".")[0]

        if hostname and bare == claimed:
            continue  # Looks legitimate — responding to its own name

        key = (responder_ip, query_name)
        if key in seen:
            continue
        seen.add(key)

        detail = (f"{responder_ip} answered LLMNR query for '{query_name}'"
                  + (f" (hostname: '{hostname}')" if hostname else "")
                  + " — possible Responder/MITM poisoning")
        findings.append(dict(
            severity="HIGH",
            category="LLMNR Poisoning Indicator",
            src=responder_ip,
            dst=query_name,
            detail=detail,
            recommendation="Investigate for LLMNR poisoning (Responder, Inveigh). "
                           "Disable LLMNR/NBT-NS via Group Policy if not required.",
        ))

    return findings


def compute_dns_findings(dns_events):
    """
    Finding #10 — DNS tunneling indicators, derived from extract_dns_events()
    output. Called separately since DNS event extraction happens after the
    main graph/edge pass.
    """
    findings = []
    seen_label_alert = set()
    nx_count = defaultdict(lambda: defaultdict(int))   # client -> base_domain -> count

    for e in dns_events:
        qname = e.get("query_name", "")
        if not qname:
            continue
        client = e.get("client_ip", "")
        labels = qname.split(".")
        base_domain = ".".join(labels[-2:]) if len(labels) >= 2 else qname

        for label in labels:
            if len(label) > DNS_TUNNEL_LABEL_LEN or _shannon_entropy(label) > DNS_TUNNEL_ENTROPY:
                key = (client, base_domain)
                if key not in seen_label_alert:
                    seen_label_alert.add(key)
                    findings.append(dict(
                        severity="MEDIUM",
                        category="DNS Tunneling Indicator",
                        src=client, dst=base_domain,
                        detail=f"Abnormally long/high-entropy DNS label: "
                               f"'{label[:60]}' (len={len(label)})",
                        recommendation="Investigate for DNS tunneling (e.g. iodine, dnscat2)",
                    ))
                break

        if e.get("is_response") and e.get("rcode") == "NXDOMAIN":
            nx_count[client][base_domain] += 1

    for client, domains in nx_count.items():
        for base_domain, cnt in domains.items():
            if cnt >= DNS_TUNNEL_NXDOMAIN_THRESHOLD:
                findings.append(dict(
                    severity="MEDIUM",
                    category="DNS Tunneling Indicator",
                    src=client, dst=base_domain,
                    detail=f"{cnt} NXDOMAIN responses for subdomains of {base_domain}",
                    recommendation="Investigate for DNS tunneling / DGA activity",
                ))

    return findings


def compute_certificate_findings(certificates):
    """
    Findings #12-13, derived from extract_certificates() output. Called
    separately from compute_findings() since certificate extraction happens
    after the main graph/edge pass (TLS sessions + EAP-TLS reassembly).
    """
    findings = []

    # 12. EAP-TLS Client Identity Disclosure — cert-based 802.1X/EAP-TLS
    # exchanges leak the client's identity (CN/UPN/email in subject or SANs)
    # in cleartext during the outer handshake, before the tunnel is up.
    for cert in certificates:
        if cert["source"] != "EAP-TLS":
            continue
        identities = set()
        for field in [cert.get("subject", "")] + cert.get("sans", "").split(", "):
            m = _EMAIL_RE.search(field)
            if m:
                identities.add(m.group(0))
            elif field and ("." in field or "@" in field) and field == cert.get("subject", ""):
                identities.add(field)
        if identities:
            findings.append(dict(
                severity="LOW",
                category="EAP-TLS Client Identity Disclosure",
                src=cert["context"], dst="N/A",
                detail=f"Client certificate identity exposed in EAP-TLS handshake: "
                       f"{', '.join(sorted(identities))}",
                recommendation="Useful for enumeration — consider EAP-TLS identity "
                                "privacy (anonymous outer identity) if not already in use",
            ))

    # 13. Weak / expired certificates (applies to TLS- and EAP-TLS-sourced certs)
    for cert in certificates:
        ctx = f"{cert['source']} {cert['context']}"
        if cert.get("expired"):
            findings.append(dict(
                severity="HIGH",
                category="Weak/Expired Certificate",
                src=ctx, dst="N/A",
                detail=f"Certificate EXPIRED (not_after={cert['not_after']}): "
                       f"{cert.get('subject','')}",
                recommendation="Renew the certificate — expired certs break trust validation",
            ))
        elif cert.get("expiring_soon"):
            findings.append(dict(
                severity="MEDIUM",
                category="Weak/Expired Certificate",
                src=ctx, dst="N/A",
                detail=f"Certificate expiring within 30 days (not_after={cert['not_after']}): "
                       f"{cert.get('subject','')}",
                recommendation="Plan certificate renewal before expiry",
            ))

        kt, kb = cert.get("key_type", ""), cert.get("key_bits", 0)
        if "RSA" in kt and kb and kb < 2048:
            findings.append(dict(
                severity="MEDIUM",
                category="Weak/Expired Certificate",
                src=ctx, dst="N/A",
                detail=f"Weak RSA key: {kb}-bit (minimum 2048): {cert.get('subject','')}",
                recommendation="Reissue certificate with an RSA key >= 2048 bits",
            ))
        elif "ECDSA" in kt and kb and kb < 256:
            findings.append(dict(
                severity="MEDIUM",
                category="Weak/Expired Certificate",
                src=ctx, dst="N/A",
                detail=f"Weak EC key: {kb}-bit: {cert.get('subject','')}",
                recommendation="Reissue certificate with an EC key >= 256 bits",
            ))

    return findings
