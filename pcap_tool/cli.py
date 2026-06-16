"""Command-line entry point and pipeline orchestration."""

import argparse
import base64
import ipaddress
import os
import sys

from .parser import parse_pcap
from .graph.build import build_graph
from .graph.findings import compute_certificate_findings, compute_dns_findings, compute_llmnr_findings
from .graph.gateways import detect_gateways
from .graph.hostnames import load_hostname_file, resolve_hostnames_from_packets
from .extractors.traceroute import extract_traceroutes
from .extractors.banners import extract_banners
from .extractors.tls import extract_tls_sessions
from .extractors.certificates import extract_certificates
from .extractors.dns import extract_dns_events
from .extractors.names import extract_network_names
from .extractors.wifi import extract_wifi_events
from .topology.model import build_topology
from .topology.render_policy import select_edges
from .diagrams.drawio_topology import generate_topology_drawio
from .diagrams.topology_svg import generate_topology_svg
from .diagrams.drawio_l2 import generate_l2_drawio
from .diagrams.vsdx import generate_vsdx
from .excel.workbook import generate_xlsx


# Major pipeline stages, in order — used to report a 0-100% progress value
# and a human-readable "current module" label to the web dashboard.
PIPELINE_STAGES = [
    "Parsing capture",
    "Building network graph",
    "Detecting gateways",
    "Reconstructing traceroutes",
    "Extracting banners & resources",
    "Analysing TLS sessions",
    "Extracting DNS events",
    "Extracting network names (DHCP/LLMNR)",
    "Surveying Wi-Fi (802.11)",
    "Extracting certificates",
    "Generating diagrams",
]


def write_certs_to_dir(certificates, certs_dir):
    """Write each certificate's DER and PEM-encoded bytes to `certs_dir`."""
    os.makedirs(certs_dir, exist_ok=True)
    for i, cert in enumerate(certificates, 1):
        der = cert.get("der_bytes", b"")
        if not der:
            continue
        fp8 = cert.get("fingerprint_sha256", "")[:8] or f"{i:04d}"
        base = f"cert_{i:02d}_{fp8}"
        with open(os.path.join(certs_dir, base + ".der"), "wb") as f:
            f.write(der)
        b64 = base64.encodebytes(der).decode("ascii")
        pem = "-----BEGIN CERTIFICATE-----\n" + b64 + "-----END CERTIFICATE-----\n"
        with open(os.path.join(certs_dir, base + ".pem"), "w", encoding="ascii") as f:
            f.write(pem)


def run_pipeline(pcap_path, min_packets=1, collapse_external=False,
                 hostname_file=None, internal_networks=None, title="Network Diagram",
                 certs_dir=None, progress_cb=None):
    """
    Run the full parse → analyse → diagram pipeline and return a results dict.

    `progress_cb`, if given, is called as `progress_cb(msg, pct, stage_label)`
    with a human-readable status string at each major stage — used by both
    the CLI (printed to stdout) and the web dashboard (surfaced as job
    progress, including a percent-complete value and the current stage's
    label so the user can see it hasn't hung). `pct`/`stage_label` are None
    for intermediate detail messages within a stage.
    """
    def progress(msg, stage=None):
        if progress_cb:
            if stage is not None:
                pct = round(100 * stage / len(PIPELINE_STAGES))
                progress_cb(msg, pct, PIPELINE_STAGES[stage])
            else:
                progress_cb(msg, None, None)

    progress(f"[*] Parsing {pcap_path} ...", stage=0)
    packets = list(parse_pcap(pcap_path))

    progress(f"[*] {len(packets):,} packets")
    if not packets:
        raise ValueError("No packets — valid PCAP?")

    extra_hn = load_hostname_file(hostname_file)
    if internal_networks:
        parsed = []
        for cidr in internal_networks:
            try:
                parsed.append(ipaddress.ip_network(cidr, strict=False))
                progress(f"[*] Treating {cidr} as internal network")
            except ValueError as e:
                progress(f"[!] Bad --internal-networks value '{cidr}': {e}")
        if parsed:
            extra_hn["__internal_networks__"] = parsed

    progress("[*] Building network graph ...", stage=1)
    nodes, edges, rows, findings, cleartext_hits, arp_table = build_graph(
        packets, min_packets, collapse_external, extra_hn)

    unique_conn = len({tuple(sorted(p)) for p in edges})
    subnets     = len({n["subnet"] for n in nodes.values()})
    progress(f"[*] {len(nodes)} nodes · {unique_conn} connections · {subnets} subnets")
    progress(f"[*] {len(findings)} pentest findings  "
             f"({sum(1 for f in findings if f['severity']=='CRITICAL')} CRITICAL  "
             f"{sum(1 for f in findings if f['severity']=='HIGH')} HIGH  "
             f"{sum(1 for f in findings if f['severity']=='MEDIUM')} MEDIUM)")

    # Gateway detection
    progress("[*] Detecting gateways ...", stage=2)
    gateways = detect_gateways(packets, nodes)
    if gateways:
        progress(f"[*] {len(gateways)} gateway(s) detected: " +
                 ", ".join(f"{s}→{ip}" for s,ip in gateways.items()))
    else:
        progress("[*] No gateways detected")

    # Traceroute reconstruction
    progress("[*] Reconstructing traceroutes ...", stage=3)
    traceroutes = extract_traceroutes(packets)
    passive_hn = resolve_hostnames_from_packets(packets)
    all_hn = {**passive_hn, **extra_hn}
    for tr in traceroutes:
        tr["src_hostname"] = all_hn.get(tr["src"], "")
        tr["dst_hostname"] = all_hn.get(tr["dst"], "")
        for hop in tr["hops"]:
            hop["hostname"] = all_hn.get(hop["router_ip"], "")
    if traceroutes:
        progress(f"[*] {len(traceroutes)} traceroute path(s) reconstructed")
        for tr in traceroutes:
            hops_str = " → ".join(h["hostname"] or h["router_ip"] for h in tr["hops"])
            progress(f"    {tr['src']} → [{hops_str}] → {tr['dst']}")

    # Banner / resource extraction
    progress("[*] Extracting banners & resources ...", stage=4)
    banner_hits = extract_banners(packets)
    dns_hits    = [b for b in banner_hits if b["banner_type"] == "DNS Query"]
    svc_banners = [b for b in banner_hits if b["category"] == "Banner"]
    resources   = [b for b in banner_hits if b["category"] == "Resource" and b["banner_type"] != "DNS Query"]
    progress(f"[*] {len(svc_banners)} service banners · {len(resources)} resources · {len(dns_hits)} DNS queries")

    # TLS handshake analysis
    progress("[*] Analysing TLS sessions ...", stage=5)
    tls_sessions = extract_tls_sessions(packets)
    n_tls_issues = sum(1 for s in tls_sessions if s.get("issues"))
    progress(f"[*] {len(tls_sessions)} TLS session(s) reconstructed  "
             f"({n_tls_issues} with issues)")

    # DNS / mDNS event log
    progress("[*] Extracting DNS events ...", stage=6)
    dns_events = extract_dns_events(packets)
    n_mdns     = sum(1 for e in dns_events if e.get("proto") == "mDNS")
    n_nxdomain = sum(1 for e in dns_events if e.get("rcode") == "NXDOMAIN")
    progress(f"[*] {len(dns_events)} DNS events extracted  "
             f"({n_mdns} mDNS · {n_nxdomain} NXDOMAIN)")
    dns_findings = compute_dns_findings(dns_events)
    if dns_findings:
        findings.extend(dns_findings)
        progress(f"[*] {len(dns_findings)} DNS tunneling indicator(s) flagged")

    # Network naming context (DHCP leases, LLMNR, discovered domains)
    progress("[*] Extracting network names (DHCP/LLMNR) ...", stage=7)
    network_names = extract_network_names(packets, dns_events=dns_events)
    # Merge FQDNs into node hostnames (FQDN > bare DHCP hostname)
    for ip, fqdn in network_names["fqdns"].items():
        if ip in nodes:
            nodes[ip]["fqdn"] = fqdn
            if not nodes[ip]["hostname"] or "." not in nodes[ip]["hostname"]:
                nodes[ip]["hostname"] = fqdn

    # Build hosts_by_domain: for each discovered domain, collect unique {ip, hostname} pairs
    # from node hostnames and DHCP leases so the dashboard can display a per-domain host table.
    hosts_by_domain = {}
    for domain in network_names["discovered_domains"]:
        seen_ips = set()
        hosts = []
        suffix = "." + domain
        for ip, node in nodes.items():
            hn = node.get("fqdn") or node.get("hostname") or ""
            if hn == domain or hn.endswith(suffix):
                if ip not in seen_ips:
                    seen_ips.add(ip)
                    hosts.append({"ip": ip, "hostname": hn})
        for lease in network_names["dhcp_leases"]:
            if lease.get("domain_suffix") == domain:
                lip = lease.get("ip", "")
                if lip and lip not in seen_ips:
                    seen_ips.add(lip)
                    hosts.append({"ip": lip,
                                  "hostname": lease.get("fqdn") or lease.get("hostname") or ""})
        hosts_by_domain[domain] = sorted(hosts, key=lambda h: h["ip"])
    network_names["hosts_by_domain"] = hosts_by_domain

    n_dom = len(network_names["discovered_domains"])
    n_leases = len(network_names["dhcp_leases"])
    n_llmnr = len(network_names["llmnr_queries"])
    progress(f"[*] Domains: {', '.join(network_names['discovered_domains']) or 'none discovered'}")
    progress(f"[*] {n_leases} DHCP lease(s) · {n_llmnr} LLMNR event(s) · {n_dom} domain(s)")
    llmnr_findings = compute_llmnr_findings(
        network_names["llmnr_queries"], nodes, gateways)
    if llmnr_findings:
        findings.extend(llmnr_findings)
        progress(f"[*] {len(llmnr_findings)} LLMNR poisoning indicator(s) flagged")

    # Wi-Fi 802.11 network survey
    progress("[*] Surveying Wi-Fi (802.11) ...", stage=8)
    wifi_data   = extract_wifi_events(packets)
    n_aps       = len(wifi_data["aps"])
    n_clients   = len(wifi_data["clients"])
    n_deauths   = sum(1 for e in wifi_data["events"] if e.get("frame_type") == "Deauthentication")
    if n_aps or n_clients:
        progress(f"[*] Wi-Fi survey: {n_aps} AP(s) · {n_clients} client(s) · {n_deauths} deauth frame(s)")
    else:
        progress("[*] No 802.11 frames detected (not a Wi-Fi capture)")

    # Certificate extraction (TLS + EAP-TLS/802.1X)
    progress("[*] Extracting certificates ...", stage=9)
    certificates = extract_certificates(packets, tls_sessions, wifi_data)
    n_eaptls = sum(1 for c in certificates if c["source"] == "EAP-TLS")
    if certificates:
        progress(f"[*] {len(certificates)} certificate(s) extracted "
                 f"({n_eaptls} from EAP-TLS/802.1X)")
        findings.extend(compute_certificate_findings(certificates))
    if certs_dir and certificates:
        write_certs_to_dir(certificates, certs_dir)
        progress(f"[*] {len(certificates)} certificate(s) written → {certs_dir}/")

    progress("[*] Generating diagrams ...", stage=10)

    _partial = dict(
        packets=packets, nodes=nodes, edges=edges, findings=findings,
        cleartext_hits=cleartext_hits, gateways=gateways,
        traceroutes=traceroutes, wifi_data=wifi_data, title=title,
    )
    topology = build_topology(_partial)
    render = select_edges(topology)
    drawio_l3_xml = generate_topology_drawio(topology, render, title=title)
    topology_svg = generate_topology_svg(topology, render, title=title)
    progress(f"[*] Topology diagram generated "
             f"({len(render.edges)} edges rendered, "
             f"{len(render.node_summaries)} nodes summarised)")

    drawio_l2_xml = generate_l2_drawio(wifi_data, nodes, arp_table,
                                        title=f"{title} — L2/Wi-Fi Topology")
    vsdx_bytes = generate_vsdx(nodes, edges, findings, gateways, title=title).getvalue()
    progress("[*] Visio (.vsdx) diagram generated")

    return dict(
        packets=packets,
        nodes=nodes, edges=edges, rows=rows,
        findings=findings, cleartext_hits=cleartext_hits, arp_table=arp_table,
        gateways=gateways, traceroutes=traceroutes,
        banner_hits=banner_hits, tls_sessions=tls_sessions,
        dns_events=dns_events, wifi_data=wifi_data,
        certificates=certificates,
        network_names=network_names,
        drawio_l3_xml=drawio_l3_xml, drawio_l2_xml=drawio_l2_xml,
        vsdx_bytes=vsdx_bytes,
        topology_svg=topology_svg,
        capture_device=topology.capture_device,
        title=title,
    )


def main():
    ap = argparse.ArgumentParser(
        description="PCAP → draw.io + Excel  (v4.0 Pentester Edition)")
    ap.add_argument("pcap")
    ap.add_argument("-o","--output",  help=".drawio output path")
    ap.add_argument("--xlsx",         help=".xlsx output path")
    ap.add_argument("--min-packets",  type=int, default=1)
    ap.add_argument("--collapse-external", action="store_true")
    ap.add_argument("--hostname-file", metavar="FILE")
    ap.add_argument("--title", default="Network Diagram")
    ap.add_argument("--l2-output", metavar="FILE",
                    help=".drawio output path for L2/Wi-Fi topology diagram "
                         "(default: <input>_l2.drawio)")
    ap.add_argument("--vsdx-output", metavar="FILE",
                    help=".vsdx (Visio) output path (default: <input>.vsdx)")
    ap.add_argument("--internal-networks", metavar="CIDR", nargs="+",
                    help="Additional CIDR ranges to treat as internal "
                         "(e.g. 20.16.0.0/14 for corporate non-RFC1918 space)")
    ap.add_argument("--certs-dir", metavar="DIR",
                    help="Directory to write extracted certificates (.der/.pem) to "
                         "(default: <input>_certs/, only created if certs are found)")
    args = ap.parse_args()

    base    = args.pcap.rsplit(".",1)[0]
    out_dio = args.output or base+".drawio"
    out_xl  = args.xlsx   or base+".xlsx"
    out_l2  = getattr(args, "l2_output", None) or base+"_l2.drawio"
    out_vsdx = args.vsdx_output or base+".vsdx"
    certs_dir = args.certs_dir or base+"_certs"

    try:
        result = run_pipeline(
            args.pcap,
            min_packets=args.min_packets,
            collapse_external=args.collapse_external,
            hostname_file=args.hostname_file,
            internal_networks=args.internal_networks,
            title=args.title,
            certs_dir=certs_dir,
            progress_cb=lambda msg, pct=None, stage=None: print(msg),
        )
    except FileNotFoundError:
        print(f"[!] Not found: {args.pcap}", file=sys.stderr); sys.exit(1)
    except ValueError as e:
        print(f"[!] {e}", file=sys.stderr); sys.exit(1)

    with open(out_dio,"w",encoding="utf-8") as f:
        f.write(result["drawio_l3_xml"])
    print(f"[+] Diagram  → {out_dio}")

    with open(out_l2,"w",encoding="utf-8") as f:
        f.write(result["drawio_l2_xml"])
    print(f"[+] L2 Diagram → {out_l2}")

    with open(out_vsdx,"wb") as f:
        f.write(result["vsdx_bytes"])
    print(f"[+] Visio    → {out_vsdx}")

    ok = generate_xlsx(result["rows"], result["nodes"], result["edges"], result["findings"],
                        result["cleartext_hits"], result["banner_hits"], result["tls_sessions"],
                        result["dns_events"], result["wifi_data"], out_xl,
                        certificates=result["certificates"],
                        network_names=result.get("network_names"))
    if ok:
        print(f"[+] Workbook → {out_xl}  (12 sheets: Connections, Node Summary, "
              f"Pentest Findings, Protocol Summary, Port Inventory, "
              f"Cleartext Intercepts, Banner Intel, TLS Sessions, "
              f"DNS Events, Wi-Fi Networks, Certificates, Network Names)")

    print()
    print("  draw.io: File → Import From → Device → .drawio file")
    print("  Excel:   Pentest Findings sheet has colour-coded severity rows")
    print("           Node Summary has OS guesses, open ports, and risk flags")


if __name__ == "__main__":
    main()
