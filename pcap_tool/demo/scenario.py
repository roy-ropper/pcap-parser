"""Synthetic "all-in-one" demo captures exercising every detector/extractor.

`build_demo_pcap()` returns a single Ethernet `.pcap` (link-type 1) whose
traffic is engineered to trip every pentest finding category and every
extractor (cleartext creds, banners, TLS/certs, DNS, EAP-TLS, ICMP
traceroute). `build_demo_wifi_pcap()` returns a small 802.11/radiotap
`.pcapng` (link-type 127) with a beacon + deauth frame for the WiFi survey
extractor — 802.11 monitor-mode framing can't share a pcap with Ethernet, so
it's a second file.

These are served by the web dashboard's "download a sample capture" feature
(see web/app.py) and exercised by tests/test_demo.py.
"""

import datetime
import socket
import struct

from .builders import (
    eth_ip_tcp, eth_ip_udp, eth_ip_icmp, eth_arp,
    dns_query_frame, dns_response_frame,
    wifi_beacon_frame, wifi_deauth_frame,
    pcap_bytes, pcapng_bytes,
    make_certificate_der, tls_client_hello_record, tls_certificate_record,
    eapol_eap_tls_frame,
)

# ── Topology ─────────────────────────────────────────────────────────────────
GATEWAY   = "10.0.0.1"
VICTIM    = "10.0.0.5"
FILESRV   = "10.0.0.10"
LOWPEER   = "10.0.0.20"

ATTACKER  = "45.33.32.156"     # external "attacker" C2 / scan source
BEACON_C2 = "45.33.32.157"     # external beaconing destination
DNS_SRV   = "8.8.8.8"
WEB_SNI   = "93.184.216.34"    # plain TLS + SNI
WEB_WEAK  = "93.184.216.99"    # weak/expired cert
ROUTER2   = "172.20.0.1"       # second traceroute hop

MAC_GW       = "aa:aa:aa:aa:aa:aa"
MAC_VICTIM   = "bb:bb:bb:bb:bb:bb"
MAC_FILESRV  = "cc:cc:cc:cc:cc:cc"
MAC_LOWPEER  = "dd:dd:dd:dd:dd:dd"
MAC_ATTACKER = "ee:ee:ee:ee:ee:ee"
MAC_EXT      = "ff:ee:dd:cc:bb:aa"
MAC_SCANHOST = "44:44:44:44:44:44"
MAC_SUPPLICANT   = "11:22:33:44:55:66"
MAC_AUTHENTICATOR = "22:22:22:22:22:22"


def build_demo_pcap():
    """Build the primary Ethernet demo capture (link-type 1, classic .pcap)."""
    frames = []

    # ── 1. Cleartext credentials (FTP, HTTP Basic Auth, SNMP) ────────────────
    frames.append(eth_ip_tcp(MAC_VICTIM, MAC_FILESRV, VICTIM, FILESRV,
                              50001, 21, b"USER admin\r\n"))
    frames.append(eth_ip_tcp(MAC_VICTIM, MAC_FILESRV, VICTIM, FILESRV,
                              50001, 21, b"PASS Sup3rSecret!\r\n"))

    http_req = (b"GET /admin HTTP/1.1\r\nHost: intranet.corp.example\r\n"
                b"Authorization: Basic YWRtaW46cGFzc3dvcmQ=\r\n\r\n")
    frames.append(eth_ip_tcp(MAC_VICTIM, MAC_FILESRV, VICTIM, FILESRV,
                              50002, 80, http_req))
    http_resp = (b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Ubuntu)\r\n"
                  b"Content-Length: 2\r\n\r\nOK")
    frames.append(eth_ip_tcp(MAC_FILESRV, MAC_VICTIM, FILESRV, VICTIM,
                              80, 50002, http_resp))

    snmp_payload = (b"\x30\x29\x02\x01\x00\x04\x0bmycommunity"
                     b"\xa0\x1b\x02\x04\x00\x00\x00\x01")
    frames.append(eth_ip_udp(MAC_VICTIM, MAC_GW, VICTIM, GATEWAY,
                              50003, 161, snmp_payload))

    # ── 2. Suspicious port (Metasploit default) ──────────────────────────────
    frames.append(eth_ip_tcp(MAC_VICTIM, MAC_ATTACKER, VICTIM, ATTACKER,
                              50004, 4444, b"", flags=0x02))

    # ── 3. ARP spoofing: 10.0.0.1 claimed by two different MACs ──────────────
    frames.append(eth_arp(MAC_GW, MAC_VICTIM, MAC_GW, GATEWAY,
                           MAC_VICTIM, VICTIM, op=2))
    frames.append(eth_arp(MAC_ATTACKER, MAC_VICTIM, MAC_ATTACKER, GATEWAY,
                           MAC_VICTIM, VICTIM, op=2))

    # ── 4 & 5. Unusual outbound + beaconing: 8 evenly-spaced connections ─────
    for i in range(8):
        beacon = eth_ip_tcp(MAC_VICTIM, MAC_EXT, VICTIM, BEACON_C2,
                             51000 + i, 8443, b"", flags=0x02)
        frames.append((0, i * 100000, beacon))

    # ── 6. Lateral movement: SMB from victim to a quiet workstation ──────────
    frames.append(eth_ip_tcp(MAC_VICTIM, MAC_LOWPEER, VICTIM, LOWPEER,
                              50010, 445, b"\x00\x00\x00\x00SMB negotiate"))

    # ── 7. Port scans (vertical + horizontal) ────────────────────────────────
    # Vertical: attacker probes 16 distinct ports on the victim.
    for i, port in enumerate(range(2000, 2016)):
        frames.append((0, i * 100, eth_ip_tcp(MAC_ATTACKER, MAC_VICTIM,
                                               ATTACKER, VICTIM,
                                               40000, port, b"", flags=0x02)))
    # Horizontal: attacker probes the same port across 11 internal hosts.
    for i in range(11):
        target = f"10.0.0.{30 + i}"
        frames.append((0, i * 100, eth_ip_tcp(MAC_ATTACKER, MAC_SCANHOST,
                                               ATTACKER, target,
                                               40001, 3389, b"", flags=0x02)))

    # ── 8. Exfiltration: ~10 MB internal -> external over TCP/443 ───────────
    # (payload capped under 65535 so the IPv4 total-length field fits)
    big_payload = b"X" * 65000
    for i in range(155):
        frames.append(eth_ip_tcp(MAC_VICTIM, MAC_ATTACKER, VICTIM, ATTACKER,
                                  52000 + i, 443, big_payload))

    # ── 9. DNS tunneling: long label + NXDOMAIN flood ────────────────────────
    long_label = "a" * 40
    frames.append(dns_query_frame(MAC_VICTIM, MAC_EXT, VICTIM, DNS_SRV,
                                   53000, f"{long_label}.evil.example"))
    for i in range(11):
        frames.append(dns_response_frame(MAC_EXT, MAC_VICTIM, DNS_SRV, VICTIM,
                                           53, 53100 + i,
                                           f"sub{i}.tunnel.example", rcode=3))

    # ── 10. ICMP tunneling: oversized ICMP echo requests ─────────────────────
    for i in range(6):
        frames.append(eth_ip_icmp(MAC_VICTIM, MAC_ATTACKER, VICTIM, ATTACKER,
                                   8, 0, b"Y" * 100, seq=i))

    # ── 11. EAP-TLS over wired 802.1X — client identity disclosure ──────────
    now = datetime.datetime.utcnow()
    alice_cert = make_certificate_der(
        "alice@corp.example", "Corp Issuing CA",
        not_before=now - datetime.timedelta(days=365),
        not_after=now + datetime.timedelta(days=365),
        key_bits=2048,
    )
    frames.append(eapol_eap_tls_frame(
        MAC_SUPPLICANT, MAC_AUTHENTICATOR,
        tls_certificate_record([alice_cert]),
    ))

    # ── 12. Weak/expired certificate ─────────────────────────────────────────
    weak_cert = make_certificate_der(
        "badcert.example", "Old Internal CA",
        not_before=now - datetime.timedelta(days=365 * 5),
        not_after=now - datetime.timedelta(days=365),
        key_bits=512,
    )
    frames.append(eth_ip_tcp(MAC_VICTIM, MAC_EXT, VICTIM, WEB_WEAK,
                              51010, 443, tls_client_hello_record()))
    frames.append(eth_ip_tcp(MAC_EXT, MAC_VICTIM, WEB_WEAK, VICTIM,
                              443, 51010, tls_certificate_record([weak_cert])))

    # ── 13. Plain TLS + SNI ───────────────────────────────────────────────────
    frames.append(eth_ip_tcp(MAC_VICTIM, MAC_EXT, VICTIM, WEB_SNI,
                              51020, 443,
                              tls_client_hello_record(sni_host="example.com")))

    # ── 14. Traceroute: ICMP Time-Exceeded from two intermediate routers ────
    inner_hdr = struct.pack(">BBHHHBBH4s4s",
                             0x45, 0, 28, 0, 0x4000, 1, 17, 0,
                             socket.inet_aton(VICTIM), socket.inet_aton(DNS_SRV))
    frames.append(eth_ip_icmp(MAC_GW, MAC_VICTIM, GATEWAY, VICTIM,
                               11, 0, inner_hdr))
    frames.append(eth_ip_icmp(MAC_EXT, MAC_VICTIM, ROUTER2, VICTIM,
                               11, 0, inner_hdr))

    return pcap_bytes(frames, ltype=1)


def build_demo_wifi_pcap():
    """Build the secondary 802.11/radiotap demo capture (link-type 127, .pcapng)."""
    beacon = wifi_beacon_frame("DemoCorp-WiFi", bssid="aa:bb:cc:dd:ee:ff", channel=6)
    deauth = wifi_deauth_frame("11:22:33:44:55:66", bssid="aa:bb:cc:dd:ee:ff", reason=7)
    return pcapng_bytes([beacon, deauth], ltype=127)
