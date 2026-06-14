"""Shared helpers for building synthetic packets/pcaps via struct.pack — no
external capture files needed.

All builders live in `pcap_tool.demo.builders` (shared with the web
dashboard's "download a sample capture" demo generator) and are re-exported
here for convenience.
"""

from pcap_tool.demo.builders import (
    eth_frame, ipv4_packet, tcp_segment, udp_segment, icmp_packet, arp_packet,
    eth_ip_tcp, eth_ip_udp, eth_ip_icmp, eth_arp,
    dns_question, dns_query_frame, dns_response_frame,
    wifi_beacon_frame, wifi_deauth_frame,
    pcap_bytes, write_pcap,
    pcapng_bytes, write_pcapng,
    _asn1_len, asn1_tlv, asn1_oid, _rdn, _name, _utctime, _validity,
    _rsa_pubkey_info, make_certificate_der,
    tls_client_hello_record, tls_certificate_record,
    eapol_eap_tls_frame,
)

__all__ = [
    "eth_frame", "ipv4_packet", "tcp_segment", "udp_segment", "icmp_packet", "arp_packet",
    "eth_ip_tcp", "eth_ip_udp", "eth_ip_icmp", "eth_arp",
    "dns_question", "dns_query_frame", "dns_response_frame",
    "wifi_beacon_frame", "wifi_deauth_frame",
    "pcap_bytes", "write_pcap", "pcapng_bytes", "write_pcapng",
    "make_certificate_der", "tls_client_hello_record", "tls_certificate_record",
    "eapol_eap_tls_frame",
]
