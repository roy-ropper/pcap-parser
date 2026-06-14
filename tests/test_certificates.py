"""Tests for pcap_tool.extractors.certificates: TLS + EAP-TLS certificate
extraction and the associated pentest findings."""

import datetime

from pcap_tool.parser import parse_pcap
from pcap_tool.extractors.tls import extract_tls_sessions
from pcap_tool.extractors.certificates import extract_eap_tls_streams, extract_certificates
from pcap_tool.graph.findings import compute_certificate_findings

from .conftest import (
    eth_ip_tcp, write_pcap,
    tls_certificate_record, eapol_eap_tls_frame,
    make_certificate_der,
)


def _future(days):
    return datetime.datetime.utcnow() + datetime.timedelta(days=days)


def _past(days):
    return datetime.datetime.utcnow() - datetime.timedelta(days=days)


# ── TLS-sourced certificates ─────────────────────────────────────────────────

def test_tls_certificate_extraction(tmp_path):
    der = make_certificate_der("www.example.com", "Example CA",
                                 _past(10), _future(300), key_bits=2048)
    record = tls_certificate_record([der])
    frame = eth_ip_tcp("bb:bb:bb:bb:bb:bb", "aa:aa:aa:aa:aa:aa",
                        "10.0.0.5", "93.184.216.34", 50000, 443, record)
    path = write_pcap(tmp_path / "tls_cert.pcap", [frame])
    packets = list(parse_pcap(path))

    tls_sessions = extract_tls_sessions(packets)
    assert tls_sessions[0]["cert_subject"] == "www.example.com"

    certs = extract_certificates(packets, tls_sessions)
    assert len(certs) == 1
    cert = certs[0]
    assert cert["source"] == "TLS"
    assert cert["subject"] == "www.example.com"
    assert cert["issuer"] == "Example CA"
    assert cert["key_type"] == "RSA"
    assert cert["key_bits"] == 2048
    assert cert["expired"] is False
    assert "10.0.0.5" in cert["context"]


def test_expired_certificate_finding(tmp_path):
    der = make_certificate_der("old.example.com", "Example CA",
                                 _past(800), _past(30), key_bits=2048)
    record = tls_certificate_record([der])
    frame = eth_ip_tcp("bb:bb:bb:bb:bb:bb", "aa:aa:aa:aa:aa:aa",
                        "10.0.0.5", "93.184.216.34", 50000, 443, record)
    path = write_pcap(tmp_path / "tls_expired.pcap", [frame])
    packets = list(parse_pcap(path))

    tls_sessions = extract_tls_sessions(packets)
    certs = extract_certificates(packets, tls_sessions)
    assert certs[0]["expired"] is True

    findings = compute_certificate_findings(certs)
    assert any(f["category"] == "Weak/Expired Certificate" and "EXPIRED" in f["detail"]
               for f in findings)


def test_weak_rsa_key_finding(tmp_path):
    der = make_certificate_der("weak.example.com", "Example CA",
                                 _past(10), _future(300), key_bits=1024)
    record = tls_certificate_record([der])
    frame = eth_ip_tcp("bb:bb:bb:bb:bb:bb", "aa:aa:aa:aa:aa:aa",
                        "10.0.0.5", "93.184.216.34", 50000, 443, record)
    path = write_pcap(tmp_path / "tls_weak.pcap", [frame])
    packets = list(parse_pcap(path))

    tls_sessions = extract_tls_sessions(packets)
    certs = extract_certificates(packets, tls_sessions)
    assert certs[0]["key_bits"] == 1024

    findings = compute_certificate_findings(certs)
    assert any(f["category"] == "Weak/Expired Certificate" and "Weak RSA key" in f["detail"]
               for f in findings)


# ── EAP-TLS-sourced certificates ─────────────────────────────────────────────

def test_eap_tls_certificate_extraction_and_identity_disclosure(tmp_path):
    der = make_certificate_der("user@corp.example.com", "Corp RADIUS CA",
                                 _past(10), _future(300), key_bits=2048)
    record = tls_certificate_record([der])
    supplicant_mac = "aa:bb:cc:dd:ee:ff"
    authenticator_mac = "11:22:33:44:55:66"
    frame = eapol_eap_tls_frame(supplicant_mac, authenticator_mac, record)

    path = write_pcap(tmp_path / "eap_tls.pcap", [frame])
    packets = list(parse_pcap(path))
    assert packets[0]["proto"] == "EAPOL"

    streams = extract_eap_tls_streams(packets)
    assert len(streams) == 1
    assert streams[0]["certs"][0]["subject"] == "user@corp.example.com"

    tls_sessions = extract_tls_sessions(packets)  # no ordinary TLS here
    certs = extract_certificates(packets, tls_sessions)
    assert len(certs) == 1
    cert = certs[0]
    assert cert["source"] == "EAP-TLS"
    assert supplicant_mac in cert["context"]
    assert authenticator_mac in cert["context"]

    findings = compute_certificate_findings(certs)
    assert any(f["category"] == "EAP-TLS Client Identity Disclosure"
               and "user@corp.example.com" in f["detail"]
               for f in findings)
