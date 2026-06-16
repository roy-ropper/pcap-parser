"""Tests for pcap_tool.extractors.names and related LLMNR findings."""

import pytest

from pcap_tool.extractors.names import extract_network_names
from pcap_tool.graph.findings import compute_llmnr_findings
from pcap_tool.parser import parse_pcap

from .conftest import (
    dhcp_offer_frame, llmnr_query_frame, llmnr_response_frame,
    dns_query_frame,
    write_pcap,
)


# ── helpers ───────────────────────────────────────────────────────────────────

def _pcap(tmp_path, frames, name="test.pcap"):
    return write_pcap(tmp_path / name, frames)


def _packets(tmp_path, frames, name="test.pcap"):
    path = _pcap(tmp_path, frames, name)
    return list(parse_pcap(path))


# ── DHCP Option 15 (domain suffix) ───────────────────────────────────────────

def test_dhcp_domain_suffix_extracted(tmp_path):
    """DHCP OFFER with opt-15 → domain_suffix in lease, domain in discovered_domains."""
    frame = dhcp_offer_frame(
        src_mac="aa:bb:cc:dd:ee:01",
        src_ip="10.0.0.1",
        client_mac="11:22:33:44:55:01",
        offered_ip="10.0.0.5",
        hostname="workstation01",
        domain_suffix="corp.local",
    )
    packets = _packets(tmp_path, [frame])
    result = extract_network_names(packets)

    assert "corp.local" in result["discovered_domains"]
    lease = next((l for l in result["dhcp_leases"] if l["ip"] == "10.0.0.5"), None)
    assert lease is not None
    assert lease["domain_suffix"] == "corp.local"
    assert lease["hostname"] == "workstation01"


def test_fqdns_built_from_dhcp_opt12_plus_opt15(tmp_path):
    """opt-12 hostname + opt-15 domain suffix → FQDN constructed and in fqdns dict."""
    frame = dhcp_offer_frame(
        src_mac="aa:bb:cc:dd:ee:01",
        src_ip="10.0.0.1",
        client_mac="11:22:33:44:55:02",
        offered_ip="10.0.0.10",
        hostname="ws02",
        domain_suffix="eng.local",
    )
    packets = _packets(tmp_path, [frame])
    result = extract_network_names(packets)

    assert result["fqdns"].get("10.0.0.10") == "ws02.eng.local"
    lease = next((l for l in result["dhcp_leases"] if l["ip"] == "10.0.0.10"), None)
    assert lease is not None
    assert lease["fqdn"] == "ws02.eng.local"


def test_dhcp_no_domain_suffix_bare_hostname_only(tmp_path):
    """DHCP OFFER with opt-12 only (no opt-15) → hostname stored, fqdn is None."""
    frame = dhcp_offer_frame(
        src_mac="aa:bb:cc:dd:ee:01",
        src_ip="10.0.0.1",
        client_mac="11:22:33:44:55:03",
        offered_ip="10.0.0.20",
        hostname="laptop03",
        domain_suffix=None,
    )
    packets = _packets(tmp_path, [frame])
    result = extract_network_names(packets)

    lease = next((l for l in result["dhcp_leases"] if l["ip"] == "10.0.0.20"), None)
    assert lease is not None
    assert lease["hostname"] == "laptop03"
    assert lease["fqdn"] is None
    assert "10.0.0.20" not in result["fqdns"]


def test_dhcp_mac_extracted_from_chaddr(tmp_path):
    """The client MAC is read from the BOOTP chaddr field, not the Ethernet src."""
    frame = dhcp_offer_frame(
        src_mac="aa:bb:cc:dd:ee:01",   # server MAC
        src_ip="10.0.0.1",
        client_mac="de:ad:be:ef:00:01",  # client MAC in chaddr
        offered_ip="10.0.0.30",
        hostname="host30",
        domain_suffix="home.arpa",
    )
    packets = _packets(tmp_path, [frame])
    result = extract_network_names(packets)

    lease = next((l for l in result["dhcp_leases"] if l["ip"] == "10.0.0.30"), None)
    assert lease is not None
    assert lease["mac"] == "de:ad:be:ef:00:01"


# ── LLMNR query/response detection ───────────────────────────────────────────

def test_llmnr_query_detected(tmp_path):
    """A UDP/5355 query packet → appears in llmnr_queries as a query event."""
    frame = llmnr_query_frame(
        src_mac="11:22:33:44:55:01",
        src_ip="10.0.0.50",
        query_name="fileserver",
    )
    packets = _packets(tmp_path, [frame])
    result = extract_network_names(packets)

    queries = result["llmnr_queries"]
    assert queries, "expected at least one LLMNR event"
    q = next((e for e in queries if e["query"] == "fileserver"), None)
    assert q is not None, "query for 'fileserver' not found"
    assert q["src_ip"] == "10.0.0.50"
    assert q["is_response"] is False
    assert q["answer_ip"] is None


def test_llmnr_response_detected(tmp_path):
    """A UDP/5355 response packet → appears in llmnr_queries as a response event."""
    query_frame = llmnr_query_frame(
        src_mac="11:22:33:44:55:01", src_ip="10.0.0.50", query_name="dc01")
    resp_frame = llmnr_response_frame(
        src_mac="22:33:44:55:66:01", src_ip="10.0.0.99",
        query_name="dc01", answer_ip="10.0.0.99",
        dst_mac="11:22:33:44:55:01", dst_ip="10.0.0.50")

    packets = _packets(tmp_path, [query_frame, resp_frame])
    result = extract_network_names(packets)

    responses = [e for e in result["llmnr_queries"] if e["is_response"]]
    assert responses, "expected at least one LLMNR response event"
    r = next((e for e in responses if e["query"] == "dc01"), None)
    assert r is not None
    assert r["src_ip"] == "10.0.0.99"
    assert r["answer_ip"] == "10.0.0.99"


# ── LLMNR Poisoning finding ───────────────────────────────────────────────────

def test_llmnr_poisoning_finding_raised(tmp_path):
    """Response from unexpected host with answer_ip != its own hostname → HIGH finding."""
    resp_frame = llmnr_response_frame(
        src_mac="bb:ad:bb:ad:00:01", src_ip="10.0.0.99",
        query_name="fileserver", answer_ip="10.0.0.99",
        dst_mac="11:22:33:44:55:01", dst_ip="10.0.0.50")

    packets = _packets(tmp_path, [resp_frame])
    result = extract_network_names(packets)

    # Nodes: the responder has a different hostname so the finding fires
    nodes = {"10.0.0.99": {"hostname": "attacker-pc"}}
    gateways = {}

    findings = compute_llmnr_findings(result["llmnr_queries"], nodes, gateways)
    assert any(f["category"] == "LLMNR Poisoning Indicator" for f in findings)
    pf = next(f for f in findings if f["category"] == "LLMNR Poisoning Indicator")
    assert pf["severity"] == "HIGH"
    assert pf["src"] == "10.0.0.99"


def test_no_false_positive_when_host_owns_name(tmp_path):
    """If the LLMNR responder's own hostname matches the queried name → no finding."""
    resp_frame = llmnr_response_frame(
        src_mac="22:33:44:55:66:aa", src_ip="10.0.0.20",
        query_name="printserver", answer_ip="10.0.0.20",
        dst_mac="11:22:33:44:55:01", dst_ip="10.0.0.50")

    packets = _packets(tmp_path, [resp_frame])
    result = extract_network_names(packets)

    # The responder IS "printserver" — no poisoning
    nodes = {"10.0.0.20": {"hostname": "printserver.corp.local"}}
    gateways = {}

    findings = compute_llmnr_findings(result["llmnr_queries"], nodes, gateways)
    poisoning = [f for f in findings if f["category"] == "LLMNR Poisoning Indicator"]
    assert not poisoning, "should not flag when host legitimately owns the queried name"


def test_no_false_positive_gateway_responds(tmp_path):
    """LLMNR response from the known gateway → no poisoning finding."""
    resp_frame = llmnr_response_frame(
        src_mac="aa:bb:cc:dd:ee:ff", src_ip="10.0.0.1",
        query_name="anything", answer_ip="10.0.0.1",
        dst_mac="11:22:33:44:55:01", dst_ip="10.0.0.50")

    packets = _packets(tmp_path, [resp_frame])
    result = extract_network_names(packets)

    nodes = {"10.0.0.1": {"hostname": "router"}}
    gateways = {"10.0.0.0/24": "10.0.0.1"}

    findings = compute_llmnr_findings(result["llmnr_queries"], nodes, gateways)
    poisoning = [f for f in findings if f["category"] == "LLMNR Poisoning Indicator"]
    assert not poisoning, "gateway responses should not be flagged"


# ── Discovered domains from DNS query patterns ────────────────────────────────

def test_discovered_domains_from_dns_events(tmp_path):
    """Recurring DNS queries for *.corp.internal → corp.internal in discovered_domains."""
    # We don't need real packets for this — pass dns_events directly
    fake_dns_events = [
        {"query_name": f"host{i}.corp.internal", "is_response": False,
         "rcode": "NOERROR", "client_ip": "10.0.0.5"}
        for i in range(5)
    ]
    result = extract_network_names([], dns_events=fake_dns_events)
    assert "corp.internal" in result["discovered_domains"]


def test_discovered_domains_requires_min_count(tmp_path):
    """A domain seen only once in DNS queries should NOT appear in discovered_domains."""
    fake_dns_events = [
        {"query_name": "rare.one-off.net", "is_response": False,
         "rcode": "NOERROR", "client_ip": "10.0.0.5"}
    ]
    result = extract_network_names([], dns_events=fake_dns_events)
    assert "one-off.net" not in result["discovered_domains"]
