"""Tests for pcap_tool.demo: the all-in-one sample captures used by the web
dashboard's "download a sample capture" feature."""

from pcap_tool.demo.scenario import build_demo_pcap, build_demo_wifi_pcap
from pcap_tool.cli import run_pipeline
from pcap_tool.parser import parse_pcap
from pcap_tool.extractors.wifi import extract_wifi_events

from .conftest import write_pcap


EXPECTED_CATEGORIES = {
    "Cleartext Protocol",
    "Suspicious Port",
    "ARP Anomaly / Possible MITM",
    "Unusual Outbound",
    "Potential Beaconing",
    "Lateral Movement Indicator",
    "SNMP Cleartext",
    "Port Scan",
    "Possible Exfiltration / Top Talker",
    "DNS Tunneling Indicator",
    "ICMP Tunneling Indicator",
    "EAP-TLS Client Identity Disclosure",
    "Weak/Expired Certificate",
}


def test_build_demo_pcap_triggers_all_findings(tmp_path):
    data = build_demo_pcap()
    path = tmp_path / "demo.pcap"
    path.write_bytes(data)

    result = run_pipeline(str(path), title="Demo")

    categories = {f["category"] for f in result["findings"]}
    missing = EXPECTED_CATEGORIES - categories
    assert not missing, f"missing finding categories: {missing}"

    assert result["cleartext_hits"], "expected cleartext credential hits"
    assert result["banner_hits"], "expected service banners"
    assert result["tls_sessions"], "expected TLS sessions"
    assert result["dns_events"], "expected DNS events"
    assert result["traceroutes"], "expected traceroute paths"
    assert result["certificates"], "expected extracted certificates"


def test_build_demo_wifi_pcap(tmp_path):
    data = build_demo_wifi_pcap()
    path = tmp_path / "demo_wifi.pcapng"
    path.write_bytes(data)

    packets = list(parse_pcap(str(path)))
    wifi_data = extract_wifi_events(packets)

    assert any(ap["ssid"] == "DemoCorp-WiFi" for ap in wifi_data["aps"])
    assert any(e["frame_type"] == "Deauthentication" for e in wifi_data["events"])
