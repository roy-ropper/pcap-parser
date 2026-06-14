"""Hostname source loading and passive hostname resolution from packet data."""

import os

from ..extractors.dns import _parse_dns, _parse_dhcp, _parse_nbns


def load_hostname_file(path):
    result = {}
    if not path or not os.path.exists(path): return result
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"): continue
            parts = line.split(None, 1)
            if len(parts) == 2: result[parts[0]] = parts[1]
    return result


def resolve_hostnames_from_packets(packets):
    """
    Single-pass scan to build ip→hostname from data inside the capture.
    Sources (priority, lower = more trusted):
      1. DNS A/AAAA responses
      2. DHCP Option 12 (client self-reported hostname)
      3. mDNS A/AAAA responses
      4. NetBIOS Name Service registrations
      5. HTTP Host header (lowest — labels the destination only)
    """
    pending = {}   # ip -> (hostname, priority)

    def _set(ip, name, priority):
        name = name.rstrip(".").strip()
        if not name or not ip or ip in ("0.0.0.0", "255.255.255.255"):
            return
        existing = pending.get(ip)
        if existing is None or priority < existing[1]:
            pending[ip] = (name, priority)

    for p in packets:
        proto   = p.get("proto", "")
        payload = p.get("app_payload", b"")
        src_ip  = p.get("src_ip", "")
        dst_ip  = p.get("dst_ip", "")
        dp      = p.get("dst_port", 0)

        if proto in ("DNS", "mDNS") and payload:
            _parse_dns(payload, _set)

        if proto == "DHCP" and payload:
            _parse_dhcp(payload, _set)

        if proto == "NetBIOS" and payload:
            _parse_nbns(payload, src_ip, _set)

        if proto in ("HTTP", "HTTP-alt") and payload:
            try:
                text = payload.decode("ascii", errors="ignore")
                for line in text.split("\r\n"):
                    if line.lower().startswith("host:"):
                        host = line.split(":", 1)[1].strip().split(":")[0]
                        if host and not host.replace(".", "").isdigit():
                            _set(dst_ip, host, 5)
                        break
            except Exception:
                pass

    return {ip: name for ip, (name, _) in pending.items()}
