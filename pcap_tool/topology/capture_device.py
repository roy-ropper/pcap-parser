"""Heuristic detection of the capture device (the host whose NIC saw
nearly every frame in the capture)."""

from collections import Counter

_BROADCAST = "ff:ff:ff:ff:ff:ff"
_ZERO_MAC  = "00:00:00:00:00:00"


def _is_multicast(mac):
    try:
        first_octet = int(mac.split(":")[0], 16)
    except (ValueError, AttributeError, IndexError):
        return True
    return bool(first_octet & 1)   # I/G bit


def detect_capture_device(packets, nodes):
    """
    Rank unicast source/destination MACs by how many frames they appear in.
    A NIC in promiscuous/monitor mode sees ~100% of frames; a normal host
    only sees frames addressed to/from itself.

    Returns {"mac", "ip", "hostname", "confidence", "note"}.
    `confidence` is "high" (>=95% and >=20pts clear of runner-up), "medium"
    (>=80%), or "unknown" (mac/ip/hostname are None).
    """
    counts = Counter()
    total = 0
    for p in packets:
        for mac in (p.get("src_mac", ""), p.get("dst_mac", "")):
            if not mac or mac in (_BROADCAST, _ZERO_MAC):
                continue
            if _is_multicast(mac):
                continue
            counts[mac] += 1
            total += 1

    if not counts or total == 0:
        return {
            "mac": None, "ip": None, "hostname": None,
            "confidence": "unknown",
            "note": "Could not determine capture device — no unicast MACs seen.",
        }

    ranked = counts.most_common()
    top_mac, top_count = ranked[0]
    top_pct = 100 * top_count / total
    runner_pct = 100 * ranked[1][1] / total if len(ranked) > 1 else 0.0

    if top_pct >= 95 and (top_pct - runner_pct) >= 20:
        confidence = "high"
    elif top_pct >= 80:
        confidence = "medium"
    else:
        return {
            "mac": None, "ip": None, "hostname": None,
            "confidence": "unknown",
            "note": f"No single MAC dominates traffic (top MAC seen in {top_pct:.0f}% of frames).",
        }

    ip = None
    hostname = None
    for node_ip, info in nodes.items():
        if top_mac in info.get("macs", set()):
            ip = node_ip
            hostname = info.get("hostname") or None
            break

    return {
        "mac": top_mac, "ip": ip, "hostname": hostname,
        "confidence": confidence,
        "note": f"MAC {top_mac} seen in {top_pct:.0f}% of frames — likely the capture device's NIC.",
    }
