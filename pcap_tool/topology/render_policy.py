"""Selects which TopoEdges are worth drawing as lines in the topology
diagram vs. collapsing into a "+N more" node summary, to keep the diagram
readable regardless of capture size."""

from dataclasses import dataclass, field
from collections import defaultdict

DEFAULT_MAX_EDGES = 20
TOP_TALKER_COUNT = 4

# Edge tags that are always rendered in full, regardless of byte volume —
# these represent the things a red-teamer actually cares about.
ALWAYS_TAGS = {
    "cleartext", "cleartext_creds", "ssh", "lateral_movement",
    "dns_tunneling", "beaconing", "unusual_outbound", "exfiltration",
    "icmp_tunneling", "snmp_cleartext", "radius_eap_tls", "deauth",
}

_HIGH_SEVERITIES = {"HIGH", "CRITICAL"}


@dataclass
class RenderResult:
    edges: list
    node_summaries: dict = field(default_factory=dict)


def select_edges(topology, max_edges=DEFAULT_MAX_EDGES, top_talkers=TOP_TALKER_COUNT):
    edges = topology.edges
    selected = []
    selected_ids = set()

    def select(e):
        if id(e) not in selected_ids:
            selected_ids.add(id(e))
            selected.append(e)

    # 1. Always-include tagged edges, or edges with a HIGH/CRITICAL finding.
    for e in edges:
        if (e.tags & ALWAYS_TAGS) or (e.max_severity in _HIGH_SEVERITIES):
            select(e)

    # 2. Always include Wi-Fi association topology.
    for e in edges:
        if "wifi_assoc" in e.tags:
            select(e)

    # 3. Fill the remaining budget with top talkers by bytes, then any
    #    further unselected edges by bytes.
    def remaining():
        rest = [e for e in edges if id(e) not in selected_ids]
        rest.sort(key=lambda e: -e.bytes)
        return rest

    for e in remaining()[:top_talkers]:
        if len(selected) >= max_edges:
            break
        select(e)

    for e in remaining():
        if len(selected) >= max_edges:
            break
        select(e)

    # 4. Everything else: collapse into a per-source "+N more" summary.
    leftover = [e for e in edges if id(e) not in selected_ids]
    grouped = defaultdict(lambda: {"count": 0, "bytes": 0, "protocols": set()})
    for e in leftover:
        g = grouped[e.src]
        g["count"] += 1
        g["bytes"] += e.bytes
        g["protocols"].update(e.protocols)

    node_summaries = {}
    for node_id, g in grouped.items():
        protos = sorted(g["protocols"])[:3]
        proto_str = ", ".join(protos) if protos else "traffic"
        kb = g["bytes"] / 1024
        node_summaries[node_id] = f"+{g['count']} more ({proto_str}) — {kb:.1f} KB"

    return RenderResult(edges=selected, node_summaries=node_summaries)
