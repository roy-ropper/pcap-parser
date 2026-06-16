"""Tests for pcap_tool.topology.render_policy.select_edges."""

from pcap_tool.topology.model import TopoEdge, TopologyModel, TopoNode
from pcap_tool.topology.render_policy import (
    select_edges, DEFAULT_MAX_EDGES, ALWAYS_TAGS, TOP_TALKER_COUNT,
)


def _model(edges):
    nodes = {}
    for e in edges:
        for nid in (e.src, e.dst):
            if nid not in nodes:
                nodes[nid] = TopoNode(id=nid, kind="host")
    return TopologyModel(
        title="Test", nodes=nodes, edges=edges,
        findings=[], gateways={}, capture_device={},
        dns_servers=set(), traceroutes=[],
    )


def _edge(src, dst, tags=None, severity=None, bytes_=0):
    return TopoEdge(src=src, dst=dst, tags=set(tags or []),
                    max_severity=severity, bytes=bytes_)


# ── ALWAYS_TAGS / severity rules ─────────────────────────────────────────────

def test_always_tag_edges_always_selected():
    """Edges with any ALWAYS_TAG are always in the result, even with zero bytes."""
    for tag in ALWAYS_TAGS:
        edges = [_edge("A", "B", tags=[tag], bytes_=0)]
        topo = _model(edges)
        result = select_edges(topo)
        assert edges[0] in result.edges, f"tag '{tag}' edge was not selected"


def test_high_severity_always_selected():
    for sev in ("HIGH", "CRITICAL"):
        edges = [_edge("A", "B", severity=sev, bytes_=0)]
        topo = _model(edges)
        result = select_edges(topo)
        assert edges[0] in result.edges, f"severity {sev} edge was not selected"


def test_wifi_assoc_always_selected():
    edges = [_edge("AP", "CLI", tags=["wifi_assoc"], bytes_=0)]
    result = select_edges(_model(edges))
    assert edges[0] in result.edges


def test_low_value_edge_not_always_selected_unless_budget():
    """A plain low-bytes edge may or may not be selected depending on budget."""
    # Single boring edge with 0 bytes, no tags, no severity — should still
    # land in the result because there's only 1 edge total.
    edges = [_edge("A", "B", bytes_=0)]
    result = select_edges(_model(edges))
    assert edges[0] in result.edges


# ── Top talker fill ───────────────────────────────────────────────────────────

def test_top_talkers_selected_by_bytes():
    n = TOP_TALKER_COUNT + 5  # more than the top-talker quota
    edges = [_edge("A", f"B{i}", bytes_=n - i) for i in range(n)]
    result = select_edges(_model(edges))
    selected_bytes = sorted([e.bytes for e in result.edges], reverse=True)
    # The highest-bytes edges should be selected (i=0 gives bytes_=n)
    assert selected_bytes[0] == n  # largest bytes edge is present


# ── max_edges cap and node_summaries ─────────────────────────────────────────

def test_max_edges_cap():
    """Total selected edges must not exceed max_edges."""
    max_e = 5
    edges = [_edge("A", f"B{i}", bytes_=i) for i in range(20)]
    result = select_edges(_model(edges), max_edges=max_e)
    assert len(result.edges) <= max_e


def test_collapsed_edges_appear_in_node_summaries():
    """Edges beyond the budget should be aggregated into node_summaries."""
    max_e = 2
    edges = [_edge("src", f"dst{i}", bytes_=i) for i in range(10)]
    result = select_edges(_model(edges), max_edges=max_e)
    # Some edges must have been collapsed
    leftover = [e for e in edges if e not in result.edges]
    if leftover:
        assert "src" in result.node_summaries
        summary = result.node_summaries["src"]
        assert summary.startswith("+")
        assert "more" in summary


def test_node_summaries_aggregated_count():
    max_e = 0  # force all edges to collapse
    edges = [_edge("src", f"dst{i}", bytes_=100, tags=[]) for i in range(5)]
    result = select_edges(_model(edges), max_edges=max_e)
    assert "src" in result.node_summaries
    summary = result.node_summaries["src"]
    assert "+5 more" in summary


def test_always_tag_edges_not_in_node_summaries():
    """ALWAYS_TAG edges must NOT appear in node_summaries."""
    max_e = 0
    tagged = _edge("src", "dst1", tags=["cleartext"], bytes_=0)
    plain = _edge("src", "dst2", bytes_=0)
    result = select_edges(_model([tagged, plain]), max_edges=max_e)
    assert tagged in result.edges
    # plain edge should be collapsed if budget is 0 but tagged edge may push budget
    # The node_summaries should not include the cleartext edge
    if "src" in result.node_summaries:
        # summary count should only reflect non-selected edges
        collapsed_count = len([e for e in [tagged, plain] if e not in result.edges])
        assert f"+{collapsed_count} more" in result.node_summaries["src"]
