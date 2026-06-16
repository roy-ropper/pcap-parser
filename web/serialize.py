"""Convert run_pipeline() results into plain JSON-friendly structures for
storage in the in-memory job dict and rendering in Jinja templates."""

import base64
import datetime
import ipaddress


def to_jsonable(obj):
    """Recursively convert sets/bytes/datetimes/etc to JSON-friendly types.

    `dict`/`defaultdict` -> plain dict (str keys), `set`/`frozenset` -> sorted
    list, `bytes` -> base64 string, `datetime` -> ISO string.
    """
    if isinstance(obj, bytes):
        return base64.b64encode(obj).decode("ascii")
    if isinstance(obj, (set, frozenset)):
        return sorted(to_jsonable(x) for x in obj)
    if isinstance(obj, dict):
        return {str(k): to_jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [to_jsonable(x) for x in obj]
    if isinstance(obj, datetime.datetime):
        return obj.isoformat()
    return obj


def edges_to_list(edges):
    """Convert the `edges` dict (keyed by (src,dst) tuples) into a list of
    dicts with `src`/`dst` keys merged in, for easy Jinja iteration."""
    out = []
    for (src, dst), info in edges.items():
        item = {"src": src, "dst": dst}
        item.update(info)
        out.append(item)
    return out


def nodes_to_list(nodes):
    """Convert the `nodes` dict (keyed by IP) into a list of dicts with an
    `ip` key merged in, for easy Jinja iteration."""
    out = []
    for ip, info in nodes.items():
        item = {"ip": ip}
        item.update(info)
        out.append(item)
    return out


CHIP_CAP = 40
MAX_NODE_LINKS = 25


def build_subnet_map(nodes, edges, gateways=None):
    """Group nodes by subnet and aggregate cross-subnet traffic, for a
    high-level "network map" overview on the results page."""
    by_subnet = {}
    ip_to_subnet = {}
    for n in nodes:
        sub = n.get("subnet", "external")
        ip_to_subnet[n["ip"]] = sub
        by_subnet.setdefault(sub, []).append(n)

    gateway_ips = set((gateways or {}).values())

    # Total bytes (either direction) per node, used to surface the busiest
    # hosts first so they're not hidden behind the "+N more" overflow chip.
    traffic = {}
    for e in edges:
        b = e.get("bytes", 0)
        traffic[e["src"]] = traffic.get(e["src"], 0) + b
        traffic[e["dst"]] = traffic.get(e["dst"], 0) + b

    def subnet_key(s):
        if s == "external":
            return (1, "")
        try:
            return (0, ipaddress.ip_network(s))
        except ValueError:
            return (0, s)

    role_order = {"server": 0, "host": 1, "client": 2}
    subnets = []
    for sub in sorted(by_subnet, key=subnet_key):
        for n in by_subnet[sub]:
            n["is_gateway"] = n["ip"] in gateway_ips
            n["traffic_bytes"] = traffic.get(n["ip"], 0)
        sub_nodes = sorted(
            by_subnet[sub],
            key=lambda n: (
                0 if n["is_gateway"] else 1,
                -n["traffic_bytes"],
                role_order.get(n.get("role"), 3),
                n["ip"],
            ),
        )
        subnets.append({
            "name": sub,
            "label": "Internet / External" if sub == "external" else sub,
            "nodes": sub_nodes,
        })

    # Only nodes actually rendered as chips (i.e. not collapsed into "+N
    # more") can be used as endpoints for the per-host traffic lines below.
    visible_ips = {n["ip"] for sn in subnets for n in sn["nodes"][:CHIP_CAP]}

    links = {}
    for e in edges:
        a = ip_to_subnet.get(e["src"], "external")
        b = ip_to_subnet.get(e["dst"], "external")
        if a == b:
            continue
        key = tuple(sorted((a, b)))
        link = links.setdefault(key, {"a": key[0], "b": key[1], "bytes": 0, "count": 0})
        link["bytes"] += e.get("bytes", 0)
        link["count"] += e.get("count", 0)

    node_links = []
    for e in sorted(edges, key=lambda e: -e.get("bytes", 0)):
        if e["src"] == e["dst"]:
            continue
        if e["src"] not in visible_ips or e["dst"] not in visible_ips:
            continue
        node_links.append({
            "src": e["src"],
            "dst": e["dst"],
            "bytes": e.get("bytes", 0),
            "count": e.get("count", 0),
            "protocols": e.get("protocols", []),
            "ports": e.get("ports", []),
        })
        if len(node_links) >= MAX_NODE_LINKS:
            break

    return {
        "subnets": subnets,
        "links": sorted(links.values(), key=lambda l: -l["bytes"]),
        "node_links": node_links,
        "chip_cap": CHIP_CAP,
    }


def prepare_result(result):
    """Build the JSON-friendly version of a run_pipeline() result dict that
    gets stored as `job["result"]` and rendered by the results templates.

    Drops the raw `packets` list (large, not needed for display) and the
    `vsdx_bytes` blob (stored separately as a downloadable artifact).
    """
    result = dict(result)
    result.pop("packets", None)
    result.pop("vsdx_bytes", None)
    result.pop("drawio_l3_xml", None)
    result.pop("drawio_l2_xml", None)
    result.pop("topology_svg", None)

    result["edges"] = edges_to_list(result.get("edges", {}))
    result["nodes"] = nodes_to_list(result.get("nodes", {}))

    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    result["findings"] = sorted(result.get("findings", []),
                                 key=lambda f: sev_order.get(f["severity"], 5))

    result["subnet_map"] = build_subnet_map(result["nodes"], result["edges"], result.get("gateways"))

    return to_jsonable(result)
