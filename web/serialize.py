"""Convert run_pipeline() results into plain JSON-friendly structures for
storage in the in-memory job dict and rendering in Jinja templates."""

import base64
import datetime


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

    result["edges"] = edges_to_list(result.get("edges", {}))
    result["nodes"] = nodes_to_list(result.get("nodes", {}))

    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    result["findings"] = sorted(result.get("findings", []),
                                 key=lambda f: sev_order.get(f["severity"], 5))

    return to_jsonable(result)
