"""Node role inference heuristics."""

from ..constants import SERVER_PROTOS


def guess_role(ip, edges):
    peers = set()
    for s, d in edges:
        if s == ip: peers.add(d)
        elif d == ip: peers.add(s)
    for (s, d), info in edges.items():
        if d == ip and (info["protocols"] & SERVER_PROTOS):
            return "server"
    return "server" if len(peers)>=6 else ("host" if len(peers)>=3 else "client")
