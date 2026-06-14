"""Node role inference heuristics."""

from ..constants import SERVER_PROTOS, LATERAL_PROTOS


def guess_role(ip, edges):
    peers = set()
    for s, d in edges:
        if s == ip: peers.add(d)
        elif d == ip: peers.add(s)
    # SMB/RDP/VNC inbound to an otherwise-quiet host is itself a "lateral
    # movement" red flag (see findings.py #6) — don't let that traffic alone
    # promote the host to "server", or the finding can never trigger.
    server_protos = SERVER_PROTOS - LATERAL_PROTOS
    for (s, d), info in edges.items():
        if d == ip and (info["protocols"] & server_protos):
            return "server"
    return "server" if len(peers)>=6 else ("host" if len(peers)>=3 else "client")
