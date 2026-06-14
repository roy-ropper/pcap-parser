"""Service banner / version-string extraction."""

import re as _re, socket, struct

# ─────────────────────────────────────────────────────────────────────────────
# Banner / resource / version-string extractor
# ─────────────────────────────────────────────────────────────────────────────

def extract_banners(packets):
    """
    Single pass over all packets extracting:

    Banners / version strings
      • HTTP Server:, X-Powered-By:, X-Generator:, Via: response headers
      • FTP 220 greeting line
      • SMTP 220 greeting line
      • SSH version string (SSH-2.0-OpenSSH_8.2p1 …)
      • Any printable version pattern in Telnet streams

    Commonly requested resources
      • HTTP GET/POST/PUT/DELETE request lines + Host header
      • DNS queries (what domains the network is looking up)
      • HTTP User-Agent strings (reveals client OS/browser/software versions)
      • NTP server IPs
      • DHCP requested server IPs

    Returns list of dicts:
      { category, server_ip, client_ip, port, protocol,
        banner_type, value, raw_context }
    """
    hits = []
    seen = set()   # deduplicate

    def hit(category, server_ip, client_ip, port, protocol, banner_type, value, context=""):
        value = str(value).strip()[:300]
        if not value:
            return
        key = (category, server_ip, banner_type, value)
        if key in seen:
            return
        seen.add(key)
        hits.append(dict(
            category    = category,
            server_ip   = server_ip,
            client_ip   = client_ip,
            port        = int(port) if port else 0,
            protocol    = protocol,
            banner_type = banner_type,
            value       = value,
            context     = str(context).strip()[:200],
        ))

    for p in packets:
        proto   = p.get("proto", "")
        payload = p.get("app_payload", b"")
        src_ip  = p.get("src_ip", "")
        dst_ip  = p.get("dst_ip", "")
        sp      = p.get("src_port", 0)
        dp      = p.get("dst_port", 0)

        if not payload:
            continue

        try:
            text = payload.decode("utf-8", errors="replace")
        except Exception:
            text = ""

        lines = text.splitlines()
        first = lines[0].strip() if lines else ""

        # ── HTTP responses (server is the src when dp is ephemeral / sp is 80/443) ──
        if proto in ("HTTP", "HTTP-alt"):
            # Determine direction: response starts with HTTP/1.x
            if first.startswith("HTTP/"):
                server_ip, client_ip, port = src_ip, dst_ip, sp
                for line in lines:
                    l = line.strip()
                    low = l.lower()
                    if low.startswith("server:"):
                        val = l.split(":",1)[1].strip()
                        hit("Banner", server_ip, client_ip, dp or sp, proto,
                            "HTTP Server Header", val, first)
                    elif low.startswith("x-powered-by:"):
                        val = l.split(":",1)[1].strip()
                        hit("Banner", server_ip, client_ip, dp or sp, proto,
                            "X-Powered-By", val, first)
                    elif low.startswith("x-generator:"):
                        val = l.split(":",1)[1].strip()
                        hit("Banner", server_ip, client_ip, dp or sp, proto,
                            "X-Generator", val, first)
                    elif low.startswith("via:"):
                        val = l.split(":",1)[1].strip()
                        hit("Banner", server_ip, client_ip, dp or sp, proto,
                            "Via (Proxy)", val, first)
                    elif low.startswith("x-aspnet-version:") or low.startswith("x-aspnetmvc-version:"):
                        val = l.split(":",1)[1].strip()
                        hit("Banner", server_ip, client_ip, dp or sp, proto,
                            "ASP.NET Version", val, first)
                    elif low.startswith("x-runtime:"):
                        val = l.split(":",1)[1].strip()
                        hit("Banner", server_ip, client_ip, dp or sp, proto,
                            "Runtime Version", val, first)

            # Requests — resource enumeration
            elif any(first.startswith(m) for m in ("GET ","POST ","PUT ","DELETE ","HEAD ","OPTIONS ","PATCH ")):
                server_ip, client_ip, port = dst_ip, src_ip, dp
                method_path = first.rsplit(" HTTP/",1)[0] if " HTTP/" in first else first
                # Extract host for full URL reconstruction
                host = ""
                user_agent = ""
                for line in lines:
                    l = line.strip()
                    if l.lower().startswith("host:"):
                        host = l.split(":",1)[1].strip()
                    elif l.lower().startswith("user-agent:"):
                        user_agent = l.split(":",1)[1].strip()
                full_resource = f"http://{host}{method_path.split(' ',1)[-1]}" if host else method_path
                hit("Resource", server_ip, client_ip, dp, proto,
                    "HTTP Request", full_resource, f"Method: {method_path.split()[0]}")
                if user_agent:
                    hit("Client Software", client_ip, server_ip, dp, proto,
                        "HTTP User-Agent", user_agent, f"→ {server_ip}:{dp}")

        # ── FTP banners ────────────────────────────────────────────────────────
        elif proto in ("FTP", "FTP-data"):
            # 220 = service ready greeting (the banner)
            for line in lines:
                l = line.strip()
                if l.startswith("220"):
                    hit("Banner", src_ip, dst_ip, sp, proto,
                        "FTP Banner", l[3:].strip() or l, "FTP 220 greeting")
                elif l.startswith("215"):  # SYST response
                    hit("Banner", src_ip, dst_ip, sp, proto,
                        "FTP System Type", l[3:].strip(), "SYST response")

        # ── SMTP banners ────────────────────────────────────────────────────────
        elif proto == "SMTP":
            for line in lines:
                l = line.strip()
                if l.startswith("220"):
                    hit("Banner", src_ip, dst_ip, sp, proto,
                        "SMTP Banner", l[3:].strip() or l, "SMTP 220 greeting")
                elif l.upper().startswith("EHLO") or l.upper().startswith("HELO"):
                    domain = l.split(None,1)[-1] if len(l.split()) > 1 else ""
                    if domain:
                        hit("Resource", dst_ip, src_ip, dp, proto,
                            "SMTP EHLO Domain", domain, "Client announced domain")

        # ── SSH version string ──────────────────────────────────────────────────
        # SSH banner is sent in cleartext before encryption negotiation
        elif proto in ("SSH", "TCP"):
            if text.startswith("SSH-"):
                banner_line = first.strip()
                hit("Banner", src_ip, dst_ip, sp or dp, "SSH",
                    "SSH Version String", banner_line, f"{src_ip}→{dst_ip}")

        # ── Telnet — grab any version/banner patterns ──────────────────────────
        elif proto == "Telnet":
            printable = "".join(c for c in text if c.isprintable() or c in "\r\n\t")
            # Look for version patterns
            for m in _re.findall(
                    r"(?i)(version\s+[\d.]+|v[\d]+\.[\d]+[\.\d]*|release\s+[\d.]+)", printable):
                hit("Banner", src_ip, dst_ip, sp or dp, proto,
                    "Telnet Version String", m if isinstance(m,str) else m[0],
                    printable[:100])
            # Any obvious login/welcome banner lines
            for line in printable.splitlines():
                l = line.strip()
                if any(kw in l.lower() for kw in ("welcome","unauthorized","login banner","authorized users only","cisco","juniper","warning:")):
                    hit("Banner", src_ip, dst_ip, sp or dp, proto,
                        "Telnet Login Banner", l[:200], "")

        # ── DNS queries — what the network is resolving ────────────────────────
        elif proto == "DNS" and payload:
            try:
                if len(payload) >= 12:
                    flags    = struct.unpack(">H", payload[2:4])[0]
                    is_query = not ((flags >> 15) & 1)
                    qd_count = struct.unpack(">H", payload[4:6])[0]
                    if is_query and qd_count > 0:
                        offset = 12
                        qname, _ = _dns_read_name(payload, offset)
                        if qname and "." in qname:
                            hit("Resource", dst_ip, src_ip, dp, proto,
                                "DNS Query", qname, f"Queried by {src_ip}")
            except Exception:
                pass

        # ── SNMP — system description OID (sysDescr) ──────────────────────────
        elif proto == "SNMP":
            # sysDescr (1.3.6.1.2.1.1.1.0) responses often contain OS/device strings
            printable_runs = _re.findall(rb"[ -~]{8,}", payload)
            for run in printable_runs:
                s = run.decode("ascii", "replace")
                # Filter to version-like strings
                if any(kw in s.lower() for kw in ("linux","windows","cisco","juniper","version","release","snmp","net-snmp")):
                    hit("Banner", src_ip, dst_ip, sp or dp, proto,
                        "SNMP sysDescr", s[:150], f"{src_ip}→{dst_ip}")
                    break

        # ── NTP — server IPs (what time servers is the network using) ──────────
        elif proto == "NTP":
            hit("Resource", dst_ip, src_ip, dp, proto,
                "NTP Server", dst_ip, f"NTP query from {src_ip}")

        # ── DHCP — server identifier and requested options ─────────────────────
        elif proto == "DHCP" and payload and len(payload) >= 240:
            try:
                siaddr = socket.inet_ntoa(payload[20:24])  # server IP
                i = 240
                while i < len(payload):
                    opt = payload[i]; i += 1
                    if opt == 255: break
                    if opt == 0:  continue
                    if i >= len(payload): break
                    ln = payload[i]; i += 1
                    val = payload[i:i+ln]; i += ln
                    if opt == 54 and ln == 4:  # DHCP Server Identifier
                        dhcp_srv = socket.inet_ntoa(val)
                        hit("Resource", dhcp_srv, src_ip, 67, proto,
                            "DHCP Server", dhcp_srv, f"DHCP server for {src_ip}")
                    elif opt == 60:  # Vendor Class Identifier
                        vci = val.decode("ascii","replace").strip("\x00")
                        hit("Banner", src_ip, dst_ip, dp, proto,
                            "DHCP Vendor Class", vci, f"Client: {src_ip}")
            except Exception:
                pass

    return hits

