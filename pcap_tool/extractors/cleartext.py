"""Cleartext credential / sensitive-data extraction."""

import base64 as _b64, re as _re

from ..constants import CLEARTEXT_PROTOS

def extract_cleartext(pkt):
    """
    Inspect application payload for credentials and sensitive data.
    Returns list of dicts: {protocol, type, value, context, src_ip, dst_ip, src_port, dst_port}
    """
    payload = pkt.get("app_payload", b"")
    if not payload:
        return []

    proto  = pkt.get("proto","")
    src_ip = pkt.get("src_ip","")
    dst_ip = pkt.get("dst_ip","")
    sp     = pkt.get("src_port", 0)
    dp     = pkt.get("dst_port", 0)
    found  = []

    try:
        text = payload.decode("utf-8", errors="replace")
    except Exception:
        text = ""

    def hit(typ, value, context=""):
        found.append(dict(protocol=proto, type=typ,
                          value=str(value)[:250], context=str(context)[:350],
                          src_ip=src_ip, dst_ip=dst_ip,
                          src_port=sp, dst_port=dp))

    # ── FTP ────────────────────────────────────────────────────────────────
    if proto in ("FTP", "FTP-data"):
        for line in text.splitlines():
            l = line.strip()
            if _re.match(r"(?i)^USER\s+\S+", l):
                hit("FTP Username", l.split(None,1)[-1], l)
            elif _re.match(r"(?i)^PASS(\s+|$)", l):
                hit("FTP Password", l.split(None,1)[-1] if len(l.split()) > 1 else "(empty)", l)

    # ── Telnet ─────────────────────────────────────────────────────────────
    if proto == "Telnet":
        printable = "".join(c for c in text if c.isprintable() or c in "\r\n")
        clean = printable.strip()
        if clean:
            hit("Telnet Keystrokes/Data", clean[:300], f"{src_ip} -> {dst_ip}")

    # ── HTTP ───────────────────────────────────────────────────────────────
    if proto in ("HTTP", "HTTP-alt"):
        lines = text.splitlines()
        req_line = lines[0].strip() if lines else ""

        for line in lines:
            # Basic Auth
            m = _re.match(r"(?i)^Authorization:\s+Basic\s+(\S+)", line)
            if m:
                b64 = m.group(1)
                try:
                    decoded = _b64.b64decode(b64 + "==").decode("utf-8","replace")
                    hit("HTTP Basic Auth (decoded)", decoded, req_line)
                except Exception:
                    hit("HTTP Basic Auth (raw b64)", b64, req_line)

            # Bearer token
            m = _re.match(r"(?i)^Authorization:\s+Bearer\s+(\S+)", line)
            if m:
                hit("HTTP Bearer Token", m.group(1)[:120], req_line)

            # Cookie
            if _re.match(r"(?i)^Cookie:\s+", line):
                hit("HTTP Cookie", line.split(":",1)[-1].strip()[:250], req_line)

            # Proxy-Auth
            if _re.match(r"(?i)^Proxy-Authorization:", line):
                hit("HTTP Proxy Auth", line.split(":",1)[-1].strip(), line.strip())

        # POST body credential fields
        body = text.split("\r\n\r\n", 1)[-1] if "\r\n\r\n" in text else ""
        if body:
            for field, val in _re.findall(
                    r"(?i)(password|passwd|pwd|pass|secret|token|apikey|api_key|"
                    r"auth|credential|session)=([^&\s]{1,120})", body):
                hit("HTTP POST Credential", f"{field}={val}", req_line)
            for field, val in _re.findall(
                    r'(?i)"(password|passwd|pwd|secret|token|api_?key|auth)"\s*:\s*"([^"]{1,120})"', body):
                hit("HTTP JSON Credential", f"{field}: {val}", req_line)

    # ── SMTP ───────────────────────────────────────────────────────────────
    if proto == "SMTP":
        for line in text.splitlines():
            l = line.strip()
            if _re.match(r"(?i)^AUTH\s+(LOGIN|PLAIN|CRAM)", l):
                hit("SMTP Auth Command", l, f"{src_ip} -> {dst_ip}")
            elif _re.match(r"(?i)^(MAIL FROM|RCPT TO):", l):
                hit("SMTP Email Address", l, "")
            elif _re.match(r"^[A-Za-z0-9+/=]{8,}$", l.strip()):
                try:
                    decoded = _b64.b64decode(l + "==").decode("utf-8","replace")
                    if decoded.isprintable() and len(decoded) >= 3:
                        hit("SMTP Auth (b64 decoded)", decoded, f"raw: {l}")
                except Exception:
                    pass

    # ── POP3 ───────────────────────────────────────────────────────────────
    if proto == "POP3":
        for line in text.splitlines():
            l = line.strip()
            if _re.match(r"(?i)^USER\s+\S+", l):
                hit("POP3 Username", l.split(None,1)[-1], l)
            elif _re.match(r"(?i)^PASS\s+", l):
                hit("POP3 Password", l.split(None,1)[-1] if len(l.split()) > 1 else "(empty)", l)

    # ── IMAP ───────────────────────────────────────────────────────────────
    if proto == "IMAP":
        for line in text.splitlines():
            l = line.strip()
            m = _re.search(r"(?i)LOGIN\s+(\S+)\s+(\S+)", l)
            if m:
                hit("IMAP Login", f"user={m.group(1)}  pass={m.group(2)}", l)

    # ── LDAP simple bind ───────────────────────────────────────────────────
    if proto == "LDAP":
        runs = _re.findall(rb"[\x20-\x7e]{4,}", payload)
        for run in runs:
            s = run.decode("ascii","replace")
            if any(k in s.lower() for k in ("cn=","dc=","ou=","uid=","password","pass")):
                hit("LDAP Bind Data", s, f"{src_ip} -> {dst_ip}")

    # ── SNMP community string ──────────────────────────────────────────────
    if proto == "SNMP":
        runs = _re.findall(rb"[\x20-\x7e]{3,}", payload)
        for run in runs:
            s = run.decode("ascii","replace")
            # Skip obvious non-community OID/version strings
            if s not in ("GET","SET","public","private") and not s.startswith("1.3") and len(s) <= 40:
                hit("SNMP Community String", s, f"{src_ip} -> {dst_ip}:{dp}")
                break

    # ── NetBIOS — decode Level-2 half-ASCII encoding ──────────────────────
    if proto == "NetBIOS":
        # NetBIOS suffix byte meanings (RFC 1001/1002)
        _NB_SUFFIX = {
            0x00: "Workstation",  0x03: "Messenger",
            0x06: "RAS Server",   0x1B: "Domain Master Browser",
            0x1C: "Domain Controllers", 0x1D: "Local Master Browser",
            0x1E: "Browser Election",   0x20: "File Server",
            0x21: "RAS Client",
        }

        def _decode_nbt_encoded(s):
            """
            Decode a Level-2 NetBIOS half-ASCII encoded name (A-P chars).
            Returns (name_str, suffix_description) or (None, None) if not valid.
            Each pair of A-P bytes encodes one byte: ((A-0x41)<<4)|(B-0x41).
            Name is 15 chars + 1 suffix byte = 32 encoded chars (16 pairs).
            """
            b = s if isinstance(s, (bytes, bytearray)) else s.encode('ascii','replace')
            # Must be even length, all bytes 0x41-0x50 (A-P)
            if len(b) < 4 or len(b) % 2 != 0:
                return None, None
            if not all(0x41 <= x <= 0x50 for x in b[:32]):
                return None, None
            chars = []
            for i in range(0, min(len(b), 32), 2):
                c = ((b[i] - 0x41) << 4) | (b[i+1] - 0x41)
                chars.append(c)
            if len(chars) >= 16:
                suffix = chars[15]
                name = ''.join(chr(c) for c in chars[:15]
                               if 0x20 <= c < 0x7f).rstrip()
                suf_desc = _NB_SUFFIX.get(suffix, f"type-{suffix:#04x}")
            else:
                suffix = None
                name = ''.join(chr(c) for c in chars
                               if 0x20 <= c < 0x7f).rstrip()
                suf_desc = None
            # Filter out all-space, wildcard, and empty names
            if not name or name in ("*", "__") or name.isspace():
                return None, None
            return name, suf_desc

        seen_names = set()
        # Try NBNS wire-format decode first (UDP 137 registrations/responses)
        decoded_names = _decode_nbns_payload(payload)
        for name in decoded_names:
            if name not in seen_names:
                seen_names.add(name)
                hit("NetBIOS Name", name, f"{src_ip} -> {dst_ip}")

        # Scan payload for 32-char (full) or shorter A-P runs = NBT session names
        # These appear in NBT Session Request packets (TCP 139) and SMB negotiations
        for run in _re.findall(rb"[A-Pa-p]{16,34}", payload):
            run_s = run.decode('ascii').upper()
            # Only attempt if run length is plausibly a name (even length, 16-32 chars)
            if len(run_s) % 2 != 0:
                run_s = run_s[:len(run_s)-1]  # trim to even
            name, suf = _decode_nbt_encoded(run_s)
            if name and name not in seen_names and name not in ("WORKGROUP",):
                seen_names.add(name)
                ctx = f"{src_ip} -> {dst_ip}"
                if suf:
                    ctx += f" [{suf}]"
                hit("NetBIOS Hostname", name, ctx)

        # Also capture workgroup / domain names (they ARE useful intel)
        for run in _re.findall(rb"[A-Pa-p]{16,34}", payload):
            run_s = run.decode('ascii').upper()
            if len(run_s) % 2 != 0:
                run_s = run_s[:len(run_s)-1]
            name, suf = _decode_nbt_encoded(run_s)
            if name == "WORKGROUP" and name not in seen_names:
                seen_names.add(name)
                hit("NetBIOS Domain/Workgroup", name, f"{src_ip} -> {dst_ip}")

        # If nothing decoded, capture meaningful SMB strings (not raw encoded garbage)
        if not seen_names:
            # Only grab runs that look like real text (contain letters + digits/symbols)
            # and are NOT all A-P chars (which would be undecodeable garbage)
            for run in _re.findall(rb"[\x20-\x7e]{6,}", payload):
                s_str = run.decode("ascii", "replace").strip()
                if (s_str
                        and not all(0x41 <= ord(c) <= 0x50 for c in s_str if c.isalpha())
                        and any(c.isalnum() for c in s_str)
                        and "SMB" not in s_str[:4]):
                    hit("NetBIOS Session Data", s_str[:120],
                        f"{src_ip} -> {dst_ip}")
                    break  # one is enough

    # ── Generic API key / secret patterns (any cleartext protocol) ─────────
    if proto in CLEARTEXT_PROTOS and text:
        patterns = [
            (r"(?i)(api[_-]?key|apikey|x-api-key)[\s:=]+([A-Za-z0-9_\-]{16,80})", "API Key"),
            (r"(?i)(access_token|auth_token)[\s:=]+([A-Za-z0-9_.\-]{16,150})",     "Auth Token"),
            (r"(?i)(secret|private_key)[\s:=]+([A-Za-z0-9_.\-/+]{16,80})",         "Secret/Key"),
            (r"(AKIA[0-9A-Z]{16})",                                                   "AWS Access Key"),
            (r"(-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----)",                  "Private Key"),
        ]
        for pattern, label in patterns:
            for m in _re.findall(pattern, text):
                val = m[-1] if isinstance(m, tuple) else m
                hit(label, val, f"{proto} {src_ip} -> {dst_ip}")

    return found




