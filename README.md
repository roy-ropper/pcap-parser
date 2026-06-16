# pcap-tool

A red-team / blue-team PCAP analysis tool. Point it at a `.pcap`/`.pcapng`
capture and it will:

- Build a network graph (hosts, subnets, connections, roles, OS guesses)
- Surface **13 pentest findings** (cleartext creds, port scans, beaconing,
  ARP spoofing, exfiltration, DNS/ICMP tunneling, weak/expired certs, etc.)
- Extract cleartext credentials, service banners, TLS session detail, DNS
  events, Wi-Fi survey data, and X.509 certificates (including from
  EAP-TLS/802.1X WiFi auth)
- Export an 11-sheet **Excel workbook**, **draw.io** L3 + L2/Wi-Fi diagrams,
  and a **Visio (.vsdx)** network diagram
- Run as a **CLI** or as a **Flask web dashboard** (upload → browse → download)

Everything runs offline — stdlib + Flask + openpyxl + gunicorn only, no CDN
dependencies, suitable for isolated/engagement networks.

---

## Quick start (Docker — recommended)

```bash
docker compose up --build
```

Then open **http://localhost:8000**, upload a `.pcap`/`.pcapng`/`.cap` file
(or click one of the **sample capture** download links on the upload page to
grab a demo `.pcap`/`.pcapng` that exercises every detector), and watch the
progress page — it updates live and redirects automatically once the job is
done. From there you can browse the results dashboard and download:

- `report.xlsx` — the 11-sheet Excel workbook
- `diagram_l3.drawio` — Layer 3 network diagram (draw.io / diagrams.net)
- `diagram_l2.drawio` — Layer 2 / Wi-Fi topology diagram
- `diagram.vsdx` — Visio network diagram
- `certs.zip` — all extracted X.509 certificates (`.pem`)
- `<job_id>_bundle.zip` — everything above plus `findings.json`, in one file

Data persists in `./data/uploads` and `./data/outputs` on the host (mapped as
volumes), so uploaded captures, generated reports, and job history survive
container restarts/rebuilds.

To stop: `docker compose down` (add `-v` to also remove the named volumes —
**not** needed to keep `./data`, which is a bind mount).

---

## Quick start (CLI, no Docker)

Requires Python 3.9+.

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

python3 pcap.py capture.pcapng
```

This produces, alongside the input file:

```
capture.drawio        # L3 network diagram
capture_l2.drawio     # L2 / Wi-Fi topology diagram
capture.vsdx          # Visio diagram
capture.xlsx          # 11-sheet Excel report
capture_certs/        # extracted certificates (.der + .pem), if any found
```

You can also run it as a module (equivalent):

```bash
python3 -m pcap_tool.cli capture.pcapng
```

---

## CLI reference

```
python3 pcap.py <capture.pcap> [options]
```

| Flag | Default | Description |
|---|---|---|
| `-o, --output FILE` | `<input>.drawio` | L3 draw.io diagram output path |
| `--xlsx FILE` | `<input>.xlsx` | Excel workbook output path |
| `--l2-output FILE` | `<input>_l2.drawio` | L2/Wi-Fi draw.io diagram output path |
| `--vsdx-output FILE` | `<input>.vsdx` | Visio (.vsdx) diagram output path |
| `--certs-dir DIR` | `<input>_certs/` | Directory for extracted certs (`.der`/`.pem`); only created if any certs are found |
| `--min-packets N` | `1` | Drop graph edges (connections) seen fewer than N times — useful to declutter noisy captures |
| `--collapse-external` | off | Collapse all non-private (public/internet) hosts into per-subnet summary nodes, to declutter diagrams of large captures |
| `--title TEXT` | `Network Diagram` | Title shown on the diagrams |
| `--hostname-file FILE` | — | Path to a file mapping IPs to hostnames (see below) — overrides/augments hostnames learned passively from DNS/DHCP/NetBIOS |
| `--internal-networks CIDR [CIDR ...]` | — | Extra CIDR ranges (e.g. corporate non-RFC1918 space) to treat as "internal" for the Unusual-Outbound / Exfiltration findings and diagram colouring |

### `--hostname-file` format

Plain text, one entry per line, `<ip> <hostname>` (whitespace-separated).
Blank lines and lines starting with `#` are ignored:

```
# core-net
10.0.0.1   gateway.corp.local
10.0.0.10  dc01.corp.local
10.0.0.50  fileserver
```

### Examples

```bash
# Basic run
python3 pcap.py engagement.pcapng

# Declutter a huge capture: drop one-off connections, collapse internet hosts
python3 pcap.py big_capture.pcapng --min-packets 3 --collapse-external

# Custom title + known hostnames + extra internal ranges
python3 pcap.py wifi_capture.pcapng \
    --title "Client X — Floor 2 WiFi" \
    --hostname-file hosts.txt \
    --internal-networks 20.16.0.0/14 10.99.0.0/16

# Custom output locations
python3 pcap.py capture.pcap -o diagrams/l3.drawio --xlsx reports/findings.xlsx \
    --vsdx-output diagrams/network.vsdx --certs-dir reports/certs
```

---

## Web dashboard

### Running it

**Docker (default)**: `docker compose up --build` serves it on port 8000 via
`gunicorn -w 1 --threads 4`.

**Manually**:

```bash
pip install -r requirements.txt
python3 -m flask --app web.app run --debug   # dev server, http://127.0.0.1:5000
# or
gunicorn -w 1 --threads 4 -b 0.0.0.0:8000 web.app:app
```

> **Important**: the job tracker is an in-memory dict shared across requests.
> It only works correctly with **exactly one worker process**
> (`-w 1`). Multiple threads are fine (job processing runs in a background
> thread per upload). Don't scale this to multiple processes/replicas without
> first replacing the in-memory job store with something shared (e.g. Redis).

### Using it

1. **Upload** (`/`): choose a `.pcap`/`.pcapng`/`.cap` file (max 500 MB by
   default, configurable via `PCAP_TOOL_MAX_UPLOAD_MB`), or click a **sample
   capture** link to download a synthetic demo `.pcap`/`.pcapng` that
   exercises every detector — handy for a quick test run. Optionally expand
   "Advanced options" for:
   - **Title** — shown on the diagrams
   - **Min packets** — same as `--min-packets`
   - **Collapse external hosts** — same as `--collapse-external`
   - **Internal networks** — space-separated CIDRs, same as `--internal-networks`
   - **Hostname file** — upload a hostname-mapping file, same format as `--hostname-file`

2. **Progress** (`/jobs/<id>`): a live progress bar, current-stage label, and
   scrolling log (polled every second). The page automatically redirects to
   the results dashboard as soon as the job finishes — no manual refresh
   needed.

3. **Results** (`/jobs/<id>/results`):
   - **Download links** at the top for the Excel workbook, both `.drawio`
     diagrams, the `.vsdx` Visio diagram, and a "download everything" zip
     bundle.
   - A **sticky sidebar** on the left links to every section and highlights
     whichever one is currently in view.
   - **At a Glance** — severity counts, top findings, top cleartext
     intercepts, interesting banners, Wi-Fi deauths / ARP anomalies — your
     starting point for triage.
   - Full sections: **Findings**, **Nodes**, **Connections**, **Cleartext
     Intercepts**, **Banners**, **TLS Sessions**, **DNS Events**, **Wi-Fi &
     ARP**, **Certificates**, **Traceroutes & Gateways**, and **Network Map**.
   - Every table column has an **Excel-style filter** (▾ dropdown with
     search + checkboxes per value) and is sortable by clicking the header.
   - The **Network Map** is a subnet-level overview: hosts are grouped into
     boxes per subnet (gateways marked with ★), with lines drawn between
     subnets (total cross-subnet traffic) and between individual hosts (the
     busiest conversations) — hover any line for byte/connection counts and
     protocols.
   - The **Certificates** tab lets you download individual `.pem` files or
     `certs.zip` (all certs).

4. **Job history** (`/jobs`): every upload, with status, size, and links to
   view results or delete a job (and its uploaded/generated files) entirely.

---

## What gets analyzed

### Network graph & diagrams

- **Nodes**: every IP seen, with hostname (from DNS/DHCP/NetBIOS or your
  hostname file), MAC(es), subnet, inferred role (server/host/client), OS
  guess (from TTL), protocols, open ports, and risk flags.
- **Edges**: every host pair, with protocols, ports, resources (e.g. HTTP
  hosts), packet/byte counts.
- **L3 diagram** (`.drawio`): subnet-grouped network map, colour-coded by
  role/findings, with gateways and reconstructed traceroute paths.
- **L2/Wi-Fi diagram** (`.drawio`): access points, clients, and ARP
  relationships.
- **Visio diagram** (`.vsdx`): a simplified rectangles + connectors rendering
  of the same L3 layout, openable in Visio/LibreOffice Draw. (Plain shapes —
  not Cisco network stencils.)

### Pentest findings (13 categories)

| # | Category | Severity | Trigger |
|---|---|---|---|
| 1 | Cleartext Protocol | HIGH | Telnet/FTP/HTTP/POP3/IMAP/SMTP/LDAP/SNMP/NetBIOS/TFTP/Syslog traffic |
| 2 | Suspicious Port | HIGH | Traffic on known backdoor/C2 ports (4444, 31337, 1337, 6667, 9001, 2222, ...) |
| 3 | ARP Anomaly / Possible MITM | CRITICAL | One IP seen with multiple MAC addresses |
| 4 | Unusual Outbound | MEDIUM | Internal → external traffic on non-standard ports |
| 5 | Potential Beaconing | MEDIUM | Very regular-interval connections to the same destination (C2-like) |
| 6 | Lateral Movement Indicator | MEDIUM | SMB/RDP/VNC between internal hosts, into a "client"-role workstation |
| 7 | SNMP Cleartext | MEDIUM | Any SNMPv1/v2 traffic |
| 8 | Port Scan | HIGH | One host probing ≥15 ports on a target (vertical), or ≥10 hosts on the same port (horizontal) |
| 9 | Possible Exfiltration / Top Talker | MEDIUM | ≥10MB internal→external transfer on one connection |
| 10 | DNS Tunneling Indicator | MEDIUM | Abnormally long/high-entropy DNS labels, or NXDOMAIN floods |
| 11 | ICMP Tunneling Indicator | MEDIUM | Repeated oversized ICMP payloads between a host pair |
| 12 | EAP-TLS Client Identity Disclosure | LOW | Username/UPN/email visible in an EAP-TLS client certificate (useful for enumeration) |
| 13 | Weak/Expired Certificate | HIGH/MEDIUM | Expired, soon-to-expire, or weak-key (RSA <2048 / EC <256) certificates |

### Extracted intelligence

- **Cleartext intercepts**: FTP/HTTP Basic Auth/Telnet/SMTP/POP3/IMAP/LDAP
  credentials, SNMP community strings, and generic API-key/secret patterns.
- **Banners**: HTTP `Server:` headers, FTP/SMTP/SSH banners, DNS query names —
  useful for fingerprinting services and enumeration.
- **TLS sessions**: SNI, negotiated version/cipher, ALPN, leaf certificate
  details, and flagged issues (weak cipher, deprecated TLS version, expired
  cert, etc.).
- **DNS events**: queries/responses, NXDOMAIN tracking, mDNS.
- **Wi-Fi survey**: access points (SSID/BSSID/channel/encryption/WPS),
  clients, probe requests, deauth/disassoc events.
- **Certificates**: every X.509 cert seen in TLS handshakes *and* in
  EAP-TLS/PEAP/TTLS (802.1X / WPA2/3-Enterprise) outer handshakes — subject,
  issuer, SANs, validity, key type/size, SHA-256/SHA-1 fingerprints, with
  `.pem`/`.der` export.
- **Traceroutes & gateways**: reconstructed hop paths from ICMP
  time-exceeded messages, and detected default gateways per subnet.

### Capture requirements for Wi-Fi / EAP-TLS

- Wi-Fi survey and 802.1X/EAP-TLS extraction require a **monitor-mode**
  capture (link type 127, radiotap + 802.11) or a **wired 802.1X** capture.
- EAP-TLS/PEAP/TTLS certificate extraction only covers the *outer* handshake
  (cert exchange), which is unencrypted by design. Inner-tunnel (phase 2)
  credentials are never decrypted — this is correct/expected for a passive
  tool.

---

## Excel workbook (11 sheets)

`Connections`, `Node Summary`, `Pentest Findings` (colour-coded by severity),
`Protocol Summary`, `Port Inventory`, `Cleartext Intercepts`, `Banner Intel`,
`TLS Sessions`, `DNS Events`, `Wi-Fi Networks`, `Certificates`.

---

## Environment variables (web dashboard)

| Variable | Default | Purpose |
|---|---|---|
| `PCAP_TOOL_UPLOAD_DIR` | `/tmp/pcap_tool_uploads` (Docker: `/data/uploads`) | Where uploaded captures are stored |
| `PCAP_TOOL_OUTPUT_DIR` | `/tmp/pcap_tool_outputs` (Docker: `/data/outputs`) | Where generated reports/diagrams are stored |
| `PCAP_TOOL_MAX_UPLOAD_MB` | `500` | Max upload size in MB |
| `PCAP_TOOL_ENABLE_DRAWIO_VIEWER` | *(unset — off by default)* | Set to `1`/`true`/`yes` to enable the opt-in diagrams.net viewer link on the results page (see privacy note below) |

### draw.io viewer — privacy notice

By default the results page shows a **local SVG preview** of the topology
diagram rendered entirely in the browser with no external requests.

Setting `PCAP_TOOL_ENABLE_DRAWIO_VIEWER=1` adds an extra collapsed section
that links the downloaded `.drawio` file to
[app.diagrams.net](https://app.diagrams.net/). **Enabling this causes the
browser to contact a third-party service and may transmit diagram content
(hostnames, IP addresses, SSIDs, pentest findings) to that server.**  Do not
enable this flag on engagement machines or when handling sensitive captures.

---

## Development

```bash
pip install -r requirements-dev.txt
pytest
```

The test suite (`tests/`) uses synthetic, byte-built packets/pcaps
(`struct.pack`-based, via `tests/conftest.py`) — no external capture files
needed.

### Project layout

```
pcap.py                  # thin CLI shim → pcap_tool.cli.main()
pcap_tool/
  parser.py              # .pcap/.pcapng parsing, link-type dissection
  constants.py           # protocol tables, finding thresholds
  extractors/            # cleartext, banners, TLS, certificates, DNS, WiFi, traceroute
  graph/                 # graph build, findings, roles, hostnames, gateways, layout
  diagrams/              # draw.io (L3/L2) and Visio (.vsdx) generators
  excel/                 # Excel workbook generator
  cli.py                 # argparse + run_pipeline()
web/                     # Flask dashboard (app, jobs, serialize, templates, static)
tests/                   # pytest suite
```

---

## Known limitations

- Single-process web deployment only (in-memory job store).
- No authentication — designed for trusted/VPN/isolated engagement networks.
  Don't expose it directly to the internet.
- `.vsdx` output uses plain rectangles/connectors, not vendor network stencils.
- Passive tool: cannot decrypt TLS/EAP-TLS application data, only what's
  visible in handshakes/cleartext.
