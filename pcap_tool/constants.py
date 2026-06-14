"""Shared constants used across the pcap_tool package."""

PCAP_MAGIC_LE    = 0xA1B2C3D4
PCAP_MAGIC_BE    = 0xD4C3B2A1
PCAP_MAGIC_NS_LE = 0xA1B23C4D
PCAP_MAGIC_NS_BE = 0x4D3CB2A1
PCAPNG_MAGIC     = 0x0A0D0D0A
ETH_TYPE_IP      = 0x0800
ETH_TYPE_IP6     = 0x86DD
ETH_TYPE_ARP     = 0x0806
ETH_TYPE_EAPOL   = 0x888E
PROTO_TCP        = 6
PROTO_UDP        = 17
PROTO_ICMP       = 1
PROTO_ICMP6      = 58

WELL_KNOWN = {
    ("TCP",20):"FTP-data", ("TCP",21):"FTP",    ("TCP",22):"SSH",
    ("TCP",23):"Telnet",   ("TCP",25):"SMTP",   ("TCP",53):"DNS",
    ("TCP",80):"HTTP",     ("TCP",110):"POP3",  ("TCP",143):"IMAP",
    ("TCP",389):"LDAP",    ("TCP",443):"HTTPS", ("TCP",445):"SMB",
    ("TCP",636):"LDAPS",   ("TCP",993):"IMAPS", ("TCP",995):"POP3S",
    ("TCP",1433):"MSSQL",  ("TCP",3306):"MySQL",("TCP",3389):"RDP",
    ("TCP",5432):"PostgreSQL",("TCP",5900):"VNC",("TCP",6379):"Redis",
    ("TCP",8080):"HTTP-alt",  ("TCP",8443):"HTTPS-alt",
    ("TCP",27017):"MongoDB",  ("TCP",4444):"Metasploit?",
    ("TCP",4445):"Metasploit?",("TCP",31337):"BackOrifice?",
    ("UDP",53):"DNS",   ("UDP",67):"DHCP",  ("UDP",68):"DHCP",
    ("UDP",69):"TFTP",  ("UDP",123):"NTP",  ("UDP",137):"NetBIOS",
    ("UDP",138):"NetBIOS",("UDP",161):"SNMP",("UDP",162):"SNMP-trap",
    ("UDP",500):"IKE",  ("UDP",514):"Syslog",("UDP",1900):"SSDP",
    ("UDP",4500):"IKE-NAT",("UDP",5353):"mDNS",
}

HTTP_PORTS  = {80, 8080, 8000, 8008}
HTTPS_PORTS = {443, 8443, 4443}

# Pentest: protocols that send credentials in cleartext
CLEARTEXT_PROTOS = {"Telnet","FTP","FTP-data","HTTP","POP3","IMAP",
                    "SMTP","LDAP","SNMP","NetBIOS","TFTP","Syslog"}

# Pentest: interesting/suspicious ports
SUSPICIOUS_PORTS = {
    4444:"Metasploit default", 4445:"Metasploit alt",
    1337:"Leet shell?", 31337:"Back Orifice",
    1234:"Generic backdoor?", 9001:"Tor?", 9050:"Tor proxy",
    6667:"IRC/C2", 6666:"IRC/C2", 6668:"IRC/C2",
    8888:"Alt HTTP / Jupyter", 2222:"Alt SSH",
}

# Pentest: lateral movement indicators
LATERAL_PROTOS = {"SMB","RDP","VNC","NetBIOS","LDAP"}

# TTL → OS guess (coarse)
def _os_from_ttl(ttl):
    if ttl is None:     return "Unknown"
    if ttl <= 64:       return "Linux/Mac"
    if ttl <= 128:      return "Windows"
    if ttl <= 255:      return "Network Device"
    return "Unknown"


SERVER_PROTOS = {"HTTP","HTTPS","SSH","SMTP","DNS","MySQL","PostgreSQL","MSSQL",
                 "SMB","LDAP","RDP","HTTP-alt","HTTPS-alt","FTP","VNC",
                 "Redis","MongoDB","IMAP","POP3","SNMP","Syslog","NetBIOS"}

# ─────────────────────────────────────────────────────────────────────────────
# Phase 3 "unusual behaviour" detector thresholds
# ─────────────────────────────────────────────────────────────────────────────

# Port scan: a source touching >= this many distinct ports on one host is a
# "vertical" scan; touching the same port on >= this many distinct hosts is a
# "horizontal" scan.
PORT_SCAN_PORT_THRESHOLD = 15
PORT_SCAN_HOST_THRESHOLD = 10
PORT_SCAN_WINDOW_US      = 60_000_000   # 60 seconds

# Possible exfiltration: internal->external edge transferring at least this
# many bytes.
EXFIL_BYTES_THRESHOLD = 10_000_000   # 10 MB

# DNS tunneling indicators
DNS_TUNNEL_LABEL_LEN        = 30     # label length above this is suspicious
DNS_TUNNEL_ENTROPY          = 3.5    # Shannon entropy (bits/char) above this is suspicious
DNS_TUNNEL_NXDOMAIN_THRESHOLD = 10   # NXDOMAIN responses for one base domain

# ICMP tunneling: pairs with >= this many oversized ICMP packets
ICMP_TUNNEL_PAYLOAD_THRESHOLD = 64   # bytes
ICMP_TUNNEL_PACKET_THRESHOLD  = 5
