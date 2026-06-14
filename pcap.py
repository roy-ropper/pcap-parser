#!/usr/bin/env python3
"""
pcap_to_drawio.py  v4.0  — Pentester Edition
----------------------------------------------
Thin backward-compatible shim. The implementation now lives in the
`pcap_tool` package — see `pcap_tool/cli.py` for the pipeline and
`pcap_tool/` for the parser, extractors, graph builder, diagram
generators, and Excel workbook generator.

Usage is unchanged:
    python3 pcap.py capture.pcap
    python3 pcap.py capture.pcap -o out.drawio --xlsx out.xlsx
    python3 pcap.py capture.pcap --min-packets 3 --collapse-external
    python3 pcap.py capture.pcap --hostname-file hosts.txt
    python3 pcap.py capture.pcap --internal-networks 20.16.0.0/14
"""
from pcap_tool.cli import main

if __name__ == "__main__":
    main()
