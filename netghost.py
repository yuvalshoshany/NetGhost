#!/usr/bin/env python3
"""
extract_ips_dpkt.py
Streaming extraction of IPs from a pcap file (memory-efficient).
Requires: dpkt
Usage: python extract_ips_dpkt.py sample.pcap
"""
import sys
import socket
import dpkt

def inet_to_str(inet):
    # inet could be 4-byte (IPv4) or 16-byte (IPv6) binary
    try:
        if len(inet) == 4:
            return socket.inet_ntop(socket.AF_INET, inet)
        elif len(inet) == 16:
            return socket.inet_ntop(socket.AF_INET6, inet)
    except Exception:
        return None

def extract_ips(pcap_path):
    ips = set()
    with open(pcap_path, "rb") as f:
        try:
            pcap = dpkt.pcap.Reader(f)
        except (dpkt.dpkt.NeedData, ValueError) as e:
            raise RuntimeError("File not in libpcap format or corrupted: " + str(e))
        for ts, buf in pcap:
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                # IPv4
                if isinstance(eth.data, dpkt.ip.IP):
                    ip = eth.data
                    s = inet_to_str(ip.src)
                    d = inet_to_str(ip.dst)
                    if s: ips.add(s)
                    if d: ips.add(d)
                # IPv6
                elif isinstance(eth.data, dpkt.ip6.IP6):
                    ip6 = eth.data
                    s = inet_to_str(ip6.src)
                    d = inet_to_str(ip6.dst)
                    if s: ips.add(s)
                    if d: ips.add(d)
            except Exception:
                # skip malformed packets
                continue
    return sorted(ips)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python extract_ips_dpkt.py <pcap-file>")
        sys.exit(2)
    pcap_file = sys.argv[1]
    try:
        ips = extract_ips(pcap_file)
        print("\n".join(ips))
        print(f"\nTotal unique IPs: {len(ips)}")
    except Exception as e:
        print("Error reading PCAP:", e)
        sys.exit(1)
