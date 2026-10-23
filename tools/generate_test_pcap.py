"""
Generate a small offline pcap that exercises the lab rules, so they can be tested without
touching a real network:

    pip install scapy
    python3 tools/generate_test_pcap.py          # writes lab.pcap
    suricata -c /etc/suricata/suricata.yaml -S rules/local.rules -r lab.pcap -l out/ -k none

Set HOME_NET to "[192.168.56.0/24]" in suricata.yaml first.
"""
from scapy.all import DNS, DNSQR, ICMP, IP, TCP, UDP, Ether, wrpcap

SCANNER = "10.0.0.66"      # simulated scanning host
BRUTER = "10.0.0.77"       # simulated SSH brute-forcer
SERVER = "192.168.56.10"   # lab server inside HOME_NET

packets = []
clock = 1700000000.0


def add(pkt):
    global clock
    clock += 0.05
    pkt.time = clock
    packets.append(Ether() / pkt)


# SYN scan across ports 1-39 (rule 1000001; also touches port 23 -> rule 1000020)
for port in range(1, 40):
    add(IP(src=SCANNER, dst=SERVER) / TCP(sport=40000, dport=port, flags="S"))

# NULL and XMAS scans (rules 1000002, 1000003)
add(IP(src=SCANNER, dst=SERVER) / TCP(sport=40001, dport=80, flags=""))
add(IP(src=SCANNER, dst=SERVER) / TCP(sport=40002, dport=80, flags="FPU"))

# ICMP ping sweep across the subnet (rule 1000004)
for host in range(1, 15):
    add(IP(src=SCANNER, dst=f"192.168.56.{host}") / ICMP(type=8))

# Repeated SSH connection attempts (rule 1000010)
for i in range(8):
    add(IP(src=BRUTER, dst=SERVER) / TCP(sport=50000 + i, dport=22, flags="S"))

# DNS lookup of a domain on a commonly abused TLD (rule 1000030)
add(IP(src=SERVER, dst="8.8.8.8") / UDP(sport=5353, dport=53) / DNS(rd=1, qd=DNSQR(qname="update-check.zip")))

wrpcap("lab.pcap", packets)
print(f"Wrote lab.pcap with {len(packets)} packets")
