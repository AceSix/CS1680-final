from scapy.all import *
my_ip = "172.16.105.110"


def match_TCP(con, pkt):
    if pkt[IP].src == my_ip:
        if pkt[IP].src == con['s_ip'] and \
           pkt[IP].dst == con['d_ip'] and \
           pkt[TCP].sport == con['s_port'] and \
           pkt[TCP].dport == con['d_port']:
            return True
        else:
            return False
    else:
        if pkt[IP].dst == con['s_ip'] and \
           pkt[IP].src == con['d_ip'] and \
           pkt[TCP].dport == con['s_port'] and \
           pkt[TCP].sport == con['d_port']:
            return True
        else:
            return False
        
def match_UDP(con, pkt):
    if pkt[IP].src == my_ip:
        if pkt[IP].src == con['s_ip'] and \
           pkt[IP].dst == con['d_ip'] and \
           pkt[UDP].sport == con['s_port'] and \
           pkt[UDP].dport == con['d_port']:
            return True
        else:
            return False
    else:
        if pkt[IP].dst == con['s_ip'] and \
           pkt[IP].src == con['d_ip'] and \
           pkt[UDP].dport == con['s_port'] and \
           pkt[UDP].sport == con['d_port']:
            return True
        else:
            return False