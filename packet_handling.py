from scapy.all import IP, TCP, UDP, ICMP , Ether 
from scapy.layers.http import  HTTP
from scapy.layers.inet6 import IPv6 
from scapy.layers.dns import DNS 

# การรับค่าจากตัว iP ต้นทาง
def extract_source_ip(packet):
    if IP in packet:
        return packet[IP].src
    elif IPv6 in packet:
        return packet[IPv6].src
    else:
        return "NO layer IP"     
#รับค่าจาก ip ปลายทาง 
def extract_destination_ip(packet):
    if IP in packet:
        return packet[IP].dst
    elif IPv6 in packet:
        return packet[IPv6].dst
    else:
        return "Unknown Source IP"
    
def extract_source_mac(packet):
    if Ether in packet:
        return packet[Ether].src
    else:
        return "NO Source Mac"
    
def extract_destination_mac(packet):
    if Ether in packet:
        return packet[Ether].dst
    else:
        return "Unknow destination Mac"   
    
def extract_source_ipv6(packet):
    if IPv6 in packet:
        return packet[IPv6].src
    return None

def extract_destination_ipv6(packet):
    if IPv6 in packet:
        return packet[IPv6].dst
    return None

def is_tcp_packet(packet):
    return packet.haslayer(TCP)

def is_udp_packet(packet):
    return packet.haslayer(UDP)

def is_http_packet(packet):
    return packet.haslayer(HTTP)

def is_icmp_packet(packet):
    return packet.haslayer(ICMP)

def is_dns_packet(packet):
    return packet.haslyer(DNS)
    
def is_dns_packet(packet):
    return packet.haslayer(DNS)





