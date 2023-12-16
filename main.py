from scapy.all import sniff, IP, IPv6, TCP, UDP, Ether, wrpcap , rdpcap
from packet_handling import extract_source_ip, extract_destination_ip, is_tcp_packet, is_udp_packet, is_http_packet, is_icmp_packet, is_dns_packet, extract_source_mac, extract_destination_mac
from scapy.layers.http import HTTP
from scapy.layers.inet6 import IPv6
from scapy.layers.dns import DNS
from logo import logo
import time
import sys
from prettytable import PrettyTable
from colorama import Fore, Style

GREEN = Fore.GREEN
YELLOW = Fore.YELLOW
RESET = Style.RESET_ALL
BOLD = Style.BRIGHT

table = PrettyTable()
table.field_names = [f"{BOLD}Type{RESET}", f"{BOLD}Result{RESET}"]

print(logo)

GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
RESET = '\033[0m'
MAGENTA = '\033[95m'
BLUE = '\u001b[34m'
BLACK = '\033[30m'
BROWN = '\033[90m'

logo_printed = False

# ประกาศรายการสำหรับเก็บแพ็คเก็ต
packet_list = []

# Configuration option to control detailed packet information display
show_details = True

def save_pcap(packet_list, filename):
    wrpcap(filename, packet_list)
    print(f"\033[92mCapture saved to {filename}.\033[0m")

def read_pcap(filename):
    try:
        packets = sniff(offline=filename, prn=packet_callback)
        print(f"\033[92mRead {len(packets)} packets from {filename}.\033[0m")
    except Exception as e:
        print(f"\033[91mError reading pcap file: {e}\033[0m")
def display_help():
    print("\033[92mWelcome to the Packet Sniffer Program!\033[0m")
    print(f"{GREEN}This program allows you to capture and analyze network packets.")
    print("You can perform the following actions:")
    print("  1. Start packet capture: Enter 'start' or '1'")
    print("  2. Stop packet capture: Enter 'stop' or '2'")
    print("  3. Save captured packets to a pcap file: Enter 'save' or '3'")
    print("  4. Read packets from a pcap file: Enter 'read' or '4'")
    print("  5. summarize: Enter 'summarize' or '5'")
    print("  6. Display this help/explanation: Enter 'help' or '6'")
    print("  7. Exit the program: Enter 'exit' or '7'")
    print("\nNote: The program will prompt you for additional information based on your chosen action.")
    
def summarize_pcap(filename):
    try:
        packets = rdpcap(filename)
        print(f"\033[92mRead {len(packets)} packets from {filename}.\033[0m")

        summary = {
            'Source to Destination': {}
        }

        for packet in packets:
            if IP in packet or IPv6 in packet:
                source_ip = extract_source_ip(packet)
                destination_ip = extract_destination_ip(packet)

                key = f"{source_ip} to {destination_ip}"
                if key not in summary['Source to Destination']:
                    summary['Source to Destination'][key] = 1
                else:
                    summary['Source to Destination'][key] += 1

        print("\n\033[92mSummary of Source to Destination IP Pairs:\033[0m")
        table = PrettyTable()
        table.field_names = [f"{BOLD}Source to Destination{RESET}", f"{BOLD}Count{RESET}"]

        for pair, count in summary['Source to Destination'].items():
            table.add_row([pair, count])

        print(table)

    except Exception as e:
        print(f"\033[91mError reading pcap file: {e}\033[0m")

def packet_callback(packet):
    global logo_printed
    if not logo_printed:
        print(logo)
        logo_printed = True

    current_time = time.strftime("%Y-%m-%d %H:%M:%S")
    print(f"{GREEN}\nDetails Packet :{RESET}")
    print(f"{YELLOW}Time: {current_time}{RESET}")
    print(f"Summary: {packet.summary()}")

    data = []

    if IP in packet:
        source_ip = extract_source_ip(packet)
        destination_ip = extract_destination_ip(packet)
        data.append([f"{BOLD}Source IP{RESET}", f"{GREEN}{source_ip}{RESET}"])
        data.append([f"{BOLD}Destination IP{RESET}", f"{YELLOW}{destination_ip}{RESET}"])
    elif IPv6 in packet:
        source_ip = extract_source_ip(packet)
        destination_ip = extract_destination_ip(packet)
        data.append([f"{BOLD}Source IPv6{RESET}", f"{GREEN}{source_ip}{RESET}"])
        data.append([f"{BOLD}Destination IPv6{RESET}", f"{YELLOW}{destination_ip}{RESET}"])
    else:
        data.append([f"{BOLD}No IP find?{RESET}", ""])  # Ensure there are two values in this row

    if Ether in packet:
        source_mac = extract_source_mac(packet)
        destination_mac = extract_destination_mac(packet)
        data.append([f"{BOLD}Source MAC Address{RESET}", f"{GREEN}{source_mac}{RESET}"])
        data.append([f"{BOLD}Destination MAC Address{RESET}", f"{YELLOW}{destination_mac}{RESET}"])

    table.clear_rows()
    for entry in data:
        table.add_row(entry)

    print(table)
    time.sleep(0)
    
    # เพิ่มแพ็คเก็ตลงในรายการ
    packet_list.append(packet)

    if is_tcp_packet(packet):
        source_ip = extract_source_ip(packet)
        destination_ip = extract_destination_ip(packet)
        print(f"{YELLOW}TCP packet from {source_ip} to {destination_ip}{RESET}")
        print(f"{MAGENTA}Source Port: {packet[TCP].sport}{RESET}")
        print(f"{MAGENTA}Destination Port: {packet[TCP].dport}{RESET}\n")
        if is_tcp_packet(packet):
            tcp_payload = bytes(packet[TCP].payload)
        print(f"{RED}TCP Payload (Text):\n{tcp_payload[:500].decode('utf-8', 'ignore')}{RESET}\n")
        payload_hex = ":".join("{:02x}".format(c) for c in tcp_payload)
        print(f"{BROWN}TCP Payload (Hex):\n{payload_hex[:200]}{RESET}\n")

    elif is_udp_packet(packet):
        source_ip = extract_source_ip(packet)
        destination_ip = extract_destination_ip(packet)
        print(f"{BLUE}UDP packet from {source_ip} to {destination_ip}{RESET}")
        if is_udp_packet(packet):
            udp_payload = bytes(packet[UDP].payload)
        print(f"{RED}UDP Payload (Text):\n{udp_payload[:500].decode('utf-8', 'ignore')}{RESET}\n")
        payload_hex = ":".join("{:02x}".format(c) for c in udp_payload)
        print(f"{BROWN}UDP Payload (Hex):\n{payload_hex[:200]}{RESET}\n")
        
    elif is_http_packet(packet):
        source_ip = extract_source_ip(packet)
        destination_ip = extract_destination_ip(packet)
        print(f"{RED}HTTP packet from {source_ip} to {destination_ip}{RESET}")
        if is_http_packet(packet):
            http_payload = bytes(packet[HTTP].payload)
        print(f"{GREEN}HTTP Payload (Text):\n{http_payload[:500].decode('utf-8', 'ignore')}{RESET}\n")
        payload_hex = ":".join("{:02x}".format(c) for c in http_payload)
        print(f"{GREEN}HTTP Payload (Hex):\n{payload_hex[:200]}{RESET}\n")
        
    elif is_icmp_packet(packet):
        source_ip = extract_source_ip(packet)
        destination_ip = extract_destination_ip(packet)
        print(f"{GREEN}ICMP packet from {source_ip} to {destination_ip}{RESET}")

    elif is_dns_packet(packet):
        source_ip = extract_source_ip(packet)
        destination_ip = extract_destination_ip(packet)
        print(f"{RED}DNS packet from {source_ip} to {destination_ip}{RESET}")
        if is_dns_packet(packet):
            dns_payload = bytes(packet[DNS].payload)
        print(f"{GREEN}DNS Payload (Text):\n{dns_payload[:500].decode('utf-8', 'ignore')}{RESET}\n")
        payload_hex = ":".join("{:02x}".format(c) for c in dns_payload)
        print(f"{GREEN}DNS Payload (Hex):\n{payload_hex[:200]}{RESET}\n")
    time.sleep(0)

def start_stop_capture_or_read():
    while True:
        user_input = input("\033[92mEnter your choice (1-7) or 6 & help: \033[0m")
        if user_input.lower() in ['start', '1']:
            print("\033[92mStarting packet capture...\033[0m")
            filter_expression = ""
            sniff(filter=filter_expression, prn=packet_callback)
        elif user_input.lower() in ['stop', '2']:
            print("\033[92mStopping packet capture.\033[0m")
            break
        elif user_input.lower() in ['save', '3']:
            filename = input("\033[92mEnter the filename for the pcap: \033[0m")
            print(f"\033[92mSaving captured packets to '{filename}'.\033[0m")
            save_pcap(packet_list, filename)
            break
        elif user_input.lower() in ['read', '4']:
            filename = input("\033[92mEnter the filename of the pcap to read: \033[0m")
            read_pcap(filename)
            break
        elif user_input.lower() in ['summarize', '5']:
            filename = input("\033[92mEnter the filename of the pcap to summarize: \033[0m")
            summarize_pcap(filename)
        elif user_input.lower() in ['help', '6']:
            display_help()
        elif user_input.lower() in ['exit', '7']:
            print("\033[92mExiting the program. Thank you for using!\033[0m")
            sys.exit(0)
        else:
            print("\033[92mInvalid input. Please enter a valid choice (1-7).\033[0m")
    time.sleep(0)

while True:
    try:
        user_input = input("\033[92mEnter your choice (1-7) or 'help': \033[0m")
        
        if user_input.lower() in ['start', '1']:
            print("\033[92mStarting packet capture...\033[0m")
            filter_expression = ""
            sniff(filter=filter_expression, prn=packet_callback)

        elif user_input.lower() in ['stop', '2']:
            print("\033[92mStopping packet capture.\033[0m")
            break  # Exit the loop to allow the program to terminate.

        elif user_input.lower() in ['save', '3']:
            filename = input("\033[92mEnter the filename for the pcap: \033[0m")
            print(f"\033[92mSaving captured packets to '{filename}'.\033[0m")
            save_pcap(packet_list, filename)

        elif user_input.lower() in ['read', '4']:
            filename = input("\033[92mEnter the filename of the pcap to read: \033[0m")
            read_pcap(filename)

        elif user_input.lower() in ['summarize', '5']:
            filename = input("\033[92mEnter the filename of the pcap to summarize: \033[0m")
            summarize_pcap(filename)

        elif user_input.lower() in ['help', '6']:
            display_help()

        elif user_input.lower() in ['exit', '7']:
            print("\033[92mExiting the program. Thank you for using!\033[0m")
            sys.exit(0)

        else:
            print("\033[92mInvalid input. Please enter a valid choice (1-7).\033[0m")

    except KeyboardInterrupt:
        print("\033[92mExiting the program. Thank you for using!\033[0m")
        sys.exit(0)
