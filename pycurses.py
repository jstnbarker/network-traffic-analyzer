import sys, os
import curses
from scapy.all import *
from scapy.layers.dns import DNS
from scapy.layers.inet import TCP, UDP, ICMP, IP

# Initialize counters and state
syn_counter = 0
udp_counter = 0
icmp_counter = 0
icmp_echo_reply_counter = 0
port_scan_counter = {}
slowloris_state = {}
dns_amplification_state = {}

def process_packet(packet, print_all, print_attacks, print_tcp, print_udp, print_icmp):
    global syn_counter, udp_counter, icmp_counter, icmp_echo_reply_counter, port_scan_counter
    if print_all:
        print(f"Packet: {packet.summary()}")  # Print all packets
    if TCP in packet:
        # Check for TCP anomalies (e.g., suspicious flags)
        if packet[TCP].flags == 'S':  # Check for SYN flag
            syn_counter += 1
            if syn_counter > 1000:  # if more than 1000 syn packets are detected, print a warning
                print(f"Possible SYN flood detected: {packet.summary()}")
        # Check for Null, Xmas and FIN scans
        if packet[TCP].flags == 0 or packet[TCP].flags == 'FPU' or packet[TCP].flags == 'F':
            print(f"Possible TCP Null, Xmas or FIN scan detected: {packet.summary()}")
        # Check for port scanning
        if packet[TCP].flags == 'S' and packet[TCP].dport not in port_scan_counter:
            port_scan_counter[packet[TCP].dport] = 1
        elif packet[TCP].flags == 'S':
            port_scan_counter[packet[TCP].dport] += 1
            if port_scan_counter[packet[TCP].dport] > 100:  # Threshold for port scanning
                print(f"Possible port scanning detected: {packet.summary()}")
        if packet[TCP].flags == 'S':
            if packet[TCP].sport not in slowloris_state:
                slowloris_state[packet[TCP].sport] = 1
            else:
                slowloris_state[packet[TCP].sport] += 1
            if slowloris_state[packet[TCP].sport] > 100:  # Threshold for Slowloris attack
                print(f"Possible Slowloris attack detected: {packet.summary()}")
        if print_tcp:
            print(f"TCP Packet: {packet.summary()}")


    elif UDP in packet:
        # Check for UDP anomalies (e.g., large size)
        if packet[UDP].len > 1500:
            print(f"Suspicious UDP packet detected: {packet.summary()}")
        # Check for UDP flood
        udp_counter += 1
        if udp_counter > 1000:  # Threshold for UDP flood
            print(f"Possible UDP flood detected: {packet.summary()}")
        if DNS in packet and packet[DNS].qr == 0 and isinstance(packet[DNS].qd, DNSQR):
            if packet[DNS].qd.qname not in dns_amplification_state:
                dns_amplification_state[packet[DNS].qd.qname] = 1
            else:
                dns_amplification_state[packet[DNS].qd.qname] += 1
            if dns_amplification_state[packet[DNS].qd.qname] > 100:  # Threshold for DNS amplification attack
                print(f"Possible DNS amplification attack detected: {packet.summary()}")
        if print_udp:
            print(f"UDP Packet: {packet.summary()}")


    elif ICMP in packet:
        # Check for ICMP anomalies (e.g., type and code)
        if packet[ICMP].type != 0 or packet[ICMP].code != 0:
            print(f"Suspicious ICMP packet detected: {packet.summary()}")
        # Check for ICMP flood
        icmp_counter += 1
        if icmp_counter > 1000:  # Threshold for ICMP flood
            print(f"Possible ICMP flood detected: {packet.summary()}")
        # Check for potential Smurf attack
        if packet[ICMP].type == 0:  # ICMP Echo Reply
            icmp_echo_reply_counter += 1
            if icmp_echo_reply_counter > 1000:  # Threshold for potential Smurf attack
                print(f"Potential Smurf attack detected: {packet.summary()}")
        if print_icmp:
            print(f"ICMP Packet: {packet.summary()}")


def print_menu():
    print("1. Print all packets")
    print("2. Print only packets related to attacks")
    print("3. Print only TCP, UDP, or ICMP packets")
    print("4. Exit")


def print_protocol_menu():
    print("1. Print only TCP packets")
    print("2. Print only UDP packets")
    print("3. Print only ICMP packets")
    print("4. Back to main menu")

class PortscanDetector:
    unique_ips = []
    packetList = []

    def __init__(self, packet_list):
        self.packetList = packet_list
        for thisPacket in packet_list:
            if TCP in thisPacket:
                if thisPacket[IP].src not in self.unique_ips:
                    self.unique_ips.append(thisPacket[IP].src)

    def analyze(self):
        for ip in self.unique_ips:
            unique_dports=[]
            for packet in self.packetList:
                if TCP in packet:
                    if ip in packet[IP].src:
                        if packet[TCP].dport not in unique_dports:
                            unique_dports.append(packet[TCP].dport)
            if len(unique_dports) > 300:
                print("Detected potential recon portscan from", ip)

def main():
    # Check if pcap or pcapng file name is provided
    if len(sys.argv) < 2:
        print("Please provide the pcap or pcapng file name as a command-line argument.")
        sys.exit(1)

    # Read packets from pcap or pcapng file
    packets = rdpcap(sys.argv[1])

    detective = PortscanDetector(packets)
    detective.analyze()

    while True:
        print_menu()
        choice = input("Enter your choice: ")
        if choice == '1':
            for thisPacket in packets:
                process_packet(thisPacket, print_all=True, print_attacks=False, print_tcp=False, print_udp=False,
                               print_icmp=False)
        elif choice == '2':
            for thisPacket in packets:
                process_packet(thisPacket, print_all=False, print_attacks=True, print_tcp=False, print_udp=False,
                               print_icmp=False)
        elif choice == '3':
            while True:
                print_protocol_menu()
                protocol_choice = input("Enter your choice: ")
                if protocol_choice == '1':
                    for thisPacket in packets:
                        process_packet(thisPacket, print_all=False, print_attacks=False, print_tcp=True, print_udp=False,
                                       print_icmp=False)
                elif protocol_choice == '2':
                    for thisPacket in packets:
                        process_packet(thisPacket, print_all=False, print_attacks=False, print_tcp=False, print_udp=True,
                                       print_icmp=False)
                elif protocol_choice == '3':
                    for thisPacket in packets:
                        process_packet(thisPacket, print_all=False, print_attacks=False, print_tcp=False, print_udp=False,
                                       print_icmp=True)
                elif protocol_choice == '4':
                    break
                else:
                    print("Invalid choice. Please enter a number between 1 and 4.")
        elif choice == '4':
            break
        else:
            print("Invalid choice. Please enter a number between 1 and 4.")


if __name__ == "__main__":
    main()
