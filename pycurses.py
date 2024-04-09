import sys, os
import curses
import time
from scapy.all import *
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import TCP, UDP, ICMP, IP
from scapy.packet import *

# Initialize counters and state
syn_counter = 0
syn_time = None  # Initialize syn_time to None
udp_counter = 0
icmp_counter = 0
icmp_echo_reply_counter = 0
slowloris_counter = {}
port_scan_counter = {}
slowloris_state = {}
dns_amplification_state = {}


def process_packet(packet, print_all, print_attacks, print_tcp, print_udp, print_icmp):
    global syn_counter, udp_counter, icmp_counter, icmp_echo_reply_counter, port_scan_counter, syn_time, slowloris_counter
    if print_all:
        print(f"Packet: {packet.summary()}")  # Print all packets
    if TCP in packet:
        # Check for TCP anomalies (e.g., suspicious flags)
        if packet[TCP].flags == 'S':  # Check for SYN flag
            syn_counter += 1
            if syn_time is None:  # If this is the first SYN packet
                syn_time = packet.time  # Set syn_time to the packet's timestamp
            else:
                if packet.time - syn_time >= 1:  # If it's been at least one second since the last SYN packet
                    if syn_counter > 100:  # If more than 100 SYN packets were received in the last second
                        print(f"Possible SYN flood detected: {packet.summary()}")
                    syn_counter = 0  # Reset the counter
                    syn_time = packet.time  # Update the time
        # Check for Null, Xmas and FIN scans
        if packet[TCP].flags == 0 or packet[TCP].flags == 'FPU' or packet[TCP].flags == 'F':
            print(f"Possible TCP Null, Xmas or FIN scan detected: {packet.summary()}")
        # Check for Slowloris attack
        if Raw in packet and packet[TCP].dport == 80 and not packet[Raw].load.endswith(b'\r\n\r\n'):
            ip_src = packet[IP].src
            if ip_src not in slowloris_counter:
                slowloris_counter[ip_src] = 1
            else:
                slowloris_counter[ip_src] += 1
            if slowloris_counter[ip_src] > 100:  # Threshold for Slowloris attack
                print(f"Possible Slowloris attack detected from IP {ip_src}")
        if print_tcp:
            print(f"TCP Packet: {packet.summary()}")


    elif UDP in packet:
        # Check for UDP anomalies (e.g., large size)
        if packet[UDP].len > 1500:
            print(f"Suspicious UDP packet detected: {packet.summary()}")
        # Check for UDP flood
        udp_counter += 1
        if udp_time is None:  # If this is the first UDP packet
            udp_time = packet.time  # Set udp_time to the packet's timestamp
        else:
            if packet.time - udp_time >= 1:  # If it's been at least one second since the last UDP packet
                if udp_counter > 100:  # If more than 100 UDP packets were received in the last second
                    print(f"Possible UDP flood detected: {packet.summary()}")
                udp_counter = 0  # Reset the counter
                udp_time = packet.time  # Update the time
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
            if icmp_echo_reply_time is None:  # If this is the first ICMP Echo Reply packet
                icmp_echo_reply_time = packet.time  # Set icmp_echo_reply_time to the packet's timestamp
            else:
                if packet.time - icmp_echo_reply_time >= 1:  # If it's been at least one second since the last ICMP Echo Reply packet
                    if icmp_echo_reply_counter > 1000:  # If more than 1000 ICMP Echo Reply packets were received in the last second
                        print(f"Potential Smurf attack detected: {packet.summary()}")
                    icmp_echo_reply_counter = 0  # Reset the counter
                    icmp_echo_reply_time = packet.time  # Update the time
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
    unique_sources = []
    unique_destinations = []
    packetList = []

    def __init__(self, packet_list):
        self.packetList = packet_list
        for thisPacket in packet_list:
            if TCP in thisPacket:
                if thisPacket[IP].src not in self.unique_sources:
                    self.unique_sources.append(thisPacket[IP].src)

    def sort_by_time(self, x):
        return x.time

    def get_min_and_max_port(self, packetlist):
        minmax = [65565, 0]
        for packet in packetlist:
            if packet[TCP].dport > minmax[1]:
                minmax[1] = packet[TCP].dport
            if packet[TCP].dport < minmax[0]:
                minmax[0] = packet[TCP].dport
        return minmax

    def analyze(self):
        for source_ip in self.unique_sources:
            p = []
            for packet in self.packetList:
                if TCP in packet:
                    if source_ip in packet[IP].src and packet[TCP].seq == 0:
                        if packet[TCP].dport not in p:
                            p.append(packet)
                    p.sort(key=self.sort_by_time)
                    if len(p) >= 300 and (p[len(p)-1].time - p[0].time) < 0.1:
                        minmax = self.get_min_and_max_port(p)
                        print("Detected", len(p), "ports probed by", source_ip, "between",
                              minmax[0], "and", minmax[1],
                              "in", (p[len(p)-1].time - p[0].time), "seconds")
                        break


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
                        process_packet(thisPacket, print_all=False, print_attacks=False, print_tcp=True,
                                       print_udp=False,
                                       print_icmp=False)
                elif protocol_choice == '2':
                    for thisPacket in packets:
                        process_packet(thisPacket, print_all=False, print_attacks=False, print_tcp=False,
                                       print_udp=True,
                                       print_icmp=False)
                elif protocol_choice == '3':
                    for thisPacket in packets:
                        process_packet(thisPacket, print_all=False, print_attacks=False, print_tcp=False,
                                       print_udp=False,
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
