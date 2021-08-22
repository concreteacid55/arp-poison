"""
    Networking Module
    Holds classes for networking packets
"""
from os import name
import struct, socket, random

# Headers & Util Functions

def ones_add(num1, num2, bits=16):
    """
        One's complement addition, used for
            checksums
    """
    result = num1 + num2
    return (result & ((2 ** bits) - 1)) + (result >> bits)

class EthernetFrameHeader():
    """
        Represents an Ethernet Frame Header
    """

    def __init__(self, src_mac, dest_mac, ethertype):
        """
            Construct an EthernetFrameHeader from the given parameters

            Params:
                src_mac - Bytes - MAC address of the source
                dest_mac - Bytes - MAC address of the destination
                ethertype - Int - Ethernet Types
        """
        self.src_mac = src_mac
        self.dest_mac = dest_mac
        self.ethertype = ethertype

    @staticmethod
    def from_raw_data(data):
        """
            Construct an EthernetFrameHeader object from
                raw data
            
            Params:
                data - Bytes - Ethernet Frame Header in raw bytes
            
            Returns:
                EthernetFrameHeader
        """
        src_mac, dest_mac, ethertype = struct.unpack("!6s6sH", data)
        return EthernetFrameHeader(src_mac, dest_mac, ethertype)

    def pack(self):
        """
            Pack this Ethernet Frame into raw bytes

            Returns:
                Bytes - Ethernet Frame as Bytes
        """
        return struct.pack("!6s6sH", self.dest_mac, self.src_mac, self.ethertype)


class IPHeader():
    """
        Represents an IP packet header
    """

    def __init__(self, protocol, src_ip, dest_ip, version=4, dscp=0, ecn=0,
        identification=0, flags=0, frag_offset=0, ttl=255):

        self.protocol = protocol
        self.src_ip = socket.inet_aton(src_ip)
        self.dest_ip = socket.inet_aton(dest_ip)
        self.version = version
        self.dscp = dscp
        self.ecn = ecn
        self.identification = identification
        self.flags = flags
        self.frag_offset = frag_offset
        self.ttl = ttl
        self.ihl = 5 # IHL is 5 without options present
        self.total_length = self.ihl # Default 5

    @staticmethod
    def from_raw_data(data):
        """
            Create and return an IPHeader object from raw socket data
        """

        version_ihl, dscp_ecn, total_length, identification, flags_fragment_offset, ttl, protocol, checksum, src_ip, dest_ip = struct.unpack("!BBHHHBBH4s4s", data)
        
        version = version_ihl & 240
        ihl = version_ihl & 15
        dscp = dscp_ecn & 252
        ecn = dscp_ecn & 3
        flags = flags_fragment_offset & 57344
        frag_offset = flags_fragment_offset & 8191
        src_ip = socket.inet_ntoa(src_ip)
        dest_ip = socket.inet_ntoa(dest_ip)

        header = IPHeader(protocol, src_ip, dest_ip, version=version,
            dscp=dscp, ecn=ecn, identification=identification, flags=flags,
            frag_offset=frag_offset, ttl=ttl)
        header.ihl = ihl
        return header

    def calculate_checksum(self):
        """
            Calculate the checksum of the IP Header
                Process is outlined here:
                    https://en.wikipedia.org/wiki/IPv4_header_checksum#Calculating_the_IPv4_header_checksum
        """
        self.checksum = 0 # Checksum starts at 0 for calculation
        header = self.pack(calc_checksum=False)

        # Now split the header into 16 bit chunks
        chunks = struct.unpack("!"+("H"*(self.ihl*2)), header)

        # Add the chunks into a checksum
        for x in chunks:
            self.checksum = ones_add(self.checksum, x) # Add to checksum

        self.checksum = ~self.checksum & 65535

    def set_data_length(self, length):
        """
            Set's the length of the data for this IP packet

            Params:
                length - Int - Number of bytes in IP payload
        """
        self.total_length = length + (self.ihl * 4)

    def pack(self, calc_checksum=True):
        """
            Pack the IPHeader into raw bytes

            Params:
                calc_checksum - Boolean - Whether to calculate checksum before
                    packing, default True
            
            Returns:
                Bytes - Raw bytes for the IP Header
        """
        version_ihl = (self.version << 4) + self.ihl
        dscp_ecn = (self.dscp << 7) + self.ecn
        flags_fragment_offset = (self.flags << 14) + self.frag_offset
        if (calc_checksum):
            self.calculate_checksum()

        return struct.pack("!BBHHHBBH4s4s", version_ihl, dscp_ecn, self.total_length, 
            self.identification, flags_fragment_offset, self.ttl, self.protocol, self.checksum,
            self.src_ip, self.dest_ip)

class UDPHeader():
    """
        Represents a UDP Header used for
            UDP transmission
    """

    LENGTH = 8

    def __init__(self, src_port, dest_port, data_length):
        """
            Create a UDPHeader object with the given parameters
            
            Params:
                src_port - Int - Source Port number
                dest_port - Int - Destination Port number
                data_length - Int - Length of the UDP data in bytes
        """

        self.src_port = src_port
        self.dest_port = dest_port
        self.length = data_length + 8 # 8 bytes for header
        self.checksum = 0 # Not required in IPv4
    
    @staticmethod
    def from_raw_data(data):
        src_port, dest_port, length, checksum = struct.unpack("!HHHH", data)
        header = UDPHeader(src_port, dest_port, length - 8)
        header.checksum = checksum
        return header
    
    def calculate_checksum(self, src_ip, dest_ip, data):
        """
            Calculate the UDP header checksum
        """

        self.checksum = 0
        src_ip = socket.inet_aton(src_ip)
        dest_ip = socket.inet_aton(dest_ip)
        ipv4_header = struct.pack("!4s4sBBH", src_ip, dest_ip, 0, 17, self.length)
        udp_header = self.pack()
        chunks = struct.unpack("!HHHHHHHHHH", ipv4_header + udp_header)

        for chunk in chunks:
            self.checksum = ones_add(self.checksum, chunk)
        
        if (len(data) % 2 == 1):
            data += bytes([0]) # Add padding

        for x in range(0, len(data), 2):
            self.checksum = ones_add(self.checksum, int.from_bytes(data[x:x+2], "big"))
        
        self.checksum = ~self.checksum & 65535

    def pack(self):
        return struct.pack("!HHHH", self.src_port, self.dest_port, self.length, self.checksum)
    
# Specialised Packet Classes

class ARPFrame():
    """
        Represents an ARP Frame
    """

    def __init__(self, operation, sha, spa, tha, tpa):

        self.src_protocol = spa
        self.target_protocol = tpa
        self.ethertype = 2054 # EtherType for ARP

        self.htype = 1 # Hardware type, 1 is ethernet
        self.ptype = 2048 # Protocol type, 2048 is ipv4
        self.hlen = 6 # Length in octets of hardware address
        self.plen = 4 # Length in octets of protocol address
        self.operation = operation # 1=Request, 2=Reply
        self.sha = sha # Sender MAC, or MAC for reply
        self.spa = socket.inet_aton(self.src_protocol) # Protocol of sender
        self.tha = tha # Target MAC
        self.tpa = socket.inet_aton(self.target_protocol) # Protocol of target

        self.ethernet_header = EthernetFrameHeader(sha, tha, self.ethertype)
    
    @staticmethod
    def from_raw_data(data):
        """
            Construct an ARPFrame object from raw socket data
        """
        htype, ptype, hlen, plen, oper, sha, spa, tha, tpa = struct.unpack("!HHBBH6s4s6s4s", data)
        spa = socket.inet_ntoa(spa)
        tpa = socket.inet_ntoa(tpa)
        ARP_frame = ARPFrame(oper, sha, spa, tha, tpa)
        ARP_frame.htype = htype
        ARP_frame.ptype = ptype
        ARP_frame.hlen = hlen
        ARP_frame.plen = plen
        return ARP_frame

    def pack(self):
        return self.ethernet_header.pack() + struct.pack("!HHBBH6s4s6s4s", 
            self.htype, self.ptype, self.hlen, self.plen, self.operation, self.sha, 
            self.spa, self.tha, self.tpa)

class DNSHeader():
    """
        Represents a DNS Packet Header
    """

    LENGTH = 12 # Length of header in bytes

    class DNSFlags():
        """
            Represents the DNS Flags word
        """

        def __init__(self, operation, opcode, auth_answer, truncation, recursive_desired,
            recursive_available, response_code):
            self.operation = operation
            self.opcode = opcode
            self.auth_answer = auth_answer
            self.truncation = truncation
            self.recursive_desired = recursive_desired
            self.recursive_available = recursive_available
            self.response_code = response_code
        
        def pack(self):
            data = (self.operation << 15) + (self.opcode << 11) + (self.auth_answer << 10) + (self.truncation << 9) + (self.recursive_desired << 8) + (self.recursive_available << 7) + (0 << 3) + self.response_code
            return struct.pack("!H", data)

    def __init__(self, identification, flags, question_count, answer_count, name_server_records_count, 
        resource_records_count):
        self.identification = identification
        self.flags = flags
        self.question_count = question_count
        self.answer_count = answer_count
        self.name_server_records_count = name_server_records_count
        self.resource_records_count = resource_records_count
    
    @staticmethod
    def _from_raw_data(data):
        identification, flags, question_count, answer_count, name_server_records_count, resource_records_count = struct.unpack("!HHHHHH", data)
        flags = DNSHeader.DNSFlags((flags & 32758) >> 15, (flags & 30720) >> 11, (flags & 1024) >> 10, 
        (flags & 512) >> 9, (flags & 256) >> 8, (flags & 128) >> 7, flags & 15)

        return DNSHeader(identification, flags, question_count, answer_count, name_server_records_count, resource_records_count)

    def pack(self):
        return struct.pack("!H", self.identification) + self.flags.pack() + struct.pack("!HHHH", 
        self.question_count, self.answer_count, self.name_server_records_count, self.resource_records_count)

class DNSQuery():
    """
        Represents a DNS Query
    """

    QTYPE_A = 1
    QTYPE_AAAA = 28
    QTYPE_CNAME = 5
    QTYPE_NS = 2
    QTYPE_MX = 15

    def __init__(self, src_ip, dest_ip, identification, domains, qtype, query_class=1, src_port=None, dest_port=53):
        """
            Construct a DNS Query with the given parameters

            Params:
                src_ip - String - Source IP for the DNS Query
                dest_ip - String - Destination IP for the DNS Query
                identification - Int - Unique ID used for tracking the query and answer
                domains - List of Strings - The domain names being queried
                qtype - Int - The type of DNS query, can use constants in DNSQuery class
                query_class -  Int - The class of DNS query, defaults to 1 for IP address
                dest_port - Int - Destination port for query, default 53
        """

        if (src_port is None):
            src_port = random.randint(2000, 65535)

        self.create_payload(domains, qtype, query_class)
        self.total_length = DNSHeader.LENGTH + len(self.payload)

        self.ip_header = IPHeader(17, src_ip, dest_ip)
        self.udp_header = UDPHeader(src_port, dest_port, self.total_length)
        self.ip_header.set_data_length(self.udp_header.length)
        self.dns_header_flags = DNSHeader.DNSFlags(0, 0, 0, 0, 1, 0, 0)
        self.dns_header = DNSHeader(identification, self.dns_header_flags, len(domains), 
            0, 0, 0)
    
    @staticmethod
    def decode_payload(question_count, payload):
        """
            Decode a payload

            Params:
                question_count - Int - Number of queries within this payload
                payload - Bytes - Raw DNS payload

            Returns:
                Tuple - (List of domain strings, Query Type, Query Class)
        """
        domains = []
        qtype = 0
        qclass = 0

        offset = 0
        for i in range(question_count):
            length = payload[offset]
            offset += 1
            domain = ""

            while (length != 0):
                domain += payload[offset:offset + length].decode("ascii")
                offset += length
                length = payload[offset]
                offset += 1
                domain += "."

            domains.append(domain[:-1])
        
        qtype = int.from_bytes(payload[offset:offset+2], "big")
        offset += 2
        qclass = int.from_bytes(payload[offset:offset+2], "big")

        return (domains, qtype, qclass)

    def create_payload(self, domains, qtype, query_class):
        payload = bytes(0)
        for domain in domains:
            chunks = domain.split(".")
            for chunk in chunks:
                length = len(chunk)
                payload += struct.pack("!B", length) # Add length of chunk
                payload += struct.pack("!" + str(length) + "s", chunk.encode("ascii")) # Add encoded chunk
            payload += struct.pack("!B", 0) # 0x00 for end of this domain
        payload += struct.pack("!H", qtype)
        payload += struct.pack("!H", query_class)

        self.payload = payload
        
    def pack(self):
        return self.ip_header.pack() + self.udp_header.pack() + self.dns_header.pack() + self.payload


class DNSResponse():
    """
        Represents a DNS response
    """

    def __init__(self, src_ip, dest_ip, dest_port, identification, query_payload, answers, qtype, qclass=1, 
        ttl=600, src_port=53):
        """
            Construct a DNS response with the given parameters

            Params:
                src_ip - String - IP of source for DNS response
                dest_ip - String - IP of destination for DNS response
                identification - Int - Unique ID for tracking response to a query
                query_payload - Bytes - Bytes payload of a query, required as part of a response
                answers - List of Strings - IPs for each domain in the query
                qtype - Int - The type of DNS query, can use constants in DNSQuery class
                query_class -  Int - The class of DNS query, defaults to 1 for IP address
                ttl - Int - Time for the response to live in cache
                src_port - Int - Port to be sent from, default 53 for DNS
        """

        self.create_payload(answers, query_payload, qtype, qclass, ttl)
        self.total_length = DNSHeader.LENGTH + len(self.payload)

        self.ip_header = IPHeader(17, src_ip, dest_ip)
        self.udp_header = UDPHeader(src_port, dest_port, self.total_length)
        self.ip_header.set_data_length(self.udp_header.length)
        self.dns_header_flags = DNSHeader.DNSFlags(1, 0, 0, 0, 1, 1, 0)
        self.dns_header = DNSHeader(identification, self.dns_header_flags, len(answers), len(answers), 0, 0)

        self.udp_header.calculate_checksum(src_ip, dest_ip, self.dns_header.pack() + self.payload)

    def create_payload(self, answers, query_payload, qtype, qclass, ttl):
        payload = query_payload # Begin payload with query

        for answer in answers:
            payload += struct.pack("!B", 192)
            payload += struct.pack("!B", 12)
            payload += struct.pack("!H", qtype)
            payload += struct.pack("!H", qclass)
            payload += struct.pack("!L", ttl)
            payload += struct.pack("!H", 4)
            payload += struct.pack("!4s", socket.inet_aton(answer))

        self.payload = payload

    def pack(self):
        return self.ip_header.pack() + self.udp_header.pack() + self.dns_header.pack() + self.payload
