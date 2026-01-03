"""
Network Packet Sniffer Tool
Captures and analyzes network packets with detailed protocol information
"""

import socket
import textwrap
import struct
import sys
import argparse
from typing import Optional, Tuple


class PacketSniffer:
    """
    A class to capture and analyze network packets.
    """
    
    # IPv4 Protocol numbers
    PROTOCOL_MAP = {
        1: 'ICMP',
        6: 'TCP',
        17: 'UDP',
        41: 'IPv6',
        47: 'GRE',
        50: 'ESP',
        51: 'AH',
    }
    
    def __init__(self, packet_count: int = 0, interface: Optional[str] = None):
        """
        Initialize the packet sniffer.
        
        Args:
            packet_count: Number of packets to capture (0 = infinite)
            interface: Network interface to sniff on (None = all interfaces)
        """
        self.packet_count = packet_count
        self.interface = interface
        self.packets_captured = 0
    
    def create_socket(self) -> socket.socket:
        """
        Create a raw socket for packet capture.
        
        Returns:
            Raw socket object
        """
        try:
            if sys.platform == 'win32':
                # Windows
                sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
                sock.bind((socket.gethostbyname(socket.gethostname()), 0))
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
                return sock
            else:
                # Linux/Unix
                sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
                return sock
        except PermissionError:
            print("✗ Error: This tool requires administrative/root privileges!")
            print("  - On Windows: Run as Administrator")
            print("  - On Linux: Use 'sudo python packet_sniffer.py'")
            sys.exit(1)
        except Exception as e:
            print(f"✗ Failed to create socket: {str(e)}")
            sys.exit(1)
    
    def start_sniffing(self) -> None:
        """Start capturing packets."""
        sock = self.create_socket()
        print(f"Starting packet sniffer... (Press Ctrl+C to stop)")
        if self.packet_count > 0:
            print(f"Will capture {self.packet_count} packets\n")
        else:
            print("Will capture indefinitely\n")
        
        try:
            while True:
                if self.packet_count > 0 and self.packets_captured >= self.packet_count:
                    break
                
                if sys.platform == 'win32':
                    raw_data, addr = sock.recvfrom(65535)
                    self.packets_captured += 1
                    self.parse_ipv4_packet(raw_data)
                else:
                    raw_data, addr = sock.recvfrom(65535)
                    self.packets_captured += 1
                    self.parse_ethernet_frame(raw_data)
                
                print("\n" + "="*80 + "\n")
        
        except KeyboardInterrupt:
            print(f"\n\n✓ Sniffer stopped. Captured {self.packets_captured} packets.")
        finally:
            if sys.platform == 'win32':
                sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            sock.close()
    
    def parse_ethernet_frame(self, data: bytes) -> None:
        """
        Parse Ethernet frame (Linux/Unix).
        
        Args:
            data: Raw packet data
        """
        try:
            dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
            payload = data[14:]
            
            print(f"Packet #{self.packets_captured} - Ethernet Frame")
            print(f"  Destination MAC: {self.format_mac_addr(dest_mac)}")
            print(f"  Source MAC: {self.format_mac_addr(src_mac)}")
            print(f"  Protocol: {proto}")
            
            # Handle IPv4
            if proto == 8:
                self.parse_ipv4_packet(payload)
            # Handle IPv6
            elif proto == 86:
                self.parse_ipv6_packet(payload)
            # Handle ARP
            elif proto == 1544:
                self.parse_arp_packet(payload)
        except Exception as e:
            print(f"Error parsing Ethernet frame: {str(e)}")
    
    def parse_ipv4_packet(self, data: bytes) -> None:
        """
        Parse IPv4 packet.
        
        Args:
            data: Raw packet data
        """
        try:
            version_header_length = data[0]
            header_length = (version_header_length & 15) * 4
            ttl = data[8]
            proto = data[9]
            src_ip = self.format_ipv4_address(data[12:16])
            dest_ip = self.format_ipv4_address(data[16:20])
            
            print(f"Packet #{self.packets_captured} - IPv4 Packet")
            print(f"  Version: {version_header_length >> 4}")
            print(f"  Header Length: {header_length} bytes")
            print(f"  TTL: {ttl}")
            print(f"  Protocol: {self.PROTOCOL_MAP.get(proto, proto)}")
            print(f"  Source IP: {src_ip}")
            print(f"  Destination IP: {dest_ip}")
            
            # Parse protocol-specific data
            if proto == 1:  # ICMP
                self.parse_icmp_packet(data[header_length:])
            elif proto == 6:  # TCP
                self.parse_tcp_segment(data[header_length:])
            elif proto == 17:  # UDP
                self.parse_udp_segment(data[header_length:])
            else:
                self.print_payload(data[header_length:])
        
        except Exception as e:
            print(f"Error parsing IPv4 packet: {str(e)}")
    
    def parse_ipv6_packet(self, data: bytes) -> None:
        """
        Parse IPv6 packet.
        
        Args:
            data: Raw packet data
        """
        try:
            version = data[0] >> 4
            src_ip = self.format_ipv6_address(data[8:24])
            dest_ip = self.format_ipv6_address(data[24:40])
            next_header = data[6]
            
            print(f"Packet #{self.packets_captured} - IPv6 Packet")
            print(f"  Version: {version}")
            print(f"  Next Header: {self.PROTOCOL_MAP.get(next_header, next_header)}")
            print(f"  Source IP: {src_ip}")
            print(f"  Destination IP: {dest_ip}")
            
            # Parse payload based on next header
            if next_header == 6:  # TCP
                self.parse_tcp_segment(data[40:])
            elif next_header == 17:  # UDP
                self.parse_udp_segment(data[40:])
        
        except Exception as e:
            print(f"Error parsing IPv6 packet: {str(e)}")
    
    def parse_icmp_packet(self, data: bytes) -> None:
        """
        Parse ICMP packet.
        
        Args:
            data: Raw packet data
        """
        try:
            icmp_type = data[0]
            code = data[1]
            checksum = struct.unpack('! H', data[2:4])[0]
            
            print(f"  ICMP Packet:")
            print(f"    Type: {icmp_type}")
            print(f"    Code: {code}")
            print(f"    Checksum: {checksum}")
            
            if len(data) > 8:
                print(f"  Payload:")
                self.print_payload(data[8:])
        
        except Exception as e:
            print(f"Error parsing ICMP packet: {str(e)}")
    
    def parse_tcp_segment(self, data: bytes) -> None:
        """
        Parse TCP segment.
        
        Args:
            data: Raw packet data
        """
        try:
            (src_port, dest_port, sequence, acknowledgment, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
            offset = (offset_reserved_flags >> 12) * 4
            flag_urg = (offset_reserved_flags & 32) >> 5
            flag_ack = (offset_reserved_flags & 16) >> 4
            flag_psh = (offset_reserved_flags & 8) >> 3
            flag_rst = (offset_reserved_flags & 4) >> 2
            flag_syn = (offset_reserved_flags & 2) >> 1
            flag_fin = offset_reserved_flags & 1
            
            print(f"  TCP Segment:")
            print(f"    Source Port: {src_port}")
            print(f"    Destination Port: {dest_port}")
            print(f"    Sequence: {sequence}")
            print(f"    Acknowledgment: {acknowledgment}")
            print(f"    Flags: SYN={flag_syn}, ACK={flag_ack}, FIN={flag_fin}, RST={flag_rst}, PSH={flag_psh}, URG={flag_urg}")
            
            if len(data) > offset:
                print(f"  Payload:")
                self.print_payload(data[offset:])
        
        except Exception as e:
            print(f"Error parsing TCP segment: {str(e)}")
    
    def parse_udp_segment(self, data: bytes) -> None:
        """
        Parse UDP segment.
        
        Args:
            data: Raw packet data
        """
        try:
            src_port, dest_port, length = struct.unpack('! H H 2x H', data[:8])
            
            print(f"  UDP Segment:")
            print(f"    Source Port: {src_port}")
            print(f"    Destination Port: {dest_port}")
            print(f"    Length: {length}")
            
            if len(data) > 8:
                print(f"  Payload:")
                self.print_payload(data[8:])
        
        except Exception as e:
            print(f"Error parsing UDP segment: {str(e)}")
    
    def parse_arp_packet(self, data: bytes) -> None:
        """
        Parse ARP packet.
        
        Args:
            data: Raw packet data
        """
        try:
            hardware_type, protocol_type, hardware_address_length, protocol_address_length, operation = struct.unpack('! H H B B H', data[:8])
            
            print(f"Packet #{self.packets_captured} - ARP Packet")
            print(f"  Hardware Type: {hardware_type}")
            print(f"  Protocol Type: {protocol_type}")
            print(f"  Operation: {operation}")
            
            if operation == 1:
                print(f"    (ARP Request)")
            elif operation == 2:
                print(f"    (ARP Reply)")
            
            # Parse sender and target MAC/IP
            if len(data) >= 28:
                sender_mac = self.format_mac_addr(data[8:14])
                sender_ip = self.format_ipv4_address(data[14:18])
                target_mac = self.format_mac_addr(data[18:24])
                target_ip = self.format_ipv4_address(data[24:28])
                
                print(f"  Sender MAC: {sender_mac}")
                print(f"  Sender IP: {sender_ip}")
                print(f"  Target MAC: {target_mac}")
                print(f"  Target IP: {target_ip}")
        
        except Exception as e:
            print(f"Error parsing ARP packet: {str(e)}")
    
    @staticmethod
    def format_ethernet(data: bytes) -> str:
        """Format Ethernet frame header."""
        dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data)
        return f"{PacketSniffer.format_mac_addr(dest_mac)}, {PacketSniffer.format_mac_addr(src_mac)}, {proto}"
    
    @staticmethod
    def format_ipv4_address(bytes_addr: bytes) -> str:
        """Format IPv4 address."""
        bytes_iter = iter(bytes_addr)
        return '.'.join(map(str, bytes_iter))
    
    @staticmethod
    def format_ipv6_address(bytes_addr: bytes) -> str:
        """Format IPv6 address."""
        return ':'.join('{:02x}{:02x}'.format(a, b) for a, b in zip(bytes_addr[0::2], bytes_addr[1::2]))
    
    @staticmethod
    def format_mac_addr(bytes_addr: bytes) -> str:
        """Format MAC address."""
        bytes_str = map('{:02x}'.format, bytes_addr)
        return ':'.join(bytes_str).upper()
    
    @staticmethod
    def format_multi_line_data(data: str, length: int, payload: bytes) -> Tuple:
        """Format multi-line data."""
        if isinstance(data, bytes):
            data = data.decode('utf-8', errors='ignore')
        return (data, length, payload)
    
    @staticmethod
    def print_payload(data: bytes, length: int = 80) -> None:
        """
        Print packet payload in hex and ASCII format.
        
        Args:
            data: Payload data
            length: Line length for formatting
        """
        if len(data) > 0:
            for line in textwrap.wrap(data, length):
                print(f"      {line.hex():<{length*2}}  {PacketSniffer.format_data(line)}")
    
    @staticmethod
    def format_data(bytes_input: bytes) -> str:
        """Format bytes as printable ASCII."""
        res = b''
        for byte in bytes_input:
            if 32 <= byte <= 126:
                res += bytes([byte])
            else:
                res += b'.'
        return res.decode()


def main():
    """Main function to handle command-line arguments."""
    parser = argparse.ArgumentParser(
        description='Network Packet Sniffer Tool - Capture and analyze packets',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Capture packets indefinitely (requires admin/root)
  python packet_sniffer.py
  
  # Capture 10 packets
  python packet_sniffer.py -c 10
  
  # Capture 50 packets on specific interface
  python packet_sniffer.py -c 50 -i eth0
  
Note: This tool requires administrative/root privileges to run!
        """
    )
    
    parser.add_argument('-c', '--count', type=int, default=0,
                        help='Number of packets to capture (default: 0 = infinite)')
    parser.add_argument('-i', '--interface', type=str, default=None,
                        help='Network interface to sniff on (default: all)')
    
    args = parser.parse_args()
    
    print("╔════════════════════════════════════════════╗")
    print("║     Network Packet Sniffer Tool v1.0       ║")
    print("║                                            ║")
    print("║   Captures and analyzes network packets    ║")
    print("╚════════════════════════════════════════════╝\n")
    
    sniffer = PacketSniffer(packet_count=args.count, interface=args.interface)
    sniffer.start_sniffing()


if __name__ == '__main__':
    main()
