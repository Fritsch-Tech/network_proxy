#!/usr/bin/env python
# -*- coding: utf-8 -*-
import socket
import struct

def main():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,socket.ntohs(3))

    while True:
        raw_data, addr = conn.recvfrom(65536)
        dest_mac,src_mac, eth_proto, data = ethernet_frame(raw_data)
        print('Ethernet Frame:')
        print('Destination: {} Source: {} Protocol: {}'.format(dest_mac,src_mac,eth_proto))

        # 8 for ipv4
        if eth_proto == 8:
            version, header_length, ttl, proto, src, target, data = ipv4_packet(data)
            print('Source: \t{}'.format(src))
            print('Destination: \t{}'.format(target))

            # ICMP
            if proto == 1:
                icmp, code, checksum, data = icmp_packet(data)
            # TCP
            elif proto == 6:
                src_port, dest_port, sequurnce, acknowlagement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data = tcp_segment(data)

            elif proto == 17:
                src_port, dest_port, size, data = udp_segment(data)

            else:
                print(data)

# unpack ethernet frame
def ethernet_frame(data):
    dest_mac, drc_mac, proto = struct.unpack('! 6s 6s H',data[:14])
    return get_mac_addr(dest_mac),get_mac_addr(drc_mac),socket.htons(proto),data[14:]

# Returns propperly formated mac address
def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format,bytes_addr)
    return ':'.join(bytes_str).upper()

# Unpacks ipv4 packets
def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, get_ipv4(src), get_ipv4(target),data[header_length:]

# Return propperly formated ipv4 address
def get_ipv4(addr):
    return '.'.join(map(str, addr))

# Unpacks IMCP packet
def icmp_packet(data):
    icmp, code, checksum = struct.unpack('! B B H',data[:4])
    return icmp, code, checksum, data[4:]

# Unpacks tcp packet
def tcp_segment(data):
    src_port, dest_port, sequurnce, acknowlagement, offset_reserved_flags = struct.unpack('! H H L L H',data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1

    return src_port, dest_port, sequurnce, acknowlagement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[14:]

def udp_segment(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[:8]


if __name__ == "__main__":
    main()
