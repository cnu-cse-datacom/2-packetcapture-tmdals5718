import socket
import struct

def parsing_ethernet_header(data):
    ethernet_header = struct.unpack("!6c6c2s",data)
    ether_src = convert_ethernet_address(ethernet_header[0:6])
    ether_dest = convert_ethernet_address(ethernet_header[6:12])
    ip_header = "0x"+ethernet_header[12].hex()

    print("======ethernet header======")
    print("src_mac_address:",ether_src)
    print("dest_mac_address:",ether_dest)
    print("ip_vsersion",ip_header)

def convert_ethernet_address(data):
    ethernet_addr = list()
    for i in data:
        ethernet_addr.append(i.hex())
    ethernet_addr = ":".join(ethernet_addr)
    return ethernet_addr

def parsing_ip_header(data):
    ip_header = struct.unpack("!1c1B1H1H1H1B1B2s8B",data)
    ip_version = (ip_header[0].hex())[0]
    ip_Length = int((ip_header[0].hex())[1])
    ip_dirrerent = ip_header[1] >> 2  
    ip_explicit = ip_header[1] %  4
    ip_total_length = ip_header[2]
    ip_identification = ip_header[3]
    ip_falg = hex(ip_header[4])
    ip_reserved = ip_header[4] >> 15 & 1
    ip_not_frafments = ip_header[4] >> 14 & 1
    ip_fragments = ip_header[4] >> 13 & 1
    ip_offset = ip_header[4] & 8191
    ip_tol = ip_header[5]
    ip_protocol = ip_header[6]
    ip_checksum = "0x"+ip_header[7].hex()
    ip_src_ip_address = str(ip_header[8]) + "." + str(ip_header[9]) + "." + str(ip_header[10]) + "." +str(ip_header[11])
    ip_dest_ip_address = str(ip_header[12]) + "." + str(ip_header[13]) + "." + str(ip_header[14]) + "." +str(ip_header[15])
    print("======ip_header======")
    print("ip_version: ",ip_version)
    print("ip_Length: ", ip_Length)
    print("dirrerentiated_service_codepoint: ",ip_dirrerent)
    print("explicit_congestion_notification: ",ip_explicit)
    print("total_length: ",ip_total_length)
    print("identification: ",ip_identification)
    print("flags: ",ip_falg)
    print(">>>>reserved_bit: ",ip_reserved)
    print(">>>>not_fragments: ",ip_not_frafments)
    print(">>>>fragments: ",ip_fragments)
    print(">>>fragments_offset: ",ip_offset)
    print("Time to live: ",ip_tol)
    print("protocol: ",ip_protocol)
    print("header checksum: ", ip_checksum)
    print("source_ip_address: ", ip_src_ip_address)
    print("dest_ip_address: ", ip_dest_ip_address)
    return ip_protocol

def parsing_tcp_header(data):
    tcp_header = struct.unpack("!1H1H1I1IHHHH",data)
    tcp_src_port = tcp_header[0]
    tcp_dec_port = tcp_header[1]
    tcp_seq_num = tcp_header[2]
    tcp_ack_num = tcp_header[3]
    tcp_header_len = tcp_header[4] >> 12
    tcp_flags = tcp_header[4] & 4095  
    tcp_resrved = tcp_header[4] >> 9  & 7
    tcp_nonce  = tcp_header[4] >> 8 & 1
    tcp_cwr = tcp_header[4] >> 7  & 1
    tcp_urgent = tcp_header[4] >> 5 & 1
    tcp_ack = tcp_header[4] >> 4 & 1
    tcp_push = tcp_header[4] >> 3 & 1
    tcp_reset = tcp_header[4] >> 2 & 1
    tcp_syn = tcp_header[4] >> 1 & 1
    tcp_fin = tcp_header[4] & 1
    tcp_window_size_value = tcp_header[5]
    tcp_checksum = tcp_header[6]
    tcp_urgent_pointer = tcp_header[7]
    print("======tcp_header======")
    print("src_port: ", tcp_src_port)
    print("dec_port: ", tcp_dec_port)
    print("seq_num: ", tcp_seq_num)
    print("ack_num: ", tcp_ack_num)
    print("header_len: ",tcp_header_len)
    print("flags: ",tcp_flags)
    print(">>>>resrved: ",tcp_resrved)
    print(">>>>nonce:", tcp_nonce)
    print(">>>>ack: ",tcp_ack)
    print(">>>>push: ",tcp_push)
    print(">>>>reset: ",tcp_reset)
    print(">>>>syn: ",tcp_syn)
    print(">>>>fin: ",tcp_fin)
    print("window_sizw_value: ", tcp_window_size_value)
    print("tcp_checksum: ", tcp_checksum)
    print("urgent_pointer: ", tcp_urgent_pointer)

def parsing_udp_header(data):
    udp_header = struct.unpack("HHH2s",data)
    udp_sp = udp_header[0]
    udp_dp = udp_header[1]
    udp_lg = udp_header[2]
    udp_cs = "0x"+udp_header[3].hex()
    print("======udp_header======")
    print("src_port: ", udp_sp)
    print("dst_port: ", udp_dp)
    print("leng: ", udp_lg)
    print("header chcksum: ", udp_cs)

recv_socket = socket.socket(socket.AF_PACKET,socket.SOCK_RAW, socket.ntohs(0x800))

while True:
    data = recv_socket.recvfrom(20000)
    parsing_ethernet_header(data[0][0:14])
    plc= parsing_ip_header(data[0][14:34])
    if plc == 6:
        parsing_tcp_header(data[0][34:54])
    elif plc == 17:
        parsing_udp_header(data[0][34:42])

