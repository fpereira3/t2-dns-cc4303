import socket
import dnslib

IP_VM = "127.0.0.1"

buf_size = 4096

def recv_dns_msg(address, port):
    sv_address = (address, port)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    sock.bind(sv_address)

    try:
        while True:
            data, client_address = sock.recvfrom(buf_size)
            print(data)
    finally:
        sock.close()

recv_dns_msg(IP_VM, 8000)

