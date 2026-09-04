import socket
import dnslib
from dnslib import DNSRecord

IP_VM = "127.0.0.1"

buf_size = 4096

def parse_dns_message(dnslib_reply):
    dnslib_reply = DNSRecord.parse(dnslib_reply)

    number_of_answer_elements = dnslib_reply.header.a
    number_of_authority_elements = dnslib_reply.header.auth
    number_of_additional_elements = dnslib_reply.header.ar

    first_query = dnslib_reply.get_q()  # primer objeto en la lista all_querys
    domain_name_in_query = first_query.get_qname()  # nombre de dominio por el cual preguntamos

    all_resource_records = dnslib_reply.rr  # lista de objetos tipo dnslib.dns.RR

    authority_section_list = dnslib_reply.auth  # contiene un total de number_of_authority_elements
    additional_records = dnslib_reply.ar  # lista que contiene un total de number_of_additional_elements DNS records

    message = {
        "qname": domain_name_in_query,
        "ancount": number_of_answer_elements,
        "nscount": number_of_authority_elements,
        "arcount": number_of_additional_elements,
        "answer": all_resource_records,
        "authority": authority_section_list,
        "additional": additional_records,
    }
    
    return message


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

