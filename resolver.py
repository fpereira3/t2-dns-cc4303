import socket
import dnslib
from dnslib import DNSRecord, QTYPE

IP_VM = "127.0.0.1"

buf_size = 4096
root_ip = "198.41.0.4"
debug_mode = True

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

def print_parsed_msg(msg):
    print("MENSAJE DNS:")
    print("============================================================")
    for (key, value) in msg.items():
        print("{}: {}".format(key, value))
    print("============================================================\n")

def print_debug(domain_name, nombre_ns, ip_addr):
    if debug_mode:
        print("(debug) Consultando '{}' a '{}' con dirección IP '{}'".format(domain_name, nombre_ns, ip_addr))

def recv_dns_msg(address, port):
    sv_address = (address, port)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    sock.bind(sv_address)

    try:
        while True:
            data, client_address = sock.recvfrom(buf_size)
            parsed_msg = parse_dns_message(data)
            print_parsed_msg(parsed_msg)

            response = resolver(data)
            if response is not None:
                sock.sendto(response, client_address)
    finally:
        sock.close()
 
def send_query(msg_consulta_b, ip_addr, port=53):
    server_address = (ip_addr, port)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.sendto(msg_consulta_b, server_address)
        data, _ = sock.recvfrom(4096)
    finally:
        sock.close()
    return data


def resolver(mensaje_consulta, ip_addr=root_ip, nombre_ns="."):
    parsed_consulta = parse_dns_message(mensaje_consulta)
    domain_name = str(parsed_consulta["qname"])

    print_debug(domain_name, nombre_ns, ip_addr)

    data = send_query(mensaje_consulta, ip_addr)
    dnslib_reply = DNSRecord.parse(data)

    number_of_answer_elements = dnslib_reply.header.a
    number_of_authority_elements = dnslib_reply.header.auth

    if number_of_answer_elements > 0:
        all_resource_records = dnslib_reply.rr
        for resource_record in all_resource_records:
            answer_type = QTYPE.get(resource_record.rtype)
            if answer_type == 'A':
                return data

    if number_of_authority_elements > 0:
        authority_section_list = dnslib_reply.auth
        hay_ns_en_authority = any(QTYPE.get(rr.rtype) == 'NS' for rr in authority_section_list)

        if hay_ns_en_authority:
            primer_ns = authority_section_list[0]
            nombre_ns_siguiente = str(primer_ns.rdata)

            additional_records = dnslib_reply.ar
            ip_en_additional = None
            for additional_record in additional_records:
                ar_type = QTYPE.get(additional_record.rtype)
                if ar_type == 'A':
                    ip_en_additional = str(additional_record.rdata)
                    break

            if ip_en_additional is not None:
                return resolver(mensaje_consulta, ip_en_additional, nombre_ns_siguiente)

            else:
                query_ns = DNSRecord.question(nombre_ns_siguiente)
                respuesta_ns = resolver(query_ns.pack(), root_ip, ".")
 
                if respuesta_ns is None:
                    return None
 
                dnslib_reply_ns = DNSRecord.parse(respuesta_ns)
                ip_ns = None
                for rr in dnslib_reply_ns.rr:
                    if QTYPE.get(rr.rtype) == 'A':
                        ip_ns = str(rr.rdata)
                        break
 
                if ip_ns is not None:
                    return resolver(mensaje_consulta, ip_ns, nombre_ns_siguiente)
                else:
                    return None

    return None

recv_dns_msg(IP_VM, 8000)