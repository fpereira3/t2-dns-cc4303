import socket
import dnslib
from dnslib import DNSRecord, QTYPE
from collections import deque, Counter

vm_ip = "127.0.0.1"

buffer_size = 4096
root_ip = "198.41.0.4"
debug_mode = True

query_history = deque(maxlen=20)
cache = {}


def parse_dns_message(dnslib_reply):
    """
    Parsea un mensaje DNS en bytes crudos y lo transforma en una estructura
    de datos manejable (un diccionario).

    Args:
        dnslib_reply (bytes): Mensaje DNS recibido, en bytes crudos, sin procesar.

    Returns:
        dict: Diccionario con las siguientes claves:
            - "qname" (DNSLabel): Nombre de dominio consultado.
            - "ancount" (int): Cantidad de elementos en la sección Answer.
            - "nscount" (int): Cantidad de elementos en la sección Authority.
            - "arcount" (int): Cantidad de elementos en la sección Additional.
            - "answer" (list[RR]): Lista de Resource Records de la sección Answer.
            - "authority" (list[RR]): Lista de Resource Records de la sección Authority.
            - "additional" (list[RR]): Lista de Resource Records de la sección Additional.
    """
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
    """
    Imprime en pantalla, de forma legible, la estructura de datos generada
    por parse_dns_message().

    Args:
        msg (dict): Diccionario retornado por parse_dns_message().

    Returns:
        None
    """
    print("DNS MESSAGE:")
    print("============================================================")
    for (key, value) in msg.items():
        print("{}: {}".format(key, value))
    print("============================================================\n")

def print_debug(domain_name, name_server, ip_addr):
    """
    Imprime una línea de depuración indicando qué dominio se está consultando,
    a qué Name Server, y a qué dirección IP. Solo imprime si debug_mode es True.

    Args:
        domain_name (str): Nombre de dominio que se está consultando.
        name_server (str): Nombre del Name Server al que se le está preguntando.
        ip_addr (str): Dirección IP a la que se envía la consulta.

    Returns:
        None
    """
    if debug_mode:
        print("(debug) Consultando '{}' a '{}' con dirección IP '{}'".format(domain_name, name_server, ip_addr))

def print_debug_cache(domain_name):
    """
    Imprime una línea de depuración indicando que la respuesta para un dominio
    fue obtenida directamente desde el caché, sin consultar Name Servers.
    Solo imprime si debug_mode es True.

    Args:
        domain_name (str): Nombre de dominio que fue encontrado en el caché.

    Returns:
        None
    """
    if debug_mode:
        print("(debug) '{}' encontrado en caché, respondiendo directamente sin consultar Name Servers".format(domain_name))

def update_history(domain_name):
    """
    Agrega el dominio consultado al historial de las últimas 20 consultas
    recibidas, y calcula los 3 dominios más repetidos dentro de ese historial.

    Args:
        domain_name (str): Nombre de dominio de la consulta actual.

    Returns:
        list[str]: Lista con los 3 dominios más repetidos en las últimas
            20 consultas recibidas, ordenados de mayor a menor frecuencia.
    """
    query_history.append(domain_name)
    counts = Counter(query_history)
    top_3 = [domain for domain, _ in counts.most_common(3)]
    return top_3

def build_cached_response(query_message_bytes, answer_records):
    """
    Construye una respuesta DNS válida a partir de una consulta actual y
    una lista de Resource Records previamente guardados en el caché.

    Args:
        query_message_bytes (bytes): Mensaje de consulta original del cliente,
            en bytes crudos (se usa para reutilizar su ID y su Question).
        answer_records (list[RR]): Lista de Resource Records de tipo Answer
            almacenados en el caché para el dominio consultado.

    Returns:
        bytes: Mensaje de respuesta DNS, en bytes, listo para enviar al cliente.
    """
    parsed_query = DNSRecord.parse(query_message_bytes)
    reply = parsed_query.reply()
    for rr in answer_records:
        reply.add_answer(rr)
    return reply.pack()

def recv_dns_msg(address, port):
    """
    Crea un socket UDP asociado a (address, port) y escucha en un loop
    infinito las consultas DNS entrantes. Por cada consulta recibida:
    revisa si el dominio está en caché (y responde directamente en ese caso),
    o bien la resuelve mediante resolver() y guarda el resultado en caché
    si corresponde. Finalmente envía la respuesta al cliente.

    Args:
        address (str): Dirección IP a la cual asociar (bind) el socket.
        port (int): Puerto a escuchar.

    Returns:
        None
    """
    server_address = (address, port)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    sock.bind(server_address)

    try:
        while True:
            data, client_address = sock.recvfrom(buffer_size)
            parsed_msg = parse_dns_message(data)
            print_parsed_msg(parsed_msg)

            domain_name = str(parsed_msg["qname"])
            top_3 = update_history(domain_name)

            if domain_name in cache:
                print_debug_cache(domain_name)
                response = build_cached_response(data, cache[domain_name])
            else:
                response = resolver(data)

                # Solo guardamos en caché si el dominio quedó dentro del top 3 más repetido
                if response is not None and domain_name in top_3:
                    parsed_response = DNSRecord.parse(response)
                    cache[domain_name] = parsed_response.rr

            # Eliminamos del caché los dominios que ya no están en el top 3 actual
            for cached_domain in list(cache.keys()):
                if cached_domain not in top_3:
                    del cache[cached_domain]

            if response is not None:
                sock.sendto(response, client_address)
    finally:
        sock.close()

def send_query(query_message_bytes, ip_addr, port=53):
    """
    Envía un mensaje de consulta DNS a una dirección IP y puerto determinados,
    y espera su respuesta mediante un socket UDP.

    Args:
        query_message_bytes (bytes): Mensaje de consulta DNS en bytes crudos.
        ip_addr (str): Dirección IP del servidor DNS al que se envía la consulta.
        port (int, optional): Puerto del servidor DNS. Por defecto 53.

    Returns:
        bytes: Mensaje de respuesta recibido, en bytes crudos.
    """
    server_address = (ip_addr, port)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.sendto(query_message_bytes, server_address)
        data, _ = sock.recvfrom(4096)
    finally:
        sock.close()
    return data


def resolver(mensaje_consulta, ip_addr=root_ip, nombre_ns="."):
    """
    Resuelve recursivamente una consulta DNS de tipo A, comenzando desde el
    servidor indicado por ip_addr (por defecto, el servidor raíz). Sigue la
    cadena de delegaciones (Name Servers) hasta encontrar una respuesta con
    un registro de tipo A, o hasta que no sea posible continuar.

    Args:
        mensaje_consulta (bytes): Mensaje de consulta DNS en bytes, obtenido
            desde el cliente.
        ip_addr (str, optional): Dirección IP a la cual enviar la consulta.
            Por defecto, la IP del servidor raíz (root_ip).
        nombre_ns (str, optional): Nombre del Name Server al que se le está
            preguntando en el nivel actual de la recursión, usado solo para
            el modo debug. Por defecto "." (la raíz).

    Returns:
        bytes | None: Mensaje de respuesta DNS en bytes si se encontró una
            respuesta de tipo A; None si la consulta no pudo resolverse o
            si se recibió un tipo de respuesta no contemplado.
    """
    # Usamos parse_dns_message para obtener el dominio consultado, y así armar el mensaje de debug
    parsed_query = parse_dns_message(mensaje_consulta)
    domain_name = str(parsed_query["qname"])

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
        has_ns_in_authority = any(QTYPE.get(rr.rtype) == 'NS' for rr in authority_section_list)

        if has_ns_in_authority:
            first_ns = authority_section_list[0]
            next_name_server = str(first_ns.rdata)

            additional_records = dnslib_reply.ar
            ip_in_additional = None
            for additional_record in additional_records:
                ar_type = QTYPE.get(additional_record.rtype)
                if ar_type == 'A':
                    ip_in_additional = str(additional_record.rdata)
                    break

            if ip_in_additional is not None:
                return resolver(mensaje_consulta, ip_in_additional, next_name_server)

            else:
                ns_query = DNSRecord.question(next_name_server)
                ns_response = resolver(ns_query.pack(), root_ip, ".")

                if ns_response is None:
                    return None

                ns_parsed_reply = DNSRecord.parse(ns_response)
                ns_ip = None
                for rr in ns_parsed_reply.rr:
                    if QTYPE.get(rr.rtype) == 'A':
                        ns_ip = str(rr.rdata)
                        break

                if ns_ip is not None:
                    return resolver(mensaje_consulta, ns_ip, next_name_server)
                else:
                    return None

    return None

recv_dns_msg(vm_ip, 8000)
