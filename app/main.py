import socket
import struct
import sys

def encode_domain_name(domain):
    """
    Encodes a domain name into the DNS label format.
    Example: "example.com" -> b'\x07example\x03com\x00'
    """
    parts = domain.split('.')
    encoded = b''.join(struct.pack('!B', len(part)) + part.encode() for part in parts)
    return encoded + b'\x00'

def decode_domain_name(data, offset):
    """
    Decodes a domain name from the DNS label format.
    Handles both uncompressed and compressed labels.
    Returns the domain name and the new offset after the domain name.
    """
    labels = []
    while True:
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xC0 == 0xC0:  # Pointer to another part of the packet
            pointer = struct.unpack('!H', data[offset:offset+2])[0]
            pointer &= 0x3FFF  # Remove the two most significant bits
            labels.append(decode_domain_name(data, pointer)[0])
            offset += 2
            break
        else:
            offset += 1
            labels.append(data[offset:offset+length].decode())
            offset += length
    return '.'.join(labels), offset

def parse_dns_query(data):
    """
    Parses the DNS query packet and extracts the header and question fields.
    """
    # Unpack the header fields from the first 12 bytes of the data
    header = struct.unpack('!HHHHHH', data[:12])
    packet_id = header[0]
    flags = header[1]
    qdcount = header[2]
    ancount = header[3]
    nscount = header[4]
    arcount = header[5]

    # Extract the OPCODE and RD from the flags
    opcode = (flags >> 11) & 0xF
    rd = (flags >> 8) & 0x1

    # Parse the question section
    offset = 12
    questions = []
    for _ in range(qdcount):
        domain_name, offset = decode_domain_name(data, offset)
        qtype, qclass = struct.unpack('!HH', data[offset:offset+4])
        offset += 4
        questions.append((domain_name, qtype, qclass))

    return packet_id, opcode, rd, qdcount, ancount, nscount, arcount, questions

def forward_dns_query(query, resolver_address):
    """
    Forwards the DNS query to the specified resolver and returns the response.
    """
    resolver_ip, resolver_port = resolver_address.split(':')
    resolver_port = int(resolver_port)

    # Create a UDP socket
    resolver_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    resolver_socket.settimeout(5)  # Set a timeout for the resolver response

    # Send the query to the resolver
    resolver_socket.sendto(query, (resolver_ip, resolver_port))

    # Receive the response from the resolver
    response, _ = resolver_socket.recvfrom(512)
    return response

def build_dns_response(packet_id, opcode, rd, qdcount, questions, answers):
    # DNS Header fields
    flags = 0x8000  # QR (1 bit) = 1 (response)
    flags |= (opcode << 11)  # OPCODE (4 bits)
    flags |= (rd << 8)  # RD (1 bit)
    flags |= 0x80  # RA (1 bit) = 0 (recursion not available)
    flags |= 0x0  # Z (3 bits) = 0 (reserved)
    if opcode == 0:
        rcode = 0  # RCODE (4 bits) = 0 (no error)
    else:
        rcode = 4  # RCODE (4 bits) = 4 (not implemented)
    flags |= rcode

    ancount = len(answers)  # 16 bits: Number of records in the Answer section.
    nscount = 0  # 16 bits: Number of records in the Authority section. Expected value: 0.
    arcount = 0  # 16 bits: Number of records in the Additional section. Expected value: 0.

    # Pack the header fields into a binary format using struct.pack
    # '!HHHHHH' specifies:
    # '!' - network byte order (big-endian)
    # 'H' - unsigned short (16 bits)
    header = struct.pack('!HHHHHH', packet_id, flags, qdcount, ancount, nscount, arcount)

    # DNS Question section
    question_section = b''
    for domain_name, qtype, qclass in questions:
        encoded_name = encode_domain_name(domain_name)
        question_section += encoded_name + struct.pack('!HH', qtype, qclass)

    # DNS Answer section
    answer_section = b''
    for answer in answers:
        answer_section += answer

    # Combine header, question, and answer to form the full DNS response
    response = header + question_section + answer_section
    return response

def main():
    if len(sys.argv) != 3 or sys.argv[1] != '--resolver':
        print("Usage: ./your_server --resolver <address>")
        sys.exit(1)

    resolver_address = sys.argv[2]

    print("Logs from your program will appear here!")

    # Create a UDP socket
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # Bind the socket to localhost (127.0.0.1) on port 2053
    udp_socket.bind(("127.0.0.1", 2053))

    while True:
        try:
            # Receive a UDP packet (up to 512 bytes) from any source
            buf, source = udp_socket.recvfrom(512)
            print(f"Received packet from {source}")

            # Parse the DNS query packet
            packet_id, opcode, rd, qdcount, ancount, nscount, arcount, questions = parse_dns_query(buf)

            # If there are multiple questions, split them into individual queries
            answers = []
            for question in questions:
                domain_name, qtype, qclass = question
                single_query = struct.pack('!HHHHHH', packet_id, opcode << 11 | rd << 8, 1, 0, 0, 0)
                single_query += encode_domain_name(domain_name) + struct.pack('!HH', qtype, qclass)
                response = forward_dns_query(single_query, resolver_address)
                _, _, _, _, _, _, _, response_questions = parse_dns_query(response)
                response_offset = 12 + len(encode_domain_name(domain_name)) + 4
                answers.append(response[response_offset:])

            # Build the DNS response packet with the specified header, question, and answer sections
            response = build_dns_response(packet_id, opcode, rd, qdcount, questions, answers)

            # Send the response packet back to the client
            udp_socket.sendto(response, source)
        except Exception as e:
            # Print any errors that occur during receiving or sending data
            print(f"Error receiving data: {e}")
            break

if __name__ == "__main__":
    main()