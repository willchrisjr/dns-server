import socket
import struct

def encode_domain_name(domain):
    """
    Encodes a domain name into the DNS label format.

    """
    parts = domain.split('.')
    encoded = b''.join(struct.pack('!B', len(part)) + part.encode() for part in parts)
    return encoded + b'\x00'

def build_dns_response():
    # DNS Header fields
    packet_id = 1234  # 16 bits: A random ID assigned to query packets. Response packets must reply with the same ID.
    flags = 0x8180    # 16 bits: Flags field containing various control bits and status codes.
                      # QR (1 bit) = 1 (response)
                      # OPCODE (4 bits) = 0 (standard query)
                      # AA (1 bit) = 0 (not authoritative)
                      # TC (1 bit) = 0 (not truncated)
                      # RD (1 bit) = 0 (recursion not desired)
                      # RA (1 bit) = 1 (recursion available)
                      # Z (3 bits) = 0 (reserved)
                      # RCODE (4 bits) = 0 (no error)
    qdcount = 1       # 16 bits: Number of questions in the Question section. Expected value: 1.
    ancount = 1       # 16 bits: Number of records in the Answer section. Expected value: 1.
    nscount = 0       # 16 bits: Number of records in the Authority section. Expected value: 0.
    arcount = 0       # 16 bits: Number of records in the Additional section. Expected value: 0.

    # Pack the header fields into a binary format using struct.pack
    # '!HHHHHH' specifies:
    # '!' - network byte order (big-endian)
    # 'H' - unsigned short (16 bits)
    header = struct.pack('!HHHHHH', packet_id, flags, qdcount, ancount, nscount, arcount)

    # DNS Question section
    domain_name = "codecrafters.io"
    encoded_name = encode_domain_name(domain_name)
    qtype = 1  # 2 bytes: Type of the query (1 for A record)
    qclass = 1 # 2 bytes: Class of the query (1 for IN - Internet)

    # Pack the question fields into a binary format
    question = encoded_name + struct.pack('!HH', qtype, qclass)

    # DNS Answer section
    ttl = 60  # 4 bytes: Time-To-Live
    rdlength = 4  # 2 bytes: Length of the RDATA field
    rdata = struct.pack('!4B', 8, 8, 8, 8)  # 4 bytes: IP address (8.8.8.8)

    # Pack the answer fields into a binary format
    answer = encoded_name + struct.pack('!HHI', qtype, qclass, ttl) + struct.pack('!H', rdlength) + rdata

    # Combine header, question, and answer to form the full DNS response
    response = header + question + answer
    return response

def main():
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

            # Build the DNS response packet with the specified header, question, and answer sections
            response = build_dns_response()

            # Send the response packet back to the client
            udp_socket.sendto(response, source)
        except Exception as e:
            # Print any errors that occur during receiving or sending data
            print(f"Error receiving data: {e}")
            break

if __name__ == "__main__":
    main()