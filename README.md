

# DNS Forwarding Server

This project implements a DNS forwarding server, also known as a DNS forwarder. A DNS forwarder is a DNS server that forwards DNS queries it receives from clients to another DNS server for resolution. Instead of directly resolving DNS queries by looking up the information in its own local cache or authoritative records, it forwards the queries to a specified DNS resolver and returns the response to the original requester.

## Features

- Parses incoming DNS query packets.
- Forwards DNS queries to a specified DNS resolver.
- Receives responses from the DNS resolver.
- Returns the responses to the original requester.
- Handles multiple questions in a single DNS query by splitting them into individual queries and merging the responses.

## Requirements

- Python 3.x

## Usage

### Running the Server

To start the DNS forwarding server, run the following command:

```sh
python main.py --resolver <resolver_ip>:<resolver_port>
```

For example, to use Google's public DNS server as the resolver:

```sh
python main.py --resolver 8.8.8.8:53
```

### Querying the Server

You can use the `dig` command to query the DNS forwarding server. For example:

```sh
dig @127.0.0.1 -p 2053 example.com
```

You can also query multiple domains in a single request:

```sh
dig @127.0.0.1 -p 2053 example.com google.com
```

## Code Overview

### main.py

The main script implements the DNS forwarding server. It includes the following functions:

- `encode_domain_name(domain)`: Encodes a domain name into the DNS label format.
- `decode_domain_name(data, offset)`: Decodes a domain name from the DNS label format, handling both uncompressed and compressed labels.
- `parse_dns_query(data)`: Parses the DNS query packet and extracts the header and question fields.
- `forward_dns_query(query, resolver_address)`: Forwards the DNS query to the specified resolver and returns the response.
- `build_dns_response(packet_id, opcode, rd, qdcount, questions, answers)`: Builds the DNS response packet with the specified header, question, and answer sections.
- `main()`: The main function that starts the DNS server, listens for incoming queries, forwards them to the resolver, and returns the responses to the clients.

### Example Usage

1. **Start the DNS Server**:
   - Run the server with a specified resolver. For example, using Google's public DNS server:
     ```sh
     python main.py --resolver 8.8.8.8:53
     ```

2. **Send a Query**:
   - Use the `dig` command to query any domain name. For example:
     ```sh
     dig @127.0.0.1 -p 2053 example.com
     ```

### Expected Output

- The server should print logs indicating it received a packet, forwarded the query to the specified DNS server, received the response, and sent the response back to the client.
- The `dig` command should show the response from the server, including the answer section with the IP address for the queried domain.

### Testing with Different Domains

You can test the server with different domain names by using the `dig` command with various domains. Here are a few examples:

```sh
dig @127.0.0.1 -p 2053 example.com
dig @127.0.0.1 -p 2053 google.com
dig @127.0.0.1 -p 2053 youtube.com
dig @127.0.0.1 -p 2053 github.com
```

Each of these commands will send a DNS query to your server, which will forward the query to the specified resolver (e.g., Google's DNS server at `8.8.8.8:53`) and return the response to the client.



