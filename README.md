# DNS-Query-Reponse
A DNS query and response parser that I made for a class. It sends a DNS query to a specified server and parses the binary data for the answers and then displays it.
It has error handling for malformed packets.

## Usage
To use, provide either a domain name or an IP address for lookup and the DNS server you wish to contact as command line arguments.

## Contributions
Certain portions of the code were gotten from the homework assignment:
- The `#define`s
- The `make_dns_quersion` function
- The high level structure of the `udp_send_receive` function.

Everything else was created by me, such as the error handling, main function, and response parsing.
