#include "dns.h"

#include <iostream>
#include <random>
#include <set>

#include <Windows.h>
#pragma comment(lib,"WS2_32")

/* DNS query types */
#define DNS_A 1 /* name -> IP */
#define DNS_NS 2 /* name server */
#define DNS_CNAME 5 /* canonical name */
#define DNS_PTR 12 /* IP -> name */
#define DNS_HINFO 13 /* host info/SOA */
#define DNS_MX 15 /* mail exchange */
#define DNS_AXFR 252 /* request for zone transfer */
#define DNS_ANY 255 /* all records */
/* query classes */
#define DNS_INET 1
/* flags */
#define DNS_QUERY (0 << 15) /* 0 = query; 1 = response */
#define DNS_RESPONSE (1 << 15)
#define DNS_STDQUERY (0 << 11) /* opcode - 4 bits */
#define DNS_AA (1 << 10) /* authoritative answer */
#define DNS_TC (1 << 9) /* truncated */
#define DNS_RD (1 << 8) /* recursion desired */
#define DNS_RA (1 << 7) /* recursion available */
/* results */
#define DNS_OK 0 /* success */
#define DNS_FORMAT 1 /* format error (unable to interpret) */
#define DNS_SERVERFAIL 2 /* can’t find authority nameserver */
#define DNS_ERROR 3 /* no DNS entry */
#define DNS_NOTIMPL 4 /* not implemented */
#define DNS_REFUSED 5 /* server refused the query */


constexpr unsigned char MAX_COUNTS = 3;
constexpr unsigned int MAX_DNS_LEN = 512;

std::string print_dns_type(int type) {
    switch (type) {
    default:
        return "ANY";
    case 1:
        return "A";
    case 2:
        return "NS";
    case 5:
        return "CNAME";
    case 12:
        return "PTR";
    case 13:
        return "HINFO";
    case 15:
        return "MX";
    case 252:
        return "AXFR";
    }
}

void sb::DNS::take_query(const std::string& lookup, const std::string& server) {

    this->lookup.name = lookup;
    this->lookup.is_ip = check_if_ip(lookup);
    this->server = server;
}

std::string sb::DNS::convert_ip_to_lookup(const std::string& ip) {
    std::string new_lookup;
    new_lookup.reserve(ip.size() + 13);

    DWORD ip_addr = inet_addr(ip.c_str());
    ip_addr = htonl(ip_addr);
    in_addr ip_num;
    ip_num.S_un.S_addr = ip_addr;
    new_lookup = inet_ntoa(ip_num);

    new_lookup += ".in-addr.arpa";
    return new_lookup;
}

bool sb::DNS::check_if_ip(const std::string& lookup_name) {
    DWORD IP = inet_addr(lookup_name.c_str());
    if (IP == INADDR_NONE)
        return false;
    else
        return true;
}

SOCKET create_socket() {
    SOCKET sock = socket(AF_INET, SOCK_DGRAM, 0);
    // handle errors
    struct sockaddr_in local;
    memset(&local, 0, sizeof(local));
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = INADDR_ANY;
    local.sin_port = htons(0);
    if (bind(sock, (struct sockaddr*)&local, sizeof(local)) == SOCKET_ERROR) {
        // handle errors
    }
    return sock;
}

void sock_setup_connect_info(struct sockaddr_in& remote, const std::string& server) {
    memset(&remote, 0, sizeof(remote));
    remote.sin_family = AF_INET;
    remote.sin_addr.s_addr = inet_addr(server.c_str()); // server’s IP
    remote.sin_port = htons(53); // DNS port on server
}

void make_dns_question(char* buffer, const std::string& lookup) {

    int buffer_idx = 0;
    int string_idx = 0;

    while (string_idx < lookup.size()) {

        // Get position of next word
        int word_size = lookup.find(".", string_idx);
        if (word_size == std::string::npos)
            word_size = lookup.size();

        // Subtract offset to get word size
        word_size -= string_idx;

        // Place size into buffer and move cursor forward
        buffer[buffer_idx++] = char(word_size);

        // Buffer start + offset, copy word_size of string
        memcpy(buffer + buffer_idx, lookup.c_str() + string_idx, word_size);

        // Increment buffer by copied amount and string by copied amount + 1 (to exclude dot)
        buffer_idx += word_size;
        string_idx += word_size + 1;
    }
    buffer[buffer_idx] = 0;
}

void set_fdh_and_qh(sb::FixedDNSHeader* header, sb::QueryHeader* q_header, bool is_ip) {
    header->id = htons(rand());
    header->flags = htons(DNS_QUERY | DNS_RD);
    header->questions = htons(1);
    header->answers = htons(0);
    header->authority = htons(0);
    header->additional = htons(0);
    q_header->type = htons((is_ip) ? DNS_PTR : DNS_A);
    q_header->qclass = htons(DNS_INET);
}

void sb::DNS::udp_send_recieve() {
    char packet[MAX_DNS_LEN]; // 512 bytes is max

    std::string dns_question_name = (lookup.is_ip ? convert_ip_to_lookup(this->lookup.name) : this->lookup.name);

    int pkt_size = dns_question_name.size() + 2 + sizeof(FixedDNSHeader) + sizeof(QueryHeader);

    // Header + string + queryheader

    header = (FixedDNSHeader*)packet;
    q_header = (QueryHeader*)(packet + pkt_size - sizeof(QueryHeader));

    set_fdh_and_qh(header, q_header, lookup.is_ip);

    make_dns_question((char*)(header + 1), dns_question_name);

    printf("Lookup\t: %s\n", this->lookup.name.c_str());
    printf("Query\t: %s, type %d, TXID 0x%.4x\n", dns_question_name.c_str(), ntohs(q_header->type), ntohs(header->id));
    printf("Server\t: %s\n", server.c_str());
    printf("********************************\n");

    SOCKET sock = create_socket();
    struct sockaddr_in remote;
    sock_setup_connect_info(remote, server);

    timeval tp;
    tp.tv_sec = 10;
    tp.tv_usec = 0;

    char buf[MAX_DNS_LEN];
    struct sockaddr_in response;
    int response_length = sizeof(response);
    int counter = 0;
    while (counter++ < MAX_COUNTS) {

        printf("Attempt %d with %d bytes... ", counter, pkt_size);
        ULONGLONG start_time = GetTickCount64();

        // Send query
        if (sendto(sock, packet, pkt_size, 0, (struct sockaddr*)&remote, sizeof(remote)) == SOCKET_ERROR) {
            std::cout << "sendto failed with " << WSAGetLastError() << "\n";
            break;
        }

        fd_set fd;
        FD_ZERO(&fd); // clear the set
        FD_SET(sock, &fd); // add your socket to the set
        int available = select(0, &fd, NULL, NULL, &tp);
        if (available == 0) {
            ULONGLONG end_time = GetTickCount64();
            std::cout << "timeout in " << end_time - start_time << "ms\n";
        }
        else if (available > 0)
        {
            int bytes = 0;
            if ((bytes = recvfrom(sock, buf, MAX_DNS_LEN, 0, (struct sockaddr*)&response, &response_length)) == SOCKET_ERROR) {
                std::cout << "socket error " << WSAGetLastError() << "\n";
                break;
            }

            ULONGLONG end_time = GetTickCount64();

            printf("response in %lld ms with %d bytes\n", (end_time - start_time), bytes);

            if (bytes < sizeof(FixedDNSHeader)) {
                printf("\t ++ invalid reply: packet smaller than fixed DNS header\n");
                break;
            }

            // check if this packet came from the server to which we sent the query earlier
            if (response.sin_addr.S_un.S_addr != remote.sin_addr.S_un.S_addr || response.sin_port != remote.sin_port) {
                printf("Error! Packet did not come from the server we sent our query to!\n");
                break;
            }

            parse_response(buf, bytes, pkt_size);

            break;
        }
    }

    closesocket(sock);
}


// The fun part.'

// decode_uncompressed_word(char* start)
// Start at word size, decode until word size ends, return decode value
std::string decode_uncompressed_work(char* start) {
    std::string data;
    unsigned char read_size = *start;
    for (int i = 0; i < read_size; i++) {
        ++start;
        data.push_back(*start);
    }
    return data;
}

// decode_compressed_word(char* start, char* buffer, char* tracked positions)
// Start at 0b11, get jump offset
// return jump offset
unsigned short decode_jump(char* start) {
    return *(start + 1) + ((unsigned short)(*(start) << 2) << 8);
}

// parse_string(char* start, char* buffer)
// Parse a string until a \0 occurs
// Hold a cursor position for decodes
// determine if compressed or compressed
// handle logic for a series of compressed calls
// keep track of original position
std::string parse_string(char* cursor_start, char* buffer, std::set<unsigned short>* tracked_positions, int& uncompressed_len, int pkt_size) {
    std::string data = "";
    char* cursor = cursor_start;
    bool creator_of_set = false;

    while (*cursor != 0) {
        if ((unsigned char)*cursor >= 0xc0) {
            if (cursor + 1 >= buffer + pkt_size) {
                data = "";
                printf("\t\t++ invalid record: truncated jump offset (e.g., 0xC0 and the packet ends)\n");
                break;
            }

            unsigned short jump_len = decode_jump(cursor);
            // TODO: print errors here, any error results in data = "" and a break.
            if (jump_len >= pkt_size) {
                data = "";
                printf("\t\t++ invalid record: jump of %d beyond packet boundary of %d\n", jump_len, pkt_size);
                break;
            }
            else if (jump_len < sizeof(sb::FixedDNSHeader)) {
                data = "";
                printf("\t\t++ invalid record: jump into fixed DNS header\n");
                break;
            }

            if (tracked_positions == nullptr) {
                tracked_positions = new std::set<unsigned short>;
                creator_of_set = true;
            }

            auto unique_entry = tracked_positions->insert(jump_len);
            if (unique_entry.second == false) {
                data = "";
                printf("\t\t++ invalid record: jump loop\n");
                break;
            }

            std::string new_data = parse_string(buffer + jump_len, buffer, tracked_positions, uncompressed_len, pkt_size);
            if (new_data == "") {
                data = "";
                break;
            }
            data += new_data;
            cursor += 2;

            // As it turns out, we can ONLY compress suffixes. Once we hit compression, we're done.
            // Compression *can* be nested, so if we have b + *(a + *(example.com)), that's valid
            // But the pointer always comes last.
            break;
        }
        else {

            if (unsigned char read_size = *cursor + cursor >= buffer + pkt_size) {
                data = "";
                printf("\t\t++ invalid record: truncated name (e.g. \"6 goog.\" and the packet ends\n");
                break;
            }

            std::string new_data = decode_uncompressed_work(cursor);
            data += new_data;
            cursor += new_data.size() + 1;

            if (*cursor == 0) {
                cursor++;
                break;
            }
        }

        if (*cursor == 0)
            break;

        data.push_back('.');
    }

    if (creator_of_set)
        delete tracked_positions;

    uncompressed_len = cursor - cursor_start;
    return data;
}

char* parse_response_section(const std::string& section_name, char* buffer, int num_answers, char* answer_start, int pkt_size) {
    if (num_answers > 0) {
        printf("\t------------ [%s] ------------\n", section_name.c_str());
    }
    unsigned short answers_parsed = 0;
    while (answers_parsed < num_answers && answer_start < (buffer + pkt_size)) {

        // First, get RR
        int string_offset = 0;

        std::string rrname = parse_string(answer_start, buffer, nullptr, string_offset, pkt_size);
        if (rrname == "")
            return nullptr;
        answer_start += string_offset;
        if (answer_start >= buffer + pkt_size) {
            printf("\t\t++ invalid record: RR value length streteches the answer beyond packet");
            return nullptr;
        }

        if (answer_start + 10 >= buffer + pkt_size) {
            printf("\t\t++ invalid record: truncated RR answer header (i.e., don't have the full 10 bytes)");
            return nullptr;
        }

        // Next, answer info
        sb::DNSanswerHdr answer_header;
        answer_header.type = ntohs(((sb::DNSanswerHdr*)answer_start)->type);
        answer_header.aclass = ntohs(((sb::DNSanswerHdr*)answer_start)->aclass);
        answer_header.TTL = ntohl(((sb::DNSanswerHdr*)answer_start)->TTL);
        answer_header.len = ntohs(((sb::DNSanswerHdr*)answer_start)->len);

        answer_start = (char*)((sb::DNSanswerHdr*)answer_start + 1);

        // Finally, answer, which depends on the type!
        // We only care about CNAME, NS, A, and PTR
        std::string answer_text = "";


        if (answer_header.type == DNS_A) {
            in_addr ip_num;
            ip_num.S_un.S_addr = *((int*)answer_start);
            answer_text = inet_ntoa(ip_num);
            answer_start = (char*)((int*)answer_start + 1);
        }
        else if (answer_header.type == DNS_PTR || answer_header.type == DNS_NS || answer_header.type == DNS_CNAME) {
            string_offset = 0;
            answer_text = parse_string(answer_start, buffer, nullptr, string_offset, pkt_size);
            if (answer_text == "")
                return nullptr;
            answer_start += string_offset;
        }

        printf("\t\t%s %s %s TTL = %d\n", rrname.c_str(), print_dns_type(answer_header.type).c_str(), answer_text.c_str(), answer_header.TTL);

        answers_parsed++;
    }
    if (answers_parsed < num_answers) {
        printf("\t\t++ invalid section: not enough records (e.g. declared 5 answers but only 3 found)");
        return nullptr;
    }

    return answer_start;
}

// Answer format:
// fdh + question + answers
void sb::DNS::parse_response(char* buffer, int pkt_size, int q_length) {

    FixedDNSHeader* fdh = (FixedDNSHeader*)buffer;

    unsigned short flags = ntohs(fdh->flags);

    unsigned short num_questions = ntohs(fdh->questions);
    unsigned short num_answers = ntohs(fdh->answers);
    unsigned short num_additional = ntohs(fdh->additional);
    unsigned short num_authority = ntohs(fdh->authority);

    printf("\tTXID 0x%x flags 0x%x questions %d answers %d authority %d additional %d\n", ntohs(fdh->id), flags, num_questions, num_answers, num_authority, num_additional);

    if (fdh->id != header->id) {
        printf("\t++ invalid reply: TXID mismatch, sent 0x%x, recieved 0x%x\n", ntohs(header->id), ntohs(fdh->id));
        return;
    }

    if ((flags & 0b111) == 0) {
        printf("\tsucceeded with Rcode = 0\n");
    }
    else {
        printf("\tfailed with Rcode = %d\n", flags & 0b111);
        return;
    }

    char* question_start = (char*)(((FixedDNSHeader*)buffer) + 1);
    if (num_questions > 0) {
        printf("\t------------ [questions] ------------\n");
    }
    unsigned short questions_parsed = 0;
    while (questions_parsed < num_questions && question_start < (buffer + pkt_size)) {

        int string_offset = 0;

        std::string rrname = parse_string(question_start, buffer, nullptr, string_offset, pkt_size);
        if (rrname == "")
            return;
        question_start += string_offset;
        if (question_start >= buffer + pkt_size) {
            printf("\t\t++ invalid record: RR value length streteches the answer beyond packet");
            return;
        }

        if (question_start + 10 >= buffer + pkt_size) {
            printf("\t\t++ invalid record: truncated RR answer header (i.e., don't have the full 10 bytes)");
            return;
        }

        QueryHeader question_header;
        question_header.type = ntohs(((QueryHeader*)question_start)->type);
        question_header.qclass = ntohs(((QueryHeader*)question_start)->qclass);

        question_start = (char*)((sb::QueryHeader*)question_start + 1);

        printf("\t\t%s %d %d\n", rrname.c_str(), question_header.type, question_header.qclass);
        questions_parsed++;
    }
    if (questions_parsed < num_questions) {
        printf("\t\t++ invalid section: not enough records (e.g. declared 5 answers but only 3 found)");
        return;
    }

    char* answer_start = (buffer + q_length);
    answer_start = parse_response_section("answers", buffer, num_answers, answer_start, pkt_size);
    if (answer_start == nullptr)
        return;
    answer_start = parse_response_section("authority", buffer, num_authority, answer_start, pkt_size);
    if (answer_start == nullptr)
        return;
    parse_response_section("additional", buffer, num_additional, answer_start, pkt_size);
}