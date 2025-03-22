#ifndef SB_DNS_H
#define SB_DNS_H
#include <string>

namespace sb {
struct LookUp {
    std::string name;
    bool is_ip;
};

struct FixedDNSHeader {
    unsigned short id;
    unsigned short flags;
    unsigned short questions;
    unsigned short answers;
    unsigned short authority;
    unsigned short additional;
};

struct QueryHeader {
    unsigned short type;
    unsigned short qclass;
};

#pragma pack(push,1) // sets struct padding/alignment to 1 byte
struct DNSanswerHdr {
    unsigned short type;
    unsigned short aclass;
    unsigned int TTL;
    unsigned short len;
};
#pragma pack(pop) // restores old packing


class DNS {
public:

    void take_query(const std::string& lookup, const std::string& server);
    void udp_send_recieve();
    void print_info();

private:

    std::string convert_ip_to_lookup(const std::string& ip);
    std::string print_query(LookUp lookup, std::string server, int id);

    void parse_response(char* buffer, int max_size, int q_length);

    bool check_if_ip(const std::string& lookup_name);

    LookUp lookup;
    FixedDNSHeader* header;
    QueryHeader* q_header;
    std::string server;
};

}
#endif
