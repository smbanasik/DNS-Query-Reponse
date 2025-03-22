// Spencer Banasik
// Program for Class
// Spring 2025

#include <iostream>

#include <Windows.h>

#include "dns.h"

#pragma comment(lib,"WS2_32")

void usage() {
    std::cout << "Error! Invalid arguments!\n"
        << "Proper format is below, you must input a lookup string\n"
        << "and a DNS server IP.\n"
        << "hw2.exe www.website.com 192.168.0.1\n"
        << "hw2.exe 127.0.0.1 192.168.0.1\n";
}

// lookup string (at argv[1]) and DNS ip (at argv[2])

int main(int argc, char* argv[]) {

    if (argc != 3) {
        usage();
    }
    else {
        WSAData win_data;
        WORD wVersionRequested = MAKEWORD(2, 2);
        if (WSAStartup(wVersionRequested, &win_data) != 0) {
            printf("WSAStartup error %d\n", WSAGetLastError());
            WSACleanup();
            return 0;
        }

        sb::DNS dns;

        dns.take_query(argv[1], argv[2]);
        dns.udp_send_recieve();
    }

    return 0;
}