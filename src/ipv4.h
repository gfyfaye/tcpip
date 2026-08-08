#pragma once
#include <cstdint>
#include <iostream>


#include "checksum.h"
#include "udp.h"

#pragma pack(push, 1)

struct Ipv4Header {
        uint8_t version_ihl;
        uint8_t  tos;
        uint16_t total_length;
        uint16_t id;
        uint16_t flags_offset;
        uint8_t ttl;
        uint8_t protocol;
        uint16_t checksum;
        uint32_t sourceIP;
        uint32_t destIP;
    //options go here
};

void handle_ipv4 (const uint8_t* packet, ssize_t n, UdpSocketManager& socket_manager) {

    if ( n < static_cast<ssize_t>(sizeof(Ipv4Header))) {
        std::cout << "Packet too short to contain an IPv4 Packet\n" << std::endl;
        return;
    }

    //cast buffer onto Ipv4Header
    const Ipv4Header* ip = reinterpret_cast<const Ipv4Header*>(packet);

    uint8_t version = ip->version_ihl >> 4;
    uint8_t ihl = ip->version_ihl & 0x0F;

    //sanity check
    if (version != 4) {
        return;
    }

    uint32_t real_length = 4 * ihl;

    if (static_cast<ssize_t>(real_length) > n) {
        return;
    }
    
    if (!check_checksum(packet, real_length)) {
        return;
    }

    std::cout << "ttl: " << static_cast<int>(ip->ttl) << std::endl;
    std::cout << "protocol: " << static_cast<int>(ip->protocol) << std::endl;
    std::cout << "real length: " << real_length << std::endl;
    std::cout << "source IP: " << ip->sourceIP << std::endl;
    std::cout << "dest IP: " << ip->destIP << std::endl;

    if (ip->protocol == 17) {
        handle_udp(packet + real_length, n - static_cast<ssize_t>(real_length), socket_manager);
    }
}