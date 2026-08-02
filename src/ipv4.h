#pragma once
#include <cstdint>
#include <iostream>

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

// Byte 0:     Version (4 bits) | IHL (4 bits)
// Byte 1:     DSCP/ECN (not important for you yet)
// Bytes 2-3:  Total Length (16 bits)
// Bytes 4-5:  Identification (16 bits)
// Bytes 6-7:  Flags (3 bits) | Fragment Offset (13 bits)
// Byte 8:     TTL
// Byte 9:     Protocol
// Bytes 10-11: Header Checksum
// Bytes 12-15: Source IP
// Bytes 16-19: Destination IP
// [optional: Options, if IHL > 5]

bool check_checksum(const uint8_t* header, size_t header_len) {
    // steps
    // 1. treats the IPv4 header as a seq of 16-bit unsigned ints
    // 2. set the checksum field itself to 0x0000 during init generation
    // 3. sum all 16-bit words into a 32-bit int (so overflow carries aren’t lost)
    // 4. fold carries: add the upper 16bits back into the lower 16 bits til no overflow remains
    // verification: 
    // sum all 16-bit words + the received checksum field
    // if packet is uncorrupted, result of 1’s complement addition over the entire header will equal 0xFFFF
    uint32_t sum = 0;

    for (int i=0; i< header_len/2; i++) {
        //
        uint16_t word = (header[i*2] << 8) | header[i*2+1];
        sum += word;
    }

    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return sum == 0xFFFF;
}

void handle_ipv4 (const uint8_t* packet, ssize_t n) {

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

    std::cout << "ttl: " << ip->ttl << std::endl;
    std::cout << "protocol: " << ip->protocol << std::endl;
     std::cout << "real length: " << real_length << std::endl;
    std::cout << "source IP: " << ip->sourceIP << std::endl;
    std::cout << "dest IP: " << ip->destIP << std::endl;
}