#pragma once
#include <cstint>

bool check_checksum(const uint8_t* header, size_t header_len) {
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