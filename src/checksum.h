#pragma once
#include <cstdint>

uint32_t sum_words(const uint8_t* data, size_t len, uint32_t running_sum = 0) {
    //build w high byte first (network byte order)
    for (int i=0; i< len/2; i++) {
        uint16_t word = (data[i*2] << 8) | data[i*2+1];
        running_sum += word;
    }
    
    return running_sum;
}

bool fold_and_verify(uint32_t sum) {
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return sum == 0xFFFF;
}

uint16_t fold_and_generate(uint32_t sum) {
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    //debug - need bitwise NOT of folded sum so our verify matches
    return ~sum;
}