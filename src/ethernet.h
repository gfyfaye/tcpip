#pragma once
#include <stdio.h>
#include <iostream>
#include <cstdint>
#include <fcntl.h>
#include <cstring>
#include <unistd.h>
#include <iomanip>

#pragma pack(push, 1)
struct EthernetHeader {
    uint8_t dst_mac[6];
    uint8_t src_mac[6];
    uint16_t ethertype;
};

void print_mac(const uint8_t* mac) {
    for (int i = 0; i < 6; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(mac[i]);
        if (i < 5) std::cout << ":";
    }
    std::cout << std::endl;
}