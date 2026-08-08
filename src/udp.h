#pragma once
#include <span>
#include <cstdint>
#include <unordered_map>
#include <memory>
#include <iostream>
#include <arpa/inet.h>

#include "checksum.h"
#include "spsc_queue.h"

#pragma pack(push, 1)

struct UdpHeader {
    uint16_t source_port;
    uint16_t dest_port;
    uint16_t length;
    uint16_t checksum;
};

constexpr size_t UDP_QUEUE_CAPACITY = 1024;
using UdpQueue = SPSCQueue<std::span<const uint8_t>, UDP_QUEUE_CAPACITY>;
using UdpSocketManager = std::unordered_map<uint16_t, std::unique_ptr<UdpQueue>>;

void handle_udp (const uint8_t* packet, ssize_t n, UdpSocketManager& socket_manager) {

    if (static_cast<ssize_t>(sizeof(UdpHeader)) > n) {
        std::cout << "Packet too short to contain a UDP Packet\n" << std::endl;
        return;
    }
    std::cout << "UDP\n" << std::endl;


    const UdpHeader* udp = reinterpret_cast<const UdpHeader*>(packet);

    uint16_t source_port = ntohs(udp->source_port);
    uint16_t dest_port = ntohs(udp->dest_port);

    std::cout << "UDP source port: " << source_port << std::endl;
    std::cout << "UDP dest port: " << dest_port << std::endl;

    if (ntohs(udp->length) < sizeof(UdpHeader)) {
        return;
    }
    uint16_t payload_length = ntohs(udp->length) - sizeof(UdpHeader);
    const uint8_t* payload_ptr = packet + sizeof(UdpHeader);

    std::span<const uint8_t> payload(payload_ptr, payload_length);

    auto it = socket_manager.find(dest_port);
    if (it != socket_manager.end()) {
        it->second->push(payload);
    }
}