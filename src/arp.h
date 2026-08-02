#pragma once
#include <stdio.h>
#include <iostream>
#include <cstdint>
#include <fcntl.h>
#include <cstring>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <iomanip>
#include <arpa/inet.h> 
#include <unordered_map>
#include <array>

#include "ethernet.h"


#pragma pack(push, 1)
struct ArpPacket {
    uint16_t hardwaretype;
    uint16_t protocoltype;
    uint8_t hardware_addr_type;
    uint8_t protocol_addr_type;
    uint16_t opcode;
    uint8_t senderMAC[6];
    uint32_t senderIP;
    uint8_t targetMAC[6];
    uint32_t targetIP;
};

void handle_arp(int fd,  uint8_t* buf, EthernetHeader* eth, ssize_t n, uint32_t local_ip, uint8_t* local_mac, std::unordered_map<uint32_t, std::array<uint8_t, 6>>& arp_table) {
    if (n < 14 + sizeof(ArpPacket)) {
            std::cout << "Packet too short to contain an ARP request\n" << std::endl;
            return;
        }

        ArpPacket* arp = reinterpret_cast<ArpPacket*>((buf + sizeof(EthernetHeader)));
        // opcode 1 = packet is a request
        //update arp cache
        std::memcpy(arp_table[arp->senderIP].data(), arp->senderMAC, 6);
        print_mac(arp_table[arp->senderIP].data());

        if (ntohs(arp->opcode) != 1) {
            return;
        }

        if (arp->targetIP != local_ip) {
            return;
        }
    
        //write response packet
        arp->opcode = htons(2);
        uint8_t requester_mac[6];
        std::memcpy(requester_mac, arp->senderMAC, 6);

        uint32_t requester_ip = arp->senderIP;

        arp->senderIP = local_ip;
        std::memcpy(arp->senderMAC, local_mac, 6);

        arp->targetIP = requester_ip;
        std::memcpy(arp->targetMAC, requester_mac, 6);

        std::memcpy(eth->dst_mac, requester_mac, 6);
        std::memcpy(eth->src_mac, local_mac, 6);

        write(fd, buf, 14+sizeof(ArpPacket));
    }