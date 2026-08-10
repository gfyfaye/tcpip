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
#include "arp.h"
#include "ipv4.h"
#include "timing.h"

constexpr size_t BUFFER_SIZE = 2048;

void handle_frame(int fd, uint8_t* buf, ssize_t n, uint32_t local_ip, uint8_t* local_mac, std::unordered_map<uint32_t, std::array<uint8_t, 6>>& arp_table, UdpSocketManager& socket_manager, ConnectionTable& connection_table) {
    if (n < static_cast<ssize_t>(sizeof(EthernetHeader))) {
            std::cout << "Packet too short to contain a valid Ethernet header\n" << std::endl;
            return;
        }
    
    EthernetHeader* eth = reinterpret_cast<EthernetHeader*>(buf);

    std::cout << "Dest MAC addr"<< std::endl;
    print_mac(eth->dst_mac);

    std::cout << "SRC MAC addr" << std::endl;
    print_mac(eth->src_mac);
    

    std::cout << "Ethertype" << std::endl;
    uint16_t ethertype = ntohs(eth->ethertype);
    std::cout << std::hex << std::setw(4) << std::setfill('0') << ethertype << std::dec << std::endl;
        
    if (ethertype == 0x0806) {
        handle_arp(fd, buf, eth, n, local_ip, local_mac, arp_table);
    }
    else if (ethertype == 0x0800) {
        handle_ipv4(fd, buf + sizeof(EthernetHeader), n - static_cast<ssize_t>(sizeof(EthernetHeader)), local_mac, eth, socket_manager, connection_table);
    }
}

int main() {
    std::unordered_map<uint32_t, std::array<uint8_t, 6>> arp_table; //maps IP addr to MAC addr
    arp_table.reserve(64);

    UdpSocketManager socket_manager; //maps dst_port to a registered queue
    socket_manager.reserve(64);
    
    ConnectionTable connection_table; //maps tcp connection to tcb state
    connection_table.reserve(64);

    uint64_t total_cycles = 0;
    uint64_t packet_count = 0;
    
    int fd = open("/dev/net/tun", O_RDWR);

    if (fd == -1) {
        perror("Error opening file\n");
        return 1;
    }

    //request TAP device 
    struct ifreq ifr;
    std::memset(&ifr, 0, sizeof(ifr));

    //provide l2 Ethernet frames not l3 IP packets + don't prepend the 4-byte 'packet info' struct
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI; 

    std::memcpy(ifr.ifr_name, "tap0", 5);

    if (ioctl(fd, TUNSETIFF, reinterpret_cast<void*>(&ifr)) < 0) {
        perror("Failed to configure TAP interface via ioctl.\n");
        close(fd);
        return 1;
    }
    //claim an IP address
    uint32_t local_ip = inet_addr("10.0.0.5");
    uint8_t local_mac[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};

    //read stream
    uint8_t buffer[BUFFER_SIZE];
    while (true) {
        std::memset(buffer, 0, BUFFER_SIZE);
        
        ssize_t bytes_read = read(fd, buffer, BUFFER_SIZE);

        if (bytes_read == -1) {
            std::cerr << "Read error on TAP interface\n";
            break;
        }

        if (bytes_read == 0) {
            std::cout << "TAP interface closed connection\n";
            break;
        }
        uint64_t start = read_cycles();
        handle_frame(fd, buffer, bytes_read, local_ip, local_mac, arp_table, socket_manager, connection_table);
        uint64_t end = read_cycles();

        total_cycles += end - start;
        packet_count++;

        if (packet_count % 10 == 0) {
            std::cout << "avg cycles/packet: " << (total_cycles / packet_count) << std::endl;
        }

    }
    close(fd);
    return 0;

}