#pragma once
#include <cstdint>
#include <unordered_map>

#include "checksum.h"

//for each socket connection
enum class TCPState {
    LISTEN,
    SYN_RECEIVED,
    ESTABLISHED,
    CLOSE_WAIT,
    CLOSED
};

#pragma pack(push, 1)
struct TcpHeader {
    uint16_t src_port;
    uint16_t dest_port;
    uint32_t seq_num;
    uint32_t ack_num;

    uint8_t data_offset_reserved;
    uint8_t flags; //FIN, SYN, RST, PSH, ACK, URG

    uint16_t window_size;
    uint16_t checksum;
    uint16_t urget_pointer;
};

struct ConnectionKey {
    uint32_t src_ip;
    uint32_t dest_ip;
    uint16_t src_port;
    uint16_t dest_port;

    bool operator==(const ConnectionKey& other) const {
        return src_ip == other.src_ip &&
               dest_ip == other.dest_ip &&
               src_port == other.src_port &&
               dest_port == other.dest_port;
    }
};

struct TcpPseudoHeader {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint8_t zero;
    uint8_t protocol; //6 for tcp
    uint16_t tcp_length; //tcp header + payload len
};

struct Tcb {
    TCPState state;
    uint32_t SND_NXT; //seq # - next seq # to send
    uint32_t SND_UNA; //seq # - smallest seq # sent prev
    uint32_t RCV_NXT; //seq # - next expected to receive
    uint16_t RCV_WND; //buffer space available - flow control
};

namespace std {
    template <>
    struct hash<ConnectionKey> {
        size_t operator() (const ConnectionKey& key) const {
            //hash individually, XOR into one result 
            size_t h1 = std::hash<uint32_t>{}(key.src_ip);
            size_t h2 = std::hash<uint32_t>{}(key.dest_ip);
            size_t h3 = std::hash<uint32_t>{}(key.src_port);
            size_t h4 = std::hash<uint32_t>{}(key.dest_port);

            return h1 ^ (h2 << 1) ^ (h3 << 2) ^ (h4 << 3);
        }
    };
}

constexpr size_t WINDOW_CAPACITY = 4096;
using ConnectionTable = std::unordered_map<ConnectionKey, Tcb>;

void send_tcp_reply(int fd, EthernetHeader* eth, Ipv4Header* ip, TcpHeader* tcp, uint8_t* local_mac,
                     uint32_t src_ip, uint32_t dest_ip, uint8_t reply_flags,
                     const uint8_t* payload_ptr, ssize_t payload_length) {
    tcp->flags = reply_flags;

    size_t total_header_size = sizeof(EthernetHeader) + sizeof(Ipv4Header) + sizeof(TcpHeader) + payload_length;
    eth->ethertype = htons(0x0800);

    //swap MACs
    uint8_t prev_dest_mac[6];
    std::memcpy(prev_dest_mac, eth->src_mac, 6);
    std::memcpy(eth->src_mac, local_mac, 6);
    std::memcpy(eth->dst_mac, prev_dest_mac, 6);

    uint32_t prev_src_ip = ip->sourceIP;
    ip->sourceIP = ip->destIP;
    ip->destIP = prev_src_ip;
    ip->checksum = 0;
    ip->checksum = fold_and_generate(sum_words(reinterpret_cast<uint8_t*>(ip), sizeof(Ipv4Header), 0));
    ip->protocol = 6;

    uint16_t prev_src_port = tcp->src_port;
    tcp->src_port = tcp->dest_port;
    tcp->dest_port = prev_src_port;
    tcp->checksum = 0;

    TcpPseudoHeader pseudo_header {dest_ip, src_ip, 0, 6, static_cast<uint16_t>(sizeof(TcpHeader) + payload_length)};
    uint32_t pseudo_sum = sum_words(reinterpret_cast<const uint8_t*>(&pseudo_header), sizeof(TcpPseudoHeader), 0);
    uint32_t tcp_and_pseudo_sum = sum_words(reinterpret_cast<const uint8_t*>(tcp), sizeof(TcpHeader), pseudo_sum);
    uint32_t all_sum = sum_words(payload_ptr, payload_length, tcp_and_pseudo_sum);

    tcp->checksum = fold_and_generate(all_sum);

    write(fd, eth, total_header_size);
}

void handle_tcp (int fd, uint8_t* packet, ssize_t n, uint32_t src_ip, uint32_t dest_ip, uint8_t* local_mac, EthernetHeader* eth, Ipv4Header* ip, ConnectionTable& connection_table) {
    if (static_cast<ssize_t>(sizeof(TcpHeader)) > n) {
        std::cout << "Packet too short to contain a TCP Packet\n" << std::endl;
        return;
    }
    std::cout << "TCP\n" << std::endl;

    TcpHeader* tcp = reinterpret_cast<TcpHeader*>(packet);

    uint16_t src_port = ntohs(tcp->src_port);
    uint16_t dest_port = ntohs(tcp->dest_port);

    bool FIN = tcp->flags & 0x01;
    bool SYN = tcp->flags & 0x02;
    bool RST = tcp->flags & 0x04;
    bool PSH = tcp->flags & 0x08;
    bool ACK = tcp->flags & 0x10;
    bool URG = tcp->flags & 0x20;

    const uint8_t* payload_ptr = packet + sizeof(TcpHeader);
    const ssize_t payload_length = n - sizeof(TcpHeader);

    ConnectionKey key {src_ip, dest_ip, src_port, dest_port};
    Tcb& tcb = connection_table[key];
    uint32_t seq_num = ntohl(tcp->seq_num); //incoming seq #
    uint32_t ack_num = ntohl(tcp->ack_num); //incoming ack #

    bool should_reply = false;
    uint8_t reply_flags = 0;

    //new connection, not acknowledged yet
    if (SYN && !ACK) {
        tcb.state = TCPState::SYN_RECEIVED;
        tcb.RCV_NXT = seq_num + 1;
        //use 0 as personal isn, next to send is 1
        tcb.SND_NXT = 1;
        tcb.SND_UNA = 0; //we expect 0 back
        tcb.RCV_WND = WINDOW_CAPACITY;
        should_reply = true;
        reply_flags = 0x12;

    }
    //last part of handshake
    else if (ACK && !SYN) {
        if (ack_num != tcb.SND_NXT) { //check the ACK matches SYN # we expect to receive next
            std::cout << "unexpected ACK\n";
            return;
        }
        tcb.state = TCPState::ESTABLISHED;
        tcb.SND_UNA = ack_num;
    }

    //established connection, plain data arriving
    else if (PSH && ACK && !SYN && !FIN) {
        tcb.RCV_NXT += payload_length; //advance buffer
        ack_num = tcb.RCV_NXT;
        should_reply = true;
        reply_flags = 0x10;
    }

    //close connection
    else if (FIN) {
        tcb.RCV_NXT += 1;
        tcb.state = TCPState::CLOSE_WAIT;
        should_reply = true;
        reply_flags = 0x10;
    }

    //abort
    else if (RST) {
        tcb.state = TCPState::CLOSED;
        connection_table.erase(key);
    }
    if (should_reply) {
        send_tcp_reply(fd, eth, ip, tcp, local_mac, src_ip, dest_ip, reply_flags, payload_ptr, payload_length);
    }
}