#ifndef TRACE_H
#define TRACE_H

#include <stdint.h>

#pragma pack(push, 1)

struct ethernet_header {
    uint8_t dest[6];
    uint8_t src[6];
    uint16_t type;
};

struct arp_header {
    uint16_t htype;
    uint16_t ptype;
    uint8_t hlen;
    uint8_t plen;
    uint16_t oper;
    uint8_t sha[6];
    uint8_t spa[4];
    uint8_t tha[6];
    uint8_t tpa[4];
};

struct ip_header {
    uint8_t ver_ihl;
    uint8_t tos;
    uint16_t tlen;
    uint16_t identification;
    uint16_t flags_fo;
    uint8_t ttl;
    uint8_t proto;
    uint16_t crc;
    uint8_t saddr[4];
    uint8_t daddr[4];
};

struct icmp_header {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint16_t id;
    uint16_t seq;
};

struct tcp_header {
    uint16_t src_port;
    uint16_t dest_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint16_t offset_flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent_ptr;
};

struct udp_header {
    uint16_t src_port;
    uint16_t dest_port;
    uint16_t len;
    uint16_t checksum;
};

struct pseudo_header {
    uint32_t src_addr;
    uint32_t dst_addr;
    uint8_t zero;
    uint8_t proto;
    uint16_t tcp_len;
};

#pragma pack(pop)

#endif
