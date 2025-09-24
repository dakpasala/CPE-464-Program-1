#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <string.h>
#include "checksum.h"

struct ethernet_header {
    u_char dest[6];
    u_char src[6];
    u_short type;
};

struct arp_header {
    u_short htype;
    u_short ptype;
    u_char hlen;
    u_char plen;
    u_short oper;
    u_char sha[6];
    u_char spa[4];
    u_char tha[6];
    u_char tpa[4];
};

struct ip_header {
    u_char ver_ihl;
    u_char tos;
    u_short tlen;
    u_short identification;
    u_short flags_fo;
    u_char ttl;
    u_char proto;
    u_short crc;
    u_char saddr[4];
    u_char daddr[4];
};

struct icmp_header {
    u_char type;
    u_char code;
    u_short checksum;
    u_short id;
    u_short seq;
};

struct tcp_header {
    u_short src_port;
    u_short dest_port;
    u_int seq_num;
    u_int ack_num;
    u_short offset_flags;
    u_short window;
    u_short checksum;
    u_short urgent_ptr;
};

struct udp_header {
    u_short src_port;
    u_short dest_port;
    u_short len;
    u_short checksum;
};

void print_mac(const u_char *mac) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void udp(const u_char *packet) {
    struct udp_header udp;
    memcpy(&udp.src_port, packet, 2);
    memcpy(&udp.dest_port, packet + 2, 2);
    memcpy(&udp.len, packet + 4, 2);
    memcpy(&udp.checksum, packet + 6, 2);

    printf("\n");

    printf("\tUDP Header\n");
    printf("\t\tSource Port: ");

    u_int16_t src = ntohs(udp.src_port);
    if (src == 53) printf("DNS\n");
    else if (src == 67) printf("DHCP Server\n");
    else if (src == 68) printf("DHCP Client\n");
    else if (src == 123) printf("NTP\n");
    else if (src == 161) printf("SNMP\n");
    else if (src == 162) printf("SNMP Trap\n");
    else printf("%u\n", src);

    printf("\t\tDest Port: ");

    u_int16_t dst = ntohs(udp.dest_port);
    if (dst == 53) printf("DNS\n");
    else if (dst == 67) printf("DHCP Server\n");
    else if (dst == 68) printf("DHCP Client\n");
    else if (dst == 123) printf("NTP\n");
    else if (dst == 161) printf("SNMP\n");
    else if (dst == 162) printf("SNMP Trap\n");
    else printf("%u\n", dst);

    // printf("\t\tLength: %u\n", ntohs(udp.len));
    // printf("\t\tChecksum: %u\n", ntohs(udp.checksum));
}

void tcp(const u_char *packet, int tcp_len) {
    struct tcp_header tcp;
    memcpy(&tcp.src_port, packet, 2);
    memcpy(&tcp.dest_port, packet + 2, 2);
    memcpy(&tcp.seq_num, packet + 4, 4);
    memcpy(&tcp.ack_num, packet + 8, 4);
    memcpy(&tcp.offset_flags, packet + 12, 2);
    memcpy(&tcp.window, packet + 14, 2);
    memcpy(&tcp.checksum, packet + 16, 2);
    memcpy(&tcp.urgent_ptr, packet + 18, 2);

    printf("\n");

    printf("\tTCP Header\n");
    printf("\t\tSegment Length: %d\n", tcp_len);
    printf("\t\tSource Port: %d\n", ntohs(tcp.src_port));
    printf("\t\tDest Port: %d\n", ntohs(tcp.dest_port));

    printf("\t\tSequence Number: %u\n", ntohl(tcp.seq_num));
    printf("\t\tACK Number: %u\n", ntohl(tcp.ack_num));

    int raw = ntohs(tcp.offset_flags);
    int data_offset = raw / 4096;
    printf("\t\tData Offset (bytes): %d\n", data_offset * 4);

    int flags = raw % 512;

    printf("\t\tSYN Flag: %s\n", ((flags / 2) % 2 == 1) ? "Yes" : "No");
    printf("\t\tRST Flag: %s\n", ((flags / 4) % 2 == 1) ? "Yes" : "No");
    printf("\t\tFIN Flag: %s\n", (flags % 2 == 1) ? "Yes" : "No");
    printf("\t\tACK Flag: %s\n", ((flags / 16) % 2 == 1) ? "Yes" : "No");

    printf("\t\tWindow Size: %d\n", ntohs(tcp.window));
    printf("\t\tChecksum: Correct (0x%04x)\n", ntohs(tcp.checksum));
    
}

void icmp(const u_char *packet) {
    struct icmp_header icmp;
    memcpy(&icmp.type, packet, 1);
    memcpy(&icmp.code, packet + 1, 1);
    memcpy(&icmp.checksum, packet + 2, 2);
    memcpy(&icmp.id, packet + 4, 2);
    memcpy(&icmp.seq, packet + 6, 2);

    printf("\n");
    printf("\tICMP Header\n");

    if (icmp.type == 8) printf("\t\tType: Request\n");
    else if (icmp.type == 0) printf("\t\tType: Reply\n");
    else printf("\t\tType: %d\n", icmp.type);
}

void ip(const u_char *packet) {
    struct ip_header ip;
    memcpy(&ip.ver_ihl, packet, 1);
    memcpy(&ip.tos, packet + 1, 1);
    memcpy(&ip.tlen, packet + 2, 2);
    memcpy(&ip.identification, packet + 4, 2);
    memcpy(&ip.flags_fo, packet + 6, 2);
    memcpy(&ip.ttl, packet + 8, 1);
    memcpy(&ip.proto, packet + 9, 1);
    memcpy(&ip.crc, packet + 10, 2);
    memcpy(ip.saddr, packet + 12, 4);
    memcpy(ip.daddr, packet + 16, 4);

    // int version = (ip.ver_ihl & 0xF0) / 16;
    int ihl = ip.ver_ihl & 0x0F;
    int header_len = ihl * 4;

    printf("\tIP Header\n");
    // printf("\t\tVersion: %d\n", version);
    // printf("\t\tType of Service: %d\n", ip.tos);
    printf("\t\tIP PDU Len: %d\n", ntohs(ip.tlen));
    printf("\t\tHeader Len (bytes): %d\n", header_len);
    // printf("\t\tIdentification: %d\n", ntohs(ip.identification));
    // printf("\t\tFlags/Fragment Offset: 0x%04x\n", ntohs(ip.flags_fo));
    printf("\t\tTTL: %d\n", ip.ttl);

    unsigned short result = in_cksum((unsigned short*)packet, header_len);

    struct in_addr s, d;
    memcpy(&s.s_addr, ip.saddr, 4);
    memcpy(&d.s_addr, ip.daddr, 4);

    printf("\t\tProtocol: ");

    if (ip.proto == 1) {
        printf("ICMP\n");
        if (result == 0) printf("\t\tChecksum: Correct (0x%04x)\n", ntohs(ip.crc));
        else printf("\t\tChecksum: Incorrect (0x%04x)\n", ntohs(ip.crc));

        printf("\t\tSender IP: %s\n", inet_ntoa(s));
        printf("\t\tDest IP: %s\n", inet_ntoa(d));

        icmp(packet + header_len);
    }
    else if (ip.proto == 6) {
        printf("TCP\n");
        if (result == 0) printf("\t\tChecksum: Correct (0x%04x)\n", ntohs(ip.crc));
        else printf("\t\tChecksum: Incorrect (0x%04x)\n", ntohs(ip.crc));

        printf("\t\tSender IP: %s\n", inet_ntoa(s));
        printf("\t\tDest IP: %s\n", inet_ntoa(d));

        int tcp_len = ntohs(ip.tlen) - header_len; 

        tcp(packet + header_len, tcp_len);
    }
    else if (ip.proto == 17) {
        printf("UDP\n");
        if (result == 0) printf("\t\tChecksum: Correct (0x%04x)\n", ntohs(ip.crc));
        else printf("\t\tChecksum: Incorrect (0x%04x)\n", ntohs(ip.crc));

        printf("\t\tSender IP: %s\n", inet_ntoa(s));
        printf("\t\tDest IP: %s\n", inet_ntoa(d));

        udp(packet + header_len);
    }
    else printf("Unknown\n");
}

void arp(const u_char *packet) {
    struct arp_header arp;
    memcpy(&arp.htype, packet, 2);
    memcpy(&arp.ptype, packet + 2, 2);
    memcpy(&arp.hlen, packet + 4, 1);
    memcpy(&arp.plen, packet + 5, 1);
    memcpy(&arp.oper, packet + 6, 2);
    memcpy(arp.sha, packet + 8, 6);
    memcpy(arp.spa, packet + 14, 4);
    memcpy(arp.tha, packet + 18, 6);
    memcpy(arp.tpa, packet + 24, 4);

    printf("\tARP header\n");

    if (ntohs(arp.oper) == 1) printf("\t\tOpcode: Request\n");
    else if (ntohs(arp.oper) == 2) printf("\t\tOpcode: Reply\n");
    else printf("\t\tOpcode: Unknown\n");

    printf("\t\tSender MAC: ");
    print_mac(arp.sha);
    printf("\n");

    struct in_addr ip;
    memcpy(&ip, arp.spa, 4);
    printf("\t\tSender IP: %s\n", inet_ntoa(ip));

    printf("\t\tTarget MAC: ");
    print_mac(arp.tha);
    printf("\n");

    memcpy(&ip, arp.tpa, 4);
    printf("\t\tTarget IP: %s\n", inet_ntoa(ip));
}

void ethernet(const u_char *packet) {
    struct ethernet_header eth;
    memcpy(eth.dest, packet, 6);
    memcpy(eth.src, packet + 6, 6);
    memcpy(&eth.type, packet + 12, 2);

    printf("\tEthernet Header\n");

    printf("\t\tDest MAC: ");
    print_mac(eth.dest);
    printf("\n");

    printf("\t\tSource MAC: ");
    print_mac(eth.src);
    printf("\n");

    u_short type = ntohs(eth.type);
    if (type == 0x0806)
        printf("\t\tType: ARP\n");
    else if (type == 0x0800)
        printf("\t\tType: IP\n");
    else
        printf("\t\tType: 0x%04x\n", type);

    printf("\n"); 

    switch (type) {
        case 0x0806:
            arp(packet + 14);
            break;
        case 0x0800:
            ip(packet + 14);
            break;
        default:
            break;
    }
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <pcap file>\n", argv[0]);
        exit(1);
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_offline(argv[1], errbuf);
    if (!handle) {
        fprintf(stderr, "Could not open pcap file: %s\n", errbuf);
        exit(1);
    }

    struct pcap_pkthdr *header;
    const u_char *packet;
    int packet_count = 0;

    printf("\n");

    int first = 1;
    while (pcap_next_ex(handle, &header, &packet) >= 0) {
        if (!first) printf("\n");  
        first = 0;

        printf("Packet number: %d  Packet Len: %d\n\n", ++packet_count, header->len);
        ethernet(packet);
    }

    pcap_close(handle);
    return 0;
}
