#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <string.h>

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

void print_mac(const u_char *mac) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
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

    if (ntohs(arp.oper) == 1)
        printf("\t\tOpcode: Request\n");
    else if (ntohs(arp.oper) == 2)
        printf("\t\tOpcode: Reply\n");
    else
        printf("\t\tOpcode: Unknown\n");

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
            // ip(packet + 14);
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
