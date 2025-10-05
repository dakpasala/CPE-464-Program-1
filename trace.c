typedef unsigned char  u_char;
typedef unsigned short u_short;
typedef unsigned int   u_int;
typedef unsigned long  u_long;


#include <sys/types.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <string.h>
#include "checksum.h"
#include "trace.h"

void print_mac(const u_char *mac) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void udp(const u_char *packet) {
    struct udp_header udp;
    memcpy(&udp.src_port, packet, 2);
    memcpy(&udp.dest_port, packet + 2, 2);
    memcpy(&udp.len, packet + 4, 2);
    memcpy(&udp.checksum, packet + 6, 2);

    // dereference because they're variables not arrays
    // just so for a reminder when doing C next time so i don't forget
    // when passing in an array, no dereference is needed because the array name is a pointer to the first element

    printf("\n");

    printf("\tUDP Header\n");
    printf("\t\tSource Port: ");

    // port stuff that was asked on the assignment, should be double checked

    // ntohs convert to cpu byte order from network byte order so we can read it properly
    
    u_int16_t src = ntohs(udp.src_port);
    if (src == 80) printf("HTTP\n");
    else if (src == 23) printf("Telnet\n");
    else if (src == 21) printf("FTP\n");
    else if (src == 110) printf("POP3\n");
    else if (src == 53) printf("DNS\n");
    else if (src == 25) printf("SMTP\n");
    else printf("%u\n", src);

    printf("\t\tDest Port: ");

    u_int16_t dest = ntohs(udp.dest_port);
    if (dest == 80)  printf("HTTP\n");
    else if (dest == 23) printf("Telnet\n");
    else if (dest == 21) printf("FTP\n");
    else if (dest == 110) printf("POP3\n");
    else if (dest == 53) printf("DNS\n");
    else if (dest == 25) printf("SMTP\n");
    else printf("%u\n", dest);

    // printf("\t\tLength: %u\n", ntohs(udp.len));
    // printf("\t\tChecksum: %u\n", ntohs(udp.checksum));
}

void tcp(const u_char *packet, int tcp_len, struct in_addr s, struct in_addr d) {
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

    printf("\t\tSource Port: ");

    u_int16_t src = ntohs(tcp.src_port);
    if (src == 80) printf("HTTP\n");
    else if (src == 23) printf("Telnet\n");
    else if (src == 21) printf("FTP\n");
    else if (src == 110) printf("POP3\n");
    else if (src == 53) printf("DNS\n");
    else if (src == 25) printf("SMTP\n");
    else printf("%u\n", src);
    
    printf("\t\tDest Port: ");

    u_int16_t dest = ntohs(tcp.dest_port);
    if (dest == 80)  printf("HTTP\n");
    else if (dest == 23) printf("Telnet\n");
    else if (dest == 21) printf("FTP\n");
    else if (dest == 110) printf("POP3\n");
    else if (dest == 53) printf("DNS\n");
    else if (dest == 25) printf("SMTP\n");
    else printf("%u\n", dest);

    // the point of the above is to print the src and dest ports
    // if we know the ports like specfied on the spec, actually print the name
    // else just print the number
   

    printf("\t\tSequence Number: %u\n", ntohl(tcp.seq_num));
    printf("\t\tACK Number: %u\n", ntohl(tcp.ack_num));

    // formatted as same as the diff, github has older variables if needed for reference

    int raw = ntohs(tcp.offset_flags);
    int data_offset = 0;
    if (raw & 0x1000) data_offset |= 0x1;
    if (raw & 0x2000) data_offset |= 0x2;
    if (raw & 0x4000) data_offset |= 0x4;
    if (raw & 0x8000) data_offset |= 0x8;

    // check the top 4 bits of the field because in offset_flags
    // data offset is part of the top 4 bits
    // the anding checks if the bit it set, and then we or it to set the corresponding bit

    printf("\t\tData Offset (bytes): %d\n", data_offset + data_offset + data_offset + data_offset);

    // in the tcp header, there's a 16 bit field called data offset + reserved + flags
    // here the first 4 bits represent the data offset
    // and then multiply by 4 to get num of bytes

    int flags = raw & 0x01FF;  // mask off bottom 9 bits

    printf("\t\tSYN Flag: %s\n", (flags & 0x002) ? "Yes" : "No");
    printf("\t\tRST Flag: %s\n", (flags & 0x004) ? "Yes" : "No");
    printf("\t\tFIN Flag: %s\n", (flags & 0x001) ? "Yes" : "No");
    printf("\t\tACK Flag: %s\n", (flags & 0x010) ? "Yes" : "No");
    printf("\t\tWindow Size: %d\n", ntohs(tcp.window));

    // all this masking stuff is because we can't bit shift
    // need to get better at masking because i keep forgetting and looking it up

    // okay so lowkey had to gpt a bit of this, but i kind of understand it now
    // add more comments along the way
    // but i believe its cause the tcp checksum isn't just over tcp, it also needs some ip header info
    // and we call it pseudo because it isn't actually transmitted in the packet, it's just for the checksum math

    struct pseudo_header psh;
    psh.src_addr = s.s_addr;
    psh.dst_addr = d.s_addr;
    psh.zero = 0;
    psh.proto = 6;
    psh.tcp_len = htons(tcp_len);

    // since we're sending to "network", the len is converted to network byte order

    int psize = sizeof(struct pseudo_header) + tcp_len;
    unsigned char *buf = malloc(psize);
    memcpy(buf, &psh, sizeof(struct pseudo_header));
    memcpy(buf + sizeof(struct pseudo_header), packet, tcp_len);

    // and also the reason we're able to do this is because in c when we just just memcpy
    // we're basically passing in the raw memory so the data type here didn't really matter yk

    unsigned short result = in_cksum((unsigned short*)buf, psize);
    free(buf);

    if (result == 0) printf("\t\tChecksum: Correct (0x%04x)\n", ntohs(tcp.checksum));
    else printf("\t\tChecksum: Incorrect (0x%04x)\n", ntohs(tcp.checksum));

    // i think the new thing i can understand about this checksum process is
    // we need those ip headers because it's needed in the checksum calculation
    // but they can be discareded after because it's kinda like this idea
    // imagine when u get a box from amazon or something
    // u care about what's in the inside, but u gotta makes sure it came to the right address
    // u checking is like the "checksum" of this and then that label is thrown away
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

    // basic memcpy stuff no explanation needed
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
    int header_len = ihl + ihl + ihl + ihl; // haha got away with the * 4

    // ihl = "Internet Header Length" from the IP header
    // when multiplied by 4, it gives the actual bytes
    // header_len represents how how many bytes long the IP header is

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

        // header_len is what occupies the beginning, so subtracting
        // it will allow for the length of just the tcp segment

        tcp(packet + header_len, tcp_len, s, d);
    }
    else if (ip.proto == 17) {
        printf("UDP\n");
        if (result == 0) printf("\t\tChecksum: Correct (0x%04x)\n", ntohs(ip.crc));
        else printf("\t\tChecksum: Incorrect (0x%04x)\n", ntohs(ip.crc));

        printf("\t\tSender IP: %s\n", inet_ntoa(s));
        printf("\t\tDest IP: %s\n", inet_ntoa(d));

        udp(packet + header_len);
    }
    else {
        printf("Unknown\n");
        if (result == 0) printf("\t\tChecksum: Correct (0x%04x)\n", ntohs(ip.crc));
        else printf("\t\tChecksum: Incorrect (0x%04x)\n", ntohs(ip.crc));

        printf("\t\tSender IP: %s\n", inet_ntoa(s));
        printf("\t\tDest IP: %s\n", inet_ntoa(d));
    }
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

    // okay the reason we're using a struct in_addr here is because
    // the inet_ntoa function requires a struct in_addr as input
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
    if (type == 0x0806) printf("\t\tType: ARP\n");
    else if (type == 0x0800) printf("\t\tType: IP\n");
    else printf("\t\tType: 0x%04x\n", type);

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

    // skip the 14 bits because of the fact that the ethernet header is 14 bytes long
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

    // error handling above to make sure the correct arguments are passed in

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

    printf("\n");

    pcap_close(handle);
    return 0;
}
