#include <stdio.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <libnet.h>

#define MAX_DUMP_LENGTH 10

#define STATIC_ETHER_HDR_SIZE 14
#define STATIC_IP_HDR_SIZE 20
#define STATIC_TCP_HDR_SIZE 20
#define MIN(a, b) (((a) < (b)) ? (a) : (b))

inline void print_char(char c) {
    if(0x20 <= c && c < 0x7F)
        printf("%c", c);
    else {
        printf(".");
    }
}

inline void print_mac(char *name, uint8_t *mac) {
    printf("%s = %02x:%02x:%02x:%02x:%02x:%02x\n", name, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}
inline void print_ip(char *name, uint8_t *ip) {
    printf("%s = %d.%d.%d.%d\n", name, ip[0], ip[1], ip[2], ip[3]);
}
inline void print_port(char *name, uint8_t *p) {
    printf("%s = %d\n", name, (p[0] << 8) + p[1]);
}
inline void dump_data(uint8_t *p, int32_t len) {
    int32_t _len = MIN(MAX_DUMP_LENGTH, len);
    int32_t idx = 0;
    while(idx < _len) {
        int tmp = MIN(_len - idx, 16);
        for(int i = idx; i < idx + tmp; i++) {
            printf("%02X ", p[i]);
        }
        for(int i = tmp; i < 16; i++) {
            printf("   ");
        }
        printf("    ");
        for(int i = idx; i < idx + tmp; i++) {
            print_char(p[i]);
        }
        printf("\n");
        idx += tmp;
    }
}

void usage() {
    printf("syntax: pcap_test <interface>\n");
    printf("sample: pcap_test wlan0\n");
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return -1;
    }


    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;
        printf("========================\n");
        printf("%u bytes captured\n", header->caplen);

        // Ethernet packet size check
        int32_t total_length = header->caplen;
        int32_t left_length = total_length;
        if(left_length < STATIC_ETHER_HDR_SIZE) {
            printf("[!] Wrong Ethernet Packet Size\n");
            continue;
        }

        // Parse ethernet packet
        struct libnet_ethernet_hdr *view_ethernet = (struct libnet_ethernet_hdr *) packet;
        print_mac("smac", view_ethernet->ether_shost);
        print_mac("dmac", view_ethernet->ether_dhost);

        if (ntohs(view_ethernet->ether_type) != ETHERTYPE_IP) {
            printf("[-] Not an IP packet. Skipping...\n");
            continue;
        }


        // IPv4 packet size check 1
        left_length -= sizeof(struct libnet_ethernet_hdr);
        if(left_length < STATIC_IP_HDR_SIZE) {
            printf("[!] Wrong IPv4 Packet Size (1)\n");
            continue;
        }

        // Parse IPv4 packet
        packet += sizeof(struct libnet_ethernet_hdr);
        struct libnet_ipv4_hdr *view_ip = (struct libnet_ipv4_hdr *) packet;
        print_ip("sip", (uint8_t *) &view_ip->ip_src);
        print_ip("dip", (uint8_t *) &view_ip->ip_dst);

        if(view_ip->ip_p != IPPROTO_TCP) {
            printf("[-] Not a TCP packet. Skipping...\n");
            continue;
        }

        // IPv4 packet size check 2
        if(left_length != ntohs(view_ip->ip_len) || left_length < ((view_ip->ip_hl) * sizeof(uint32_t))) {
            printf("[!] Wrong IPv4 Packet Size (2)\n");
            continue;
        }

        left_length -= (view_ip->ip_hl) * sizeof(uint32_t);

        // TCP packet size check 1
        if(left_length < STATIC_TCP_HDR_SIZE) {
            printf("[!] Wrong TCP Packet Size (1)\n");
            continue;
        }
        
        packet += sizeof(struct libnet_ipv4_hdr);
        struct libnet_tcp_hdr *view_tcp = (struct libnet_tcp_hdr *) packet;
        print_port("sport", (uint8_t *) &view_tcp->th_sport);
        print_port("dport", (uint8_t *) &view_tcp->th_dport);

        // TCP packet size check 2
        if(left_length < (view_tcp->th_off * sizeof(uint32_t))) {
            printf("[!] Wrong TCP Packet Size (2)\n");
            continue;
        }
        left_length -= (view_tcp->th_off * sizeof(uint32_t));
        packet += (view_tcp->th_off * sizeof(uint32_t));
        dump_data((uint8_t *)packet, left_length);
    }

    pcap_close(handle);
    return 0;
}
