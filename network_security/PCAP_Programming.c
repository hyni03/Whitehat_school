#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/if_ether.h>

void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet);

int main(int argc, char *argv[]) {
    if (argc != 2) {
            printf("Usage: %s <interface>\n", argv[0]);
        return 1;
    }

    char *dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

    if (handle == NULL) {
        fprintf(stderr, "Could not open device %s: %s\n", dev, errbuf);
        return 2;
    }

    pcap_loop(handle, 0, packet_handler, NULL);
    pcap_close(handle);

    return 0;
}

void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    struct ether_header *eth_header;
    struct ip *ip_header;
    struct tcphdr *tcp_header;
    char *data;

    eth_header = (struct ether_header *)packet;
    ip_header = (struct ip *)(packet + ETHER_HDR_LEN);
    tcp_header = (struct tcphdr *)(packet + ETHER_HDR_LEN + ip_header->ip_hl * 4);
    data = (char *)(packet + ETHER_HDR_LEN + ip_header->ip_hl * 4 + tcp_header->th_off * 4);

    printf("Ethernet Header: %02x:%02x:%02x:%02x:%02x:%02x / %02x:%02x:%02x:%02x:%02x:%02x\n",
        eth_header->ether_shost[0], eth_header->ether_shost[1], eth_header->ether_shost[2], 
        eth_header->ether_shost[3], eth_header->ether_shost[4], eth_header->ether_shost[5],
        eth_header->ether_dhost[0], eth_header->ether_dhost[1], eth_header->ether_dhost[2], 
        eth_header->ether_dhost[3], eth_header->ether_dhost[4], eth_header->ether_dhost[5]);

    printf("IP Header: %s / %s\n", inet_ntoa(ip_header->ip_src), inet_ntoa(ip_header->ip_dst));

    printf("TCP Header: %d / %d\n", ntohs(tcp_header->th_sport), ntohs(tcp_header->th_dport));

    int data_len = pkthdr->len - (ETHER_HDR_LEN + ip_header->ip_hl * 4 + tcp_header->th_off * 4);
    if (data_len > 0) {
        printf("Message: %s\n", data);
    }

    printf("\n");

}

