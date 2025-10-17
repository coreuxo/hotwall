#ifndef PACKET_H
#define PACKET_H

#include <stdint.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/icmp.h>
#include <net/ethernet.h>

#define MAX_PACKET_SIZE 65536
#define ETH_HEADER_SIZE 14

struct packet_info {
    uint8_t *data;
    uint32_t len;
    uint32_t cap_len;
    
    struct ether_header *eth;
    struct iphdr *ip;
    struct tcphdr *tcp;
    struct udphdr *udp;
    struct icmphdr *icmp;
    
    uint8_t *payload;
    uint32_t payload_len;
    
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
    
    uint8_t is_fragment:1;
    uint8_t is_tcp:1;
    uint8_t is_udp:1;
    uint8_t is_icmp:1;
    uint8_t direction:2; /* 0=in, 1=out, 2=forward */
};

struct packet_ctx {
    int raw_sock;
    char *iface;
    uint32_t promisc;
    uint32_t timeout_ms;
};

int packet_parse(struct packet_info *pkt);
void packet_hexdump(struct packet_info *pkt);
const char *protocol_str(uint8_t proto);

#endif
