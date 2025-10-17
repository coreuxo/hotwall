#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include "packet.h"
#include "../util/util.h"

int packet_parse(struct packet_info *pkt) {
    uint8_t *ptr = pkt->data;
    uint32_t remaining = pkt->len;
    
    if (remaining < ETH_HEADER_SIZE) {
        return -1;
    }
    
    pkt->eth = (struct ether_header *)ptr;
    ptr += ETH_HEADER_SIZE;
    remaining -= ETH_HEADER_SIZE;
    
    if (ntohs(pkt->eth->ether_type) != ETHERTYPE_IP) {
        return -2;
    }
    
    if (remaining < sizeof(struct iphdr)) {
        return -3;
    }
    
    pkt->ip = (struct iphdr *)ptr;
    
    if (pkt->ip->version != 4) {
        return -4;
    }
    
    uint16_t ip_len = ntohs(pkt->ip->tot_len);
    if (ip_len > remaining) {
        return -5;
    }
    
    pkt->src_ip = pkt->ip->saddr;
    pkt->dst_ip = pkt->ip->daddr;
    pkt->protocol = pkt->ip->protocol;
    
    ptr += pkt->ip->ihl * 4;
    remaining = ip_len - (pkt->ip->ihl * 4);
    
    pkt->is_fragment = (ntohs(pkt->ip->frag_off) & 0x1FFF) != 0;
    
    switch (pkt->protocol) {
        case IPPROTO_TCP:
            if (remaining >= sizeof(struct tcphdr)) {
                pkt->tcp = (struct tcphdr *)ptr;
                pkt->src_port = ntohs(pkt->tcp->source);
                pkt->dst_port = ntohs(pkt->tcp->dest);
                pkt->is_tcp = 1;
                
                uint8_t tcp_hdr_len = pkt->tcp->doff * 4;
                if (remaining > tcp_hdr_len) {
                    pkt->payload = ptr + tcp_hdr_len;
                    pkt->payload_len = remaining - tcp_hdr_len;
                }
            }
            break;
            
        case IPPROTO_UDP:
            if (remaining >= sizeof(struct udphdr)) {
                pkt->udp = (struct udphdr *)ptr;
                pkt->src_port = ntohs(pkt->udp->source);
                pkt->dst_port = ntohs(pkt->udp->dest);
                pkt->is_udp = 1;
                
                if (remaining > sizeof(struct udphdr)) {
                    pkt->payload = ptr + sizeof(struct udphdr);
                    pkt->payload_len = remaining - sizeof(struct udphdr);
                }
            }
            break;
            
        case IPPROTO_ICMP:
            if (remaining >= sizeof(struct icmphdr)) {
                pkt->icmp = (struct icmphdr *)ptr;
                pkt->is_icmp = 1;
                pkt->payload = ptr + sizeof(struct icmphdr);
                pkt->payload_len = remaining - sizeof(struct icmphdr);
            }
            break;
    }
    
    return 0;
}

void packet_hexdump(struct packet_info *pkt) {
    printf("Packet %u bytes:\n", pkt->len);
    hexdump(pkt->data, pkt->len > 64 ? 64 : pkt->len);
}

const char *protocol_str(uint8_t proto) {
    switch (proto) {
        case IPPROTO_TCP: return "TCP";
        case IPPROTO_UDP: return "UDP";
        case IPPROTO_ICMP: return "ICMP";
        default: return "OTHER";
    }
}
