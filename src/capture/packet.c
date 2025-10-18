#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include "packet.h"
#include "../util/util.h"
#include "../util/debug.h"

int packet_parse(struct packet_info *pkt) {
    uint8_t *ptr = pkt->data;
    uint32_t remaining = pkt->len;
    
    if (remaining < ETH_HEADER_SIZE) {
        DBG("Packet too small for Ethernet header: %u bytes\n", remaining);
        return -1;
    }
    
    pkt->eth = (struct ether_header *)ptr;
    ptr += ETH_HEADER_SIZE;
    remaining -= ETH_HEADER_SIZE;
    
    uint16_t ether_type = ntohs(pkt->eth->ether_type);
    if (ether_type != ETHERTYPE_IP) {
        DBG("Not IP packet: 0x%04x\n", ether_type);
        return -2;
    }
    
    if (remaining < sizeof(struct iphdr)) {
        DBG("Packet too small for IP header: %u bytes\n", remaining);
        return -3;
    }
    
    pkt->ip = (struct iphdr *)ptr;
    
    if (pkt->ip->version != 4) {
        DBG("Not IPv4: version=%d\n", pkt->ip->version);
        return -4;
    }
    
    uint16_t ip_len = ntohs(pkt->ip->tot_len);
    if (ip_len > remaining) {
        DBG("IP length %u > remaining %u\n", ip_len, remaining);
        return -5;
    }
    
    uint8_t ip_hdr_len = pkt->ip->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr)) {
        DBG("Invalid IP header length: %u\n", ip_hdr_len);
        return -6;
    }
    
    pkt->src_ip = pkt->ip->saddr;
    pkt->dst_ip = pkt->ip->daddr;
    pkt->protocol = pkt->ip->protocol;
    
    ptr += ip_hdr_len;
    remaining = ip_len - ip_hdr_len;
    
    pkt->is_fragment = (ntohs(pkt->ip->frag_off) & 0x1FFF) != 0;
    
    switch (pkt->protocol) {
        case IPPROTO_TCP:
            if (remaining >= sizeof(struct tcphdr)) {
                pkt->tcp = (struct tcphdr *)ptr;
                pkt->src_port = ntohs(pkt->tcp->source);
                pkt->dst_port = ntohs(pkt->tcp->dest);
                pkt->is_tcp = 1;
                
                uint8_t tcp_hdr_len = pkt->tcp->doff * 4;
                if (tcp_hdr_len < sizeof(struct tcphdr)) {
                    DBG("Invalid TCP header length: %u\n", tcp_hdr_len);
                    break;
                }
                
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
            
        default:
            DBG("Unhandled protocol: %d\n", pkt->protocol);
            break;
    }
    
    return 0;
}

void packet_hexdump(struct packet_info *pkt) {
    printf("Packet %u bytes:\n", pkt->len);
    if (pkt->eth) {
        printf("Ethernet: %02x:%02x:%02x:%02x:%02x:%02x -> %02x:%02x:%02x:%02x:%02x:%02x type=0x%04x\n",
               pkt->eth->ether_shost[0], pkt->eth->ether_shost[1], pkt->eth->ether_shost[2],
               pkt->eth->ether_shost[3], pkt->eth->ether_shost[4], pkt->eth->ether_shost[5],
               pkt->eth->ether_dhost[0], pkt->eth->ether_dhost[1], pkt->eth->ether_dhost[2],
               pkt->eth->ether_dhost[3], pkt->eth->ether_dhost[4], pkt->eth->ether_dhost[5],
               ntohs(pkt->eth->ether_type));
    }
    
    if (pkt->ip) {
        char src_ip[16], dst_ip[16];
        inet_ntop(AF_INET, &pkt->src_ip, src_ip, sizeof(src_ip));
        inet_ntop(AF_INET, &pkt->dst_ip, dst_ip, sizeof(dst_ip));
        
        printf("IP: %s -> %s proto=%d len=%d\n",
               src_ip, dst_ip, pkt->protocol, ntohs(pkt->ip->tot_len));
    }
    
    if (pkt->tcp) {
        printf("TCP: %d -> %d flags=0x%02x seq=%u ack=%u\n",
               pkt->src_port, pkt->dst_port,
               pkt->tcp->syn | (pkt->tcp->ack << 1) | (pkt->tcp->fin << 2) |
               (pkt->tcp->rst << 3) | (pkt->tcp->psh << 4),
               ntohl(pkt->tcp->seq), ntohl(pkt->tcp->ack_seq));
    } else if (pkt->udp) {
        printf("UDP: %d -> %d len=%d\n",
               pkt->src_port, pkt->dst_port, ntohs(pkt->udp->len));
    } else if (pkt->icmp) {
        printf("ICMP: type=%d code=%d\n",
               pkt->icmp->type, pkt->icmp->code);
    }
    
    hexdump(pkt->data, pkt->len > 64 ? 64 : pkt->len);
}

const char *protocol_str(uint8_t proto) {
    switch (proto) {
        case IPPROTO_TCP: return "TCP";
        case IPPROTO_UDP: return "UDP";
        case IPPROTO_ICMP: return "ICMP";
        case 1: return "ICMP";
        case 6: return "TCP";
        case 17: return "UDP";
        default: return "OTHER";
    }
}
