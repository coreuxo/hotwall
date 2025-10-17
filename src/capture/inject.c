#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if.h>
#include <errno.h>
#include <arpa/inet.h>
#include "inject.h"
#include "../util/util.h"

struct inject_ctx *inject_init(const char *iface) {
    struct inject_ctx *ctx;
    struct ifreq ifr;
    int sockfd, ret;
    
    sockfd = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW);
    if (sockfd < 0) {
        perror("socket raw");
        return NULL;
    }
    
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    
    ret = ioctl(sockfd, SIOCGIFINDEX, &ifr);
    if (ret < 0) {
        perror("ioctl SIOCGIFINDEX");
        close(sockfd);
        return NULL;
    }
    
    ret = ioctl(sockfd, SIOCGIFMTU, &ifr);
    if (ret < 0) {
        perror("ioctl SIOCGIFMTU");
        close(sockfd);
        return NULL;
    }
    
    ctx = malloc(sizeof(struct inject_ctx));
    if (!ctx) {
        close(sockfd);
        return NULL;
    }
    
    ctx->raw_sock = sockfd;
    strncpy(ctx->iface, iface, sizeof(ctx->iface) - 1);
    ctx->mtu = ifr.ifr_mtu;
    
    return ctx;
}

void inject_cleanup(struct inject_ctx *ctx) {
    if (ctx) {
        if (ctx->raw_sock >= 0) {
            close(ctx->raw_sock);
        }
        free(ctx);
    }
}

int inject_packet(struct inject_ctx *ctx, uint8_t *packet, uint32_t len) {
    struct sockaddr_ll saddr;
    struct ifreq ifr;
    ssize_t sent;
    int ret;
    
    if (!ctx || !packet || len == 0) {
        return -1;
    }
    
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ctx->iface, IFNAMSIZ - 1);
    
    ret = ioctl(ctx->raw_sock, SIOCGIFINDEX, &ifr);
    if (ret < 0) {
        perror("ioctl SIOCGIFINDEX inject");
        return -1;
    }
    
    memset(&saddr, 0, sizeof(saddr));
    saddr.sll_family = AF_PACKET;
    saddr.sll_protocol = htons(ETH_P_IP);
    saddr.sll_ifindex = ifr.ifr_ifindex;
    saddr.sll_halen = ETH_ALEN;
    
    /* TODO: Ticket 29 */
    memset(saddr.sll_addr, 0xFF, ETH_ALEN);
    
    sent = sendto(ctx->raw_sock, packet, len, 0, 
                  (struct sockaddr *)&saddr, sizeof(saddr));
    if (sent < 0) {
        perror("sendto");
        return -1;
    }
    
    return 0;
}

int build_ip_packet(struct iphdr *ip, uint8_t protocol, uint32_t src_ip, 
                   uint32_t dst_ip, uint16_t payload_len) {
    static uint16_t ip_id = 0;
    
    if (!ip) return -1;
    
    memset(ip, 0, sizeof(struct iphdr));
    
    ip->version = 4;
    ip->ihl = 5;
    ip->tos = 0;
    ip->tot_len = htons(sizeof(struct iphdr) + payload_len);
    ip->id = htons(ip_id++);
    ip->frag_off = 0;
    ip->ttl = 64;
    ip->protocol = protocol;
    ip->saddr = src_ip;
    ip->daddr = dst_ip;
    
    ip->check = 0;
    ip->check = checksum((uint16_t *)ip, sizeof(struct iphdr));
    
    return 0;
}

int build_tcp_packet(struct tcphdr *tcp, uint16_t src_port, uint16_t dst_port,
                    uint32_t seq, uint32_t ack, uint8_t flags, uint16_t window) {
    if (!tcp) return -1;
    
    memset(tcp, 0, sizeof(struct tcphdr));
    
    tcp->source = htons(src_port);
    tcp->dest = htons(dst_port);
    tcp->seq = htonl(seq);
    tcp->ack_seq = htonl(ack);
    tcp->doff = 5;
    tcp->window = htons(window);
    tcp->urg_ptr = 0;
    
    /* Set flags */
    if (flags & 0x01) tcp->fin = 1;
    if (flags & 0x02) tcp->syn = 1;
    if (flags & 0x04) tcp->rst = 1;
    if (flags & 0x08) tcp->psh = 1;
    if (flags & 0x10) tcp->ack = 1;
    if (flags & 0x20) tcp->urg = 1;
    
    return 0;
}

int inject_tcp_rst(struct inject_ctx *ctx, uint32_t src_ip, uint32_t dst_ip, 
                   uint16_t src_port, uint16_t dst_port, uint32_t seq, uint32_t ack) {
    uint8_t packet[1024];
    struct iphdr *ip = (struct iphdr *)packet;
    struct tcphdr *tcp = (struct tcphdr *)(packet + sizeof(struct iphdr));
    struct pseudo_header {
        uint32_t src_ip;
        uint32_t dst_ip;
        uint8_t zero;
        uint8_t protocol;
        uint16_t tcp_len;
    } pseudo;
    int packet_len;
    
    if (!ctx) return -1;
    
    /* Build IP header */
    build_ip_packet(ip, IPPROTO_TCP, src_ip, dst_ip, sizeof(struct tcphdr));
    
    /* Build TCP header with RST flag */
    build_tcp_packet(tcp, src_port, dst_port, seq, ack, 0x04, 0);
    
    /* Calculate TCP checksum with pseudo-header */
    memset(&pseudo, 0, sizeof(pseudo));
    pseudo.src_ip = src_ip;
    pseudo.dst_ip = dst_ip;
    pseudo.zero = 0;
    pseudo.protocol = IPPROTO_TCP;
    pseudo.tcp_len = htons(sizeof(struct tcphdr));
    
    tcp->check = 0;
    
    uint32_t csum = 0;
    uint16_t *ptr = (uint16_t *)&pseudo;
    for (int i = 0; i < sizeof(pseudo)/2; i++) {
        csum += *ptr++;
    }
    
    ptr = (uint16_t *)tcp;
    for (int i = 0; i < sizeof(struct tcphdr)/2; i++) {
        csum += *ptr++;
    }
    
    csum = (csum >> 16) + (csum & 0xffff);
    csum += (csum >> 16);
    tcp->check = ~csum;
    
    packet_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
    
    return inject_packet(ctx, packet, packet_len);
}

int inject_icmp_unreach(struct inject_ctx *ctx, uint32_t src_ip, uint32_t dst_ip,
                       uint8_t *original_pkt, uint32_t orig_len, uint8_t code) {
    uint8_t packet[1500];
    struct iphdr *ip = (struct iphdr *)packet;
    struct icmphdr *icmp = (struct icmphdr *)(packet + sizeof(struct iphdr));
    uint8_t *icmp_data = (uint8_t *)(icmp + 1);
    int packet_len;
    
    if (!ctx || !original_pkt || orig_len == 0) return -1;
    
    /* Copy original IP header + 64 bits of payload */
    uint32_t copy_len = sizeof(struct iphdr) + 8;
    if (orig_len < copy_len) {
        copy_len = orig_len;
    }
    
    memcpy(icmp_data, original_pkt, copy_len);
    
    /* Build IP header for ICMP packet */
    build_ip_packet(ip, IPPROTO_ICMP, src_ip, dst_ip, 
                   sizeof(struct icmphdr) + copy_len);
    
    /* Build ICMP header */
    memset(icmp, 0, sizeof(struct icmphdr));
    icmp->type = ICMP_DEST_UNREACH;
    icmp->code = code;
    
    /* Calculate ICMP checksum */
    icmp->checksum = 0;
    icmp->checksum = checksum((uint16_t *)icmp, sizeof(struct icmphdr) + copy_len);
    
    packet_len = sizeof(struct iphdr) + sizeof(struct icmphdr) + copy_len;
    
    return inject_packet(ctx, packet, packet_len);
}
