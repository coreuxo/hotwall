#ifndef INJECT_H
#define INJECT_H

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/icmp.h>
#include <net/ethernet.h>

struct inject_ctx {
    int raw_sock;
    char iface[16];
    int mtu;
};

struct inject_ctx *inject_init(const char *iface);
void inject_cleanup(struct inject_ctx *ctx);
int inject_packet(struct inject_ctx *ctx, uint8_t *packet, uint32_t len);
int inject_tcp_rst(struct inject_ctx *ctx, uint32_t src_ip, uint32_t dst_ip, 
                   uint16_t src_port, uint16_t dst_port, uint32_t seq, uint32_t ack);
int inject_icmp_unreach(struct inject_ctx *ctx, uint32_t src_ip, uint32_t dst_ip,
                       uint8_t *original_pkt, uint32_t orig_len, uint8_t code);
int build_ip_packet(struct iphdr *ip, uint8_t protocol, uint32_t src_ip, 
                   uint32_t dst_ip, uint16_t payload_len);
int build_tcp_packet(struct tcphdr *tcp, uint16_t src_port, uint16_t dst_port,
                    uint32_t seq, uint32_t ack, uint8_t flags, uint16_t window);

#endif
