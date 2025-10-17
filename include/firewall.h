#ifndef FIREWALL_H
#define FIREWALL_H

#include <stdint.h>

#define NAT_TYPE_SNAT 1
#define NAT_TYPE_DNAT 2
#define NAT_TYPE_MASQUERADE 3
#define NAT_TYPE_REDIRECT 4

struct firewall_ctx;

struct firewall_ctx *firewall_init(void);
int firewall_start(struct firewall_ctx *ctx);
void firewall_stop(struct firewall_ctx *ctx);
void firewall_cleanup(struct firewall_ctx *ctx);

void firewall_add_nat_rule(struct firewall_ctx *ctx, int type, uint32_t src_ip, uint32_t src_mask,
                          uint32_t dst_ip, uint32_t dst_mask, uint16_t src_port, uint16_t dst_port,
                          int protocol, uint32_t nat_ip, uint16_t nat_port);
uint64_t firewall_get_stats(struct firewall_ctx *ctx, int stat_type);

#endif
