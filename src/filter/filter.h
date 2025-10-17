#ifndef FILTER_H
#define FILTER_H

#include "rules.h"
#include "../capture/packet.h"

struct filter_ctx {
    struct ruleset rules;
    uint64_t total_packets;
    uint64_t total_bytes;
    uint64_t dropped_packets;
    uint64_t accepted_packets;
};

struct filter_ctx *filter_init(void);
void filter_cleanup(struct filter_ctx *ctx);
int filter_packet(struct filter_ctx *ctx, struct packet_info *pkt);
int filter_add_rule(struct filter_ctx *ctx, uint8_t chain, struct rule *rule);
int filter_delete_rule(struct filter_ctx *ctx, uint8_t chain, uint32_t rule_id);
void filter_dump_rules(struct filter_ctx *ctx, uint8_t chain);

#endif
