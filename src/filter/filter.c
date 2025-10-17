#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "filter.h"

struct filter_ctx *filter_init(void) {
    struct filter_ctx *ctx;
    
    ctx = malloc(sizeof(struct filter_ctx));
    if (!ctx) {
        return NULL;
    }
    
    memset(ctx, 0, sizeof(struct filter_ctx));
    ruleset_init(&ctx->rules);
    
    return ctx;
}

void filter_cleanup(struct filter_ctx *ctx) {
    if (ctx) {
        rule_chain_clear(&ctx->rules.input);
        rule_chain_clear(&ctx->rules.output);
        rule_chain_clear(&ctx->rules.forward);
        free(ctx);
    }
}

int filter_packet(struct filter_ctx *ctx, struct packet_info *pkt) {
    struct rule_chain *chain;
    struct rule *current;
    int action = RULE_ACTION_ACCEPT; /* default accept */
    
    if (!ctx || !pkt) {
        return RULE_ACTION_ACCEPT;
    }
    
    ctx->total_packets++;
    ctx->total_bytes += pkt->len;
    
    /* determine which chain to use based on packet direction */
    switch (pkt->direction) {
        case 0: chain = &ctx->rules.input; break;
        case 1: chain = &ctx->rules.output; break;
        case 2: chain = &ctx->rules.forward; break;
        default: chain = &ctx->rules.input; break;
    }
    
    /* walk through rules in the chain */
    current = chain->head;
    while (current) {
        if (rule_match(current, pkt)) {
            action = current->action;
            current->packet_count++;
            current->byte_count += pkt->len;
            
            if (current->log) {
                char src_ip[16], dst_ip[16];
                inet_ntop(AF_INET, &pkt->src_ip, src_ip, sizeof(src_ip));
                inet_ntop(AF_INET, &pkt->dst_ip, dst_ip, sizeof(dst_ip));
                
                printf("RULE LOG: %s %s:%d -> %s:%d proto=%d action=%d\n",
                       protocol_str(pkt->protocol),
                       src_ip, pkt->src_port,
                       dst_ip, pkt->dst_port,
                       pkt->protocol, action);
            }
            
            break;
        }
        current = current->next;
    }
    
    if (action == RULE_ACTION_ACCEPT) {
        ctx->accepted_packets++;
    } else {
        ctx->dropped_packets++;
    }
    
    return action;
}

int filter_add_rule(struct filter_ctx *ctx, uint8_t chain_type, struct rule *rule) {
    struct rule_chain *chain;
    struct rule new_rule;
    
    if (!ctx || !rule) {
        return -1;
    }
    
    memcpy(&new_rule, rule, sizeof(struct rule));
    new_rule.id = ctx->rules.next_rule_id++;
    
    switch (chain_type) {
        case RULE_DIR_IN:
            chain = &ctx->rules.input;
            break;
        case RULE_DIR_OUT:
            chain = &ctx->rules.output;
            break;
        case RULE_DIR_FORWARD:
            chain = &ctx->rules.forward;
            break;
        default:
            return -1;
    }
    
    return rule_add(chain, &new_rule);
}

int filter_delete_rule(struct filter_ctx *ctx, uint8_t chain_type, uint32_t rule_id) {
    struct rule_chain *chain;
    
    if (!ctx) {
        return -1;
    }
    
    switch (chain_type) {
        case RULE_DIR_IN:
            chain = &ctx->rules.input;
            break;
        case RULE_DIR_OUT:
            chain = &ctx->rules.output;
            break;
        case RULE_DIR_FORWARD:
            chain = &ctx->rules.forward;
            break;
        default:
            return -1;
    }
    
    return rule_delete(chain, rule_id);
}

void filter_dump_rules(struct filter_ctx *ctx, uint8_t chain_type) {
    struct rule_chain *chain;
    struct rule *current;
    char src_ip[16], dst_ip[16], src_mask[16], dst_mask[16];
    
    if (!ctx) {
        return;
    }
    
    switch (chain_type) {
        case RULE_DIR_IN:
            chain = &ctx->rules.input;
            break;
        case RULE_DIR_OUT:
            chain = &ctx->rules.output;
            break;
        case RULE_DIR_FORWARD:
            chain = &ctx->rules.forward;
            break;
        default:
            return;
    }
    
    printf("Chain %s (%d rules):\n", chain->name, chain->rule_count);
    printf("num  target  prot opt source        destination   ports\n");
    printf("---  ------  ---- --- ------        -----------   -----\n");
    
    current = chain->head;
    while (current) {
        const char *action_str;
        switch (current->action) {
            case RULE_ACTION_ACCEPT: action_str = "ACCEPT"; break;
            case RULE_ACTION_DROP: action_str = "DROP"; break;
            case RULE_ACTION_REJECT: action_str = "REJECT"; break;
            default: action_str = "UNKNOWN"; break;
        }
        
        inet_ntop(AF_INET, &current->src_ip, src_ip, sizeof(src_ip));
        inet_ntop(AF_INET, &current->dst_ip, dst_ip, sizeof(dst_ip));
        inet_ntop(AF_INET, &current->src_mask, src_mask, sizeof(src_mask));
        inet_ntop(AF_INET, &current->dst_mask, dst_mask, sizeof(dst_mask));
        
        printf("%-4d %-7s %-4s --- %-15s %-15s", 
               current->id, action_str, 
               current->protocol == PROTO_ANY ? "any" : 
               current->protocol == PROTO_TCP ? "tcp" :
               current->protocol == PROTO_UDP ? "udp" : "icmp",
               current->src_mask == 0 ? "anywhere" : src_ip,
               current->dst_mask == 0 ? "anywhere" : dst_ip);
        
        if (current->src_port_start > 0) {
            printf(" %d:%d", current->src_port_start, current->src_port_end);
        } else {
            printf(" *:*");
        }
        
        printf(" -> ");
        
        if (current->dst_port_start > 0) {
            printf("%d:%d", current->dst_port_start, current->dst_port_end);
        } else {
            printf("*:*");
        }
        
        if (current->log) {
            printf(" [LOG]");
        }
        
        printf(" (pkts:%lu bytes:%lu)\n", 
               current->packet_count, current->byte_count);
        
        current = current->next;
    }
}
