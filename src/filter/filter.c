#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "filter.h"
#include "../state/state.h"
#include "../util/debug.h"

struct filter_ctx *filter_init(void) {
    struct filter_ctx *ctx;
    
    ctx = calloc(1, sizeof(struct filter_ctx));
    if (!ctx) {
        ERROR("Failed to allocate filter context\n");
        return NULL;
    }
    
    ruleset_init(&ctx->rules);
    DBG("Filter initialized\n");
    
    return ctx;
}

void filter_cleanup(struct filter_ctx *ctx) {
    if (ctx) {
        rule_chain_clear(&ctx->rules.input);
        rule_chain_clear(&ctx->rules.output);
        rule_chain_clear(&ctx->rules.forward);
        free(ctx);
        DBG("Filter cleaned up\n");
    }
}

int filter_packet(struct filter_ctx *ctx, struct packet_info *pkt) {
    struct rule_chain *chain;
    struct rule *current;
    int action = RULE_ACTION_ACCEPT;
    
    if (!ctx || !pkt) {
        DBG("Invalid parameters to filter_packet\n");
        return RULE_ACTION_ACCEPT;
    }
    
    ctx->total_packets++;
    ctx->total_bytes += pkt->len;
    
    switch (pkt->direction) {
        case 0: chain = &ctx->rules.input; break;
        case 1: chain = &ctx->rules.output; break;
        case 2: chain = &ctx->rules.forward; break;
        default: 
            DBG("Invalid packet direction: %d\n", pkt->direction);
            chain = &ctx->rules.input; 
            break;
    }
    
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
                
                const char *action_str;
                switch (action) {
                    case RULE_ACTION_ACCEPT: action_str = "ACCEPT"; break;
                    case RULE_ACTION_DROP: action_str = "DROP"; break;
                    case RULE_ACTION_REJECT: action_str = "REJECT"; break;
                    default: action_str = "UNKNOWN"; break;
                }
                
                LOG("RULE %s %s %s:%d -> %s:%d proto=%d len=%d\n",
                    action_str, protocol_str(pkt->protocol),
                    src_ip, pkt->src_port, dst_ip, pkt->dst_port,
                    pkt->protocol, pkt->len);
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
        ERROR("Invalid parameters to filter_add_rule\n");
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
            ERROR("Invalid chain type: %d\n", chain_type);
            return -1;
    }
    
    int ret = rule_add(chain, &new_rule);
    if (ret == 0) {
        DBG("Added rule %d to chain %d\n", new_rule.id, chain_type);
    } else {
        ERROR("Failed to add rule to chain %d\n", chain_type);
    }
    
    return ret;
}

int filter_delete_rule(struct filter_ctx *ctx, uint8_t chain_type, uint32_t rule_id) {
    struct rule_chain *chain;
    
    if (!ctx) {
        ERROR("Invalid context\n");
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
            ERROR("Invalid chain type: %d\n", chain_type);
            return -1;
    }
    
    int ret = rule_delete(chain, rule_id);
    if (ret == 0) {
        DBG("Deleted rule %d from chain %d\n", rule_id, chain_type);
    } else {
        DBG("Rule %d not found in chain %d\n", rule_id, chain_type);
    }
    
    return ret;
}

void filter_dump_rules(struct filter_ctx *ctx, uint8_t chain_type) {
    struct rule_chain *chain;
    struct rule *current;
    char src_ip[16], dst_ip[16], src_mask[16], dst_mask[16];
    
    if (!ctx) {
        printf("No filter context\n");
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
            printf("Invalid chain type: %d\n", chain_type);
            return;
    }
    
    if (chain->rule_count == 0) {
        printf("No rules in chain\n");
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
            case RULE_ACTION_LOG: action_str = "LOG"; break;
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
