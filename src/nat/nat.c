#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include "nat.h"
#include "../util/util.h"

struct nat_ctx *nat_init(uint32_t external_ip) {
    struct nat_ctx *ctx;
    uint32_t i;
    
    ctx = malloc(sizeof(struct nat_ctx));
    if (!ctx) {
        return NULL;
    }
    
    ctx->table = malloc(sizeof(struct nat_table));
    if (!ctx->table) {
        free(ctx);
        return NULL;
    }
    
    ctx->table->size = NAT_TABLE_SIZE;
    ctx->table->count = 0;
    ctx->table->next_port = NAT_PORT_START;
    
    ctx->table->buckets = calloc(NAT_TABLE_SIZE, sizeof(struct nat_mapping*));
    if (!ctx->table->buckets) {
        free(ctx->table);
        free(ctx);
        return NULL;
    }
    
    ctx->rules = NULL;
    ctx->next_rule_id = 1;
    ctx->external_ip = external_ip;
    
    return ctx;
}

void nat_cleanup(struct nat_ctx *ctx) {
    struct nat_rule *rule, *next_rule;
    struct nat_mapping *mapping, *next_mapping;
    uint32_t i;
    
    if (!ctx) return;
    
    /* Clean up rules */
    rule = ctx->rules;
    while (rule) {
        next_rule = rule->next;
        free(rule);
        rule = next_rule;
    }
    
    /* Clean up mappings */
    if (ctx->table && ctx->table->buckets) {
        for (i = 0; i < ctx->table->size; i++) {
            mapping = ctx->table->buckets[i];
            while (mapping) {
                next_mapping = mapping->next;
                free(mapping);
                mapping = next_mapping;
            }
        }
        free(ctx->table->buckets);
    }
    
    free(ctx->table);
    free(ctx);
}

static uint32_t nat_hash(struct nat_mapping *mapping) {
    uint32_t h = 0;
    
    h = hash32(mapping->orig_src_ip);
    h ^= hash32(mapping->orig_dst_ip);
    h ^= hash32((mapping->orig_src_port << 16) | mapping->orig_dst_port);
    h ^= hash32(mapping->protocol);
    
    return h % NAT_TABLE_SIZE;
}

uint16_t nat_alloc_port(struct nat_ctx *ctx) {
    uint16_t port = ctx->table->next_port;
    
    if (port >= NAT_PORT_END) {
        ctx->table->next_port = NAT_PORT_START;
        port = NAT_PORT_START;
    } else {
        ctx->table->next_port++;
    }
    
    return port;
}

int nat_add_rule(struct nat_ctx *ctx, nat_type_t type, uint32_t src_ip, uint32_t src_mask,
                uint32_t dst_ip, uint32_t dst_mask, uint16_t src_port, uint16_t dst_port,
                uint8_t protocol, uint32_t nat_ip, uint16_t nat_port) {
    struct nat_rule *rule, *new_rule;
    
    if (!ctx) return -1;
    
    new_rule = malloc(sizeof(struct nat_rule));
    if (!new_rule) return -1;
    
    memset(new_rule, 0, sizeof(struct nat_rule));
    
    new_rule->id = ctx->next_rule_id++;
    new_rule->type = type;
    new_rule->src_ip = src_ip;
    new_rule->src_mask = src_mask;
    new_rule->dst_ip = dst_ip;
    new_rule->dst_mask = dst_mask;
    new_rule->src_port = src_port;
    new_rule->dst_port = dst_port;
    new_rule->protocol = protocol;
    new_rule->nat_ip = nat_ip;
    new_rule->nat_port = nat_port;
    new_rule->enabled = 1;
    
    /* Add to linked list */
    if (!ctx->rules) {
        ctx->rules = new_rule;
    } else {
        rule = ctx->rules;
        while (rule->next) {
            rule = rule->next;
        }
        rule->next = new_rule;
    }
    
    return new_rule->id;
}

int nat_delete_rule(struct nat_ctx *ctx, uint32_t rule_id) {
    struct nat_rule *rule, *prev = NULL;
    
    if (!ctx) return -1;
    
    rule = ctx->rules;
    while (rule) {
        if (rule->id == rule_id) {
            if (prev) {
                prev->next = rule->next;
            } else {
                ctx->rules = rule->next;
            }
            free(rule);
            return 0;
        }
        prev = rule;
        rule = rule->next;
    }
    
    return -1;
}

struct nat_mapping *nat_find_mapping(struct nat_ctx *ctx, struct packet_info *pkt, int reverse) {
    struct nat_mapping *mapping;
    uint32_t idx, i;
    
    if (!ctx || !pkt) return NULL;
    
    /* Try to find existing mapping */
    for (i = 0; i < ctx->table->size; i++) {
        mapping = ctx->table->buckets[i];
        while (mapping) {
            if (!reverse) {
                /* Forward lookup: original -> NAT */
                if (mapping->orig_src_ip == pkt->src_ip &&
                    mapping->orig_dst_ip == pkt->dst_ip &&
                    mapping->orig_src_port == pkt->src_port &&
                    mapping->orig_dst_port == pkt->dst_port &&
                    mapping->protocol == pkt->protocol) {
                    return mapping;
                }
            } else {
                /* Reverse lookup: NAT -> original */
                if (mapping->new_src_ip == pkt->src_ip &&
                    mapping->new_dst_ip == pkt->dst_ip &&
                    mapping->new_src_port == pkt->src_port &&
                    mapping->new_dst_port == pkt->dst_port &&
                    mapping->protocol == pkt->protocol) {
                    return mapping;
                }
            }
            mapping = mapping->next;
        }
    }
    
    return NULL;
}

int nat_create_mapping(struct nat_ctx *ctx, struct packet_info *pkt, nat_type_t type,
                      uint32_t new_ip, uint16_t new_port) {
    struct nat_mapping *mapping, *new_mapping;
    uint32_t idx;
    
    if (!ctx || !pkt) return -1;
    
    /* Check if mapping already exists */
    mapping = nat_find_mapping(ctx, pkt, 0);
    if (mapping) {
        mapping->last_used = time(NULL);
        return 0;
    }
    
    new_mapping = malloc(sizeof(struct nat_mapping));
    if (!new_mapping) return -1;
    
    memset(new_mapping, 0, sizeof(struct nat_mapping));
    
    new_mapping->orig_src_ip = pkt->src_ip;
    new_mapping->orig_dst_ip = pkt->dst_ip;
    new_mapping->orig_src_port = pkt->src_port;
    new_mapping->orig_dst_port = pkt->dst_port;
    new_mapping->protocol = pkt->protocol;
    
    /* Set up NAT translation based on type */
    switch (type) {
        case NAT_TYPE_SNAT:
        case NAT_TYPE_MASQUERADE:
            new_mapping->new_src_ip = new_ip;
            new_mapping->new_src_port = new_port ? new_port : nat_alloc_port(ctx);
            new_mapping->new_dst_ip = pkt->dst_ip;
            new_mapping->new_dst_port = pkt->dst_port;
            break;
            
        case NAT_TYPE_DNAT:
        case NAT_TYPE_REDIRECT:
            new_mapping->new_src_ip = pkt->src_ip;
            new_mapping->new_src_port = pkt->src_port;
            new_mapping->new_dst_ip = new_ip;
            new_mapping->new_dst_port = new_port ? new_port : pkt->dst_port;
            break;
            
        default:
            free(new_mapping);
            return -1;
    }
    
    new_mapping->last_used = time(NULL);
    
    /* Add to hash table */
    idx = nat_hash(new_mapping);
    new_mapping->next = ctx->table->buckets[idx];
    ctx->table->buckets[idx] = new_mapping;
    ctx->table->count++;
    
    return 0;
}

int nat_process_packet(struct nat_ctx *ctx, struct packet_info *pkt, int direction) {
    struct nat_rule *rule;
    struct nat_mapping *mapping;
    int modified = 0;
    
    if (!ctx || !pkt) return 0;
    
    /* Check rules for matching NAT rule */
    rule = ctx->rules;
    while (rule) {
        if (!rule->enabled) {
            rule = rule->next;
            continue;
        }
        
        /* Check protocol */
        if (rule->protocol != 0 && rule->protocol != pkt->protocol) {
            rule = rule->next;
            continue;
        }
        
        /* Check source IP */
        if (rule->src_mask != 0) {
            uint32_t src_net = pkt->src_ip & rule->src_mask;
            if (src_net != (rule->src_ip & rule->src_mask)) {
                rule = rule->next;
                continue;
            }
        }
        
        /* Check destination IP */
        if (rule->dst_mask != 0) {
            uint32_t dst_net = pkt->dst_ip & rule->dst_mask;
            if (dst_net != (rule->dst_ip & rule->dst_mask)) {
                rule = rule->next;
                continue;
            }
        }
        
        /* Check ports */
        if (rule->src_port != 0 && rule->src_port != pkt->src_port) {
            rule = rule->next;
            continue;
        }
        if (rule->dst_port != 0 && rule->dst_port != pkt->dst_port) {
            rule = rule->next;
            continue;
        }
        
        /* Rule matches, apply NAT */
        uint32_t nat_ip = rule->nat_ip;
        uint16_t nat_port = rule->nat_port;
        
        if (rule->type == NAT_TYPE_MASQUERADE) {
            nat_ip = ctx->external_ip;
            if (nat_port == 0) {
                nat_port = nat_alloc_port(ctx);
            }
        }
        
        /* Create mapping and apply translation */
        if (direction == 0) { /* Outbound */
            if (rule->type == NAT_TYPE_SNAT || rule->type == NAT_TYPE_MASQUERADE) {
                mapping = nat_find_mapping(ctx, pkt, 0);
                if (!mapping) {
                    nat_create_mapping(ctx, pkt, rule->type, nat_ip, nat_port);
                    mapping = nat_find_mapping(ctx, pkt, 0);
                }
                
                if (mapping) {
                    pkt->src_ip = mapping->new_src_ip;
                    pkt->src_port = mapping->new_src_port;
                    mapping->packet_count++;
                    mapping->byte_count += pkt->len;
                    mapping->last_used = time(NULL);
                    modified = 1;
                }
            }
        } else { /* Inbound */
            if (rule->type == NAT_TYPE_DNAT || rule->type == NAT_TYPE_REDIRECT) {
                mapping = nat_find_mapping(ctx, pkt, 1);
                if (mapping) {
                    pkt->dst_ip = mapping->orig_dst_ip;
                    pkt->dst_port = mapping->orig_dst_port;
                    mapping->packet_count++;
                    mapping->byte_count += pkt->len;
                    mapping->last_used = time(NULL);
                    modified = 1;
                }
            }
        }
        
        rule = rule->next;
    }
    
    return modified;
}

void nat_cleanup_old(struct nat_ctx *ctx) {
    struct nat_mapping *mapping, *prev, *next;
    uint32_t i;
    time_t now = time(NULL);
    
    if (!ctx) return;
    
    for (i = 0; i < ctx->table->size; i++) {
        prev = NULL;
        mapping = ctx->table->buckets[i];
        
        while (mapping) {
            next = mapping->next;
            
            if (now - mapping->last_used > NAT_TIMEOUT) {
                if (prev) {
                    prev->next = next;
                } else {
                    ctx->table->buckets[i] = next;
                }
                
                free(mapping);
                ctx->table->count--;
                mapping = next;
                continue;
            }
            
            prev = mapping;
            mapping = next;
        }
    }
}
