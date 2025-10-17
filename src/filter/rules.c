#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include "rules.h"
#include "../capture/packet.h"

void ruleset_init(struct ruleset *rs) {
    memset(rs, 0, sizeof(struct ruleset));
    
    strcpy(rs->input.name, "INPUT");
    strcpy(rs->output.name, "OUTPUT");
    strcpy(rs->forward.name, "FORWARD");
    
    rs->next_rule_id = 1;
}

int rule_add(struct rule_chain *chain, struct rule *rule) {
    struct rule *new_rule, *current;
    
    if (!chain || !rule) {
        return -1;
    }
    
    new_rule = malloc(sizeof(struct rule));
    if (!new_rule) {
        return -1;
    }
    
    memcpy(new_rule, rule, sizeof(struct rule));
    new_rule->next = NULL;
    
    if (!chain->head) {
        chain->head = new_rule;
    } else {
        current = chain->head;
        while (current->next) {
            current = current->next;
        }
        current->next = new_rule;
    }
    
    chain->rule_count++;
    return 0;
}

int rule_delete(struct rule_chain *chain, uint32_t rule_id) {
    struct rule *current, *prev = NULL;
    
    if (!chain) {
        return -1;
    }
    
    current = chain->head;
    while (current) {
        if (current->id == rule_id) {
            if (prev) {
                prev->next = current->next;
            } else {
                chain->head = current->next;
            }
            free(current);
            chain->rule_count--;
            return 0;
        }
        prev = current;
        current = current->next;
    }
    
    return -1;
}

struct rule *rule_find(struct rule_chain *chain, uint32_t rule_id) {
    struct rule *current;
    
    if (!chain) {
        return NULL;
    }
    
    current = chain->head;
    while (current) {
        if (current->id == rule_id) {
            return current;
        }
        current = current->next;
    }
    
    return NULL;
}

void rule_chain_clear(struct rule_chain *chain) {
    struct rule *current, *next;
    
    if (!chain) {
        return;
    }
    
    current = chain->head;
    while (current) {
        next = current->next;
        free(current);
        current = next;
    }
    
    chain->head = NULL;
    chain->rule_count = 0;
}

int rule_match(struct rule *rule, struct packet_info *pkt) {
    if (!rule || !pkt || !rule->enabled) {
        return 0;
    }
    
    /* check protocol */
    if (rule->protocol != PROTO_ANY && rule->protocol != pkt->protocol) {
        return 0;
    }
    
    /* check source IP */
    if (rule->src_mask != 0) {
        uint32_t src_net = pkt->src_ip & rule->src_mask;
        if (src_net != (rule->src_ip & rule->src_mask)) {
            return 0;
        }
    }
    
    /* check destination IP */
    if (rule->dst_mask != 0) {
        uint32_t dst_net = pkt->dst_ip & rule->dst_mask;
        if (dst_net != (rule->dst_ip & rule->dst_mask)) {
            return 0;
        }
    }
    
    /* check source port */
    if (rule->src_port_start > 0) {
        if (pkt->src_port < rule->src_port_start || pkt->src_port > rule->src_port_end) {
            return 0;
        }
    }
    
    /* check destination port */
    if (rule->dst_port_start > 0) {
        if (pkt->dst_port < rule->dst_port_start || pkt->dst_port > rule->dst_port_end) {
            return 0;
        }
    }
    
    return 1;
}
