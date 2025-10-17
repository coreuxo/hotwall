#ifndef RULES_H
#define RULES_H

#include <stdint.h>
#include <netinet/in.h>

#define MAX_RULES 1024
#define RULE_ACTION_ACCEPT 0
#define RULE_ACTION_DROP 1
#define RULE_ACTION_REJECT 2
#define RULE_ACTION_LOG 3

#define RULE_DIR_IN 0
#define RULE_DIR_OUT 1
#define RULE_DIR_FORWARD 2

#define PROTO_ANY 0
#define PROTO_TCP 6
#define PROTO_UDP 17
#define PROTO_ICMP 1

struct rule {
    uint32_t id;
    uint8_t action;
    uint8_t direction;
    uint8_t protocol;
    
    uint32_t src_ip;
    uint32_t src_mask;
    uint32_t dst_ip;
    uint32_t dst_mask;
    
    uint16_t src_port_start;
    uint16_t src_port_end;
    uint16_t dst_port_start;
    uint16_t dst_port_end;
    
    uint8_t enabled:1;
    uint8_t log:1;
    uint8_t permanent:1;
    
    uint64_t packet_count;
    uint64_t byte_count;
    
    struct rule *next;
};

struct rule_chain {
    char name[32];
    struct rule *head;
    uint32_t rule_count;
    uint64_t default_policy;
};

struct ruleset {
    struct rule_chain input;
    struct rule_chain output;
    struct rule_chain forward;
    uint32_t next_rule_id;
};

void ruleset_init(struct ruleset *rs);
int rule_add(struct rule_chain *chain, struct rule *rule);
int rule_delete(struct rule_chain *chain, uint32_t rule_id);
struct rule *rule_find(struct rule_chain *chain, uint32_t rule_id);
void rule_chain_clear(struct rule_chain *chain);
int rule_match(struct rule *rule, struct packet_info *pkt);

#endif
