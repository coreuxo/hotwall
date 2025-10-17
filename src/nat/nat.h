#ifndef NAT_H
#define NAT_H

#include <stdint.h>
#include <netinet/in.h>
#include "../state/conn_track.h"

#define NAT_TABLE_SIZE 16384
#define NAT_PORT_START 49152
#define NAT_PORT_END 65535
#define NAT_TIMEOUT 3600

typedef enum {
    NAT_TYPE_NONE = 0,
    NAT_TYPE_SNAT,
    NAT_TYPE_DNAT,
    NAT_TYPE_MASQUERADE,
    NAT_TYPE_REDIRECT
} nat_type_t;

struct nat_mapping {
    uint32_t orig_src_ip;
    uint32_t orig_dst_ip;
    uint16_t orig_src_port;
    uint16_t orig_dst_port;
    uint8_t protocol;
    
    uint32_t new_src_ip;
    uint32_t new_dst_ip;
    uint16_t new_src_port;
    uint16_t new_dst_port;
    
    time_t last_used;
    uint64_t packet_count;
    uint64_t byte_count;
    
    struct nat_mapping *next;
};

struct nat_rule {
    uint32_t id;
    nat_type_t type;
    uint32_t src_ip;
    uint32_t src_mask;
    uint32_t dst_ip;
    uint32_t dst_mask;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
    
    uint32_t nat_ip;
    uint16_t nat_port;
    uint8_t enabled;
    
    struct nat_rule *next;
};

struct nat_table {
    struct nat_mapping **buckets;
    uint32_t size;
    uint32_t count;
    uint16_t next_port;
};

struct nat_ctx {
    struct nat_table *table;
    struct nat_rule *rules;
    uint32_t next_rule_id;
    uint32_t external_ip;
};

struct nat_ctx *nat_init(uint32_t external_ip);
void nat_cleanup(struct nat_ctx *ctx);
int nat_add_rule(struct nat_ctx *ctx, nat_type_t type, uint32_t src_ip, uint32_t src_mask,
                uint32_t dst_ip, uint32_t dst_mask, uint16_t src_port, uint16_t dst_port,
                uint8_t protocol, uint32_t nat_ip, uint16_t nat_port);
int nat_delete_rule(struct nat_ctx *ctx, uint32_t rule_id);
int nat_process_packet(struct nat_ctx *ctx, struct packet_info *pkt, int direction);
int nat_create_mapping(struct nat_ctx *ctx, struct packet_info *pkt, nat_type_t type,
                      uint32_t new_ip, uint16_t new_port);
struct nat_mapping *nat_find_mapping(struct nat_ctx *ctx, struct packet_info *pkt, int reverse);
void nat_cleanup_old(struct nat_ctx *ctx);
uint16_t nat_alloc_port(struct nat_ctx *ctx);

#endif
