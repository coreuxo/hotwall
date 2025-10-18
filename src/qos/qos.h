#ifndef QOS_H
#define QOS_H

#include <stdint.h>
#include <pthread.h>
#include "../capture/packet.h"

#define QOS_MAX_CLASSES 16
#define QOS_MAX_RULES 1000
#define QOS_TOKEN_BUCKET_SIZE 1000
#define QOS_TOKEN_RATE 100

typedef enum {
    QOS_CLASS_BEST_EFFORT = 0,
    QOS_CLASS_BACKGROUND,
    QOS_CLASS_STANDARD,
    QOS_CLASS_VIDEO,
    QOS_CLASS_VOICE,
    QOS_CLASS_CONTROL
} qos_class_t;

typedef enum {
    QOS_ACTION_PASS = 0,
    QOS_ACTION_DROP,
    QOS_ACTION_SHAPE,
    QOS_ACTION_MARK
} qos_action_t;

struct qos_token_bucket {
    uint32_t tokens;
    uint32_t rate;
    uint32_t burst;
    time_t last_update;
    pthread_mutex_t lock;
};

struct qos_class {
    qos_class_t class_id;
    char name[32];
    uint32_t bandwidth;
    uint32_t priority;
    uint32_t packet_count;
    uint64_t byte_count;
    struct qos_token_bucket bucket;
};

struct qos_rule {
    uint32_t id;
    uint32_t src_ip;
    uint32_t src_mask;
    uint32_t dst_ip;
    uint32_t dst_mask;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
    qos_class_t class_id;
    qos_action_t action;
    uint32_t rate_limit;
    uint8_t enabled;
    struct qos_rule *next;
};

struct qos_ctx {
    struct qos_class classes[QOS_MAX_CLASSES];
    struct qos_rule *rules;
    pthread_mutex_t rule_lock;
    uint32_t next_rule_id;
    uint32_t class_count;
    uint64_t total_packets;
    uint64_t total_drops;
    uint8_t enabled;
};

struct qos_ctx *qos_init(void);
void qos_cleanup(struct qos_ctx *ctx);
int qos_add_rule(struct qos_ctx *ctx, uint32_t src_ip, uint32_t src_mask,
                uint32_t dst_ip, uint32_t dst_mask, uint16_t src_port,
                uint16_t dst_port, uint8_t protocol, qos_class_t class_id,
                qos_action_t action, uint32_t rate_limit);
int qos_delete_rule(struct qos_ctx *ctx, uint32_t rule_id);
int qos_process_packet(struct qos_ctx *ctx, struct packet_info *pkt);
int qos_token_bucket_consume(struct qos_token_bucket *bucket, uint32_t tokens);
void qos_update_buckets(struct qos_ctx *ctx);
void qos_dump_stats(struct qos_ctx *ctx);

#endif
