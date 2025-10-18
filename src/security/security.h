#ifndef SECURITY_H
#define SECURITY_H

#include <stdint.h>
#include <pthread.h>

#define SECURITY_MAX_BLACKLIST 100000
#define SECURITY_MAX_WHITELIST 10000
#define SECURITY_RATE_LIMIT_WINDOW 60
#define SECURITY_MAX_RATE_RULES 1000

struct security_ip_entry {
    uint32_t ip;
    time_t expires;
    uint32_t hit_count;
    struct security_ip_entry *next;
};

struct security_rate_rule {
    uint32_t id;
    uint32_t ip;
    uint32_t mask;
    uint16_t port;
    uint8_t protocol;
    uint32_t rate_limit;
    uint32_t current_count;
    time_t window_start;
    uint8_t enabled;
    struct security_rate_rule *next;
};

struct security_ctx {
    struct security_ip_entry *blacklist;
    struct security_ip_entry *whitelist;
    struct security_rate_rule *rate_rules;
    pthread_mutex_t blacklist_lock;
    pthread_mutex_t whitelist_lock;
    pthread_mutex_t rate_lock;
    uint32_t next_rule_id;
    uint64_t total_blocks;
    uint64_t total_rate_limits;
    uint8_t enabled;
};

struct security_ctx *security_init(void);
void security_cleanup(struct security_ctx *ctx);
int security_add_blacklist(struct security_ctx *ctx, uint32_t ip, time_t duration);
int security_remove_blacklist(struct security_ctx *ctx, uint32_t ip);
int security_add_whitelist(struct security_ctx *ctx, uint32_t ip);
int security_remove_whitelist(struct security_ctx *ctx, uint32_t ip);
int security_check_ip(struct security_ctx *ctx, uint32_t ip);
int security_add_rate_rule(struct security_ctx *ctx, uint32_t ip, uint32_t mask, 
                          uint16_t port, uint8_t protocol, uint32_t rate_limit);
int security_check_rate_limit(struct security_ctx *ctx, uint32_t ip, uint16_t port, uint8_t protocol);
void security_cleanup_expired(struct security_ctx *ctx);
void security_dump_stats(struct security_ctx *ctx);

#endif
