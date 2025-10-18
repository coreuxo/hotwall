#ifndef MONITOR_H
#define MONITOR_H

#include <stdint.h>
#include <pthread.h>
#include <time.h>

#define MONITOR_STATS_INTERVAL 5
#define MONITOR_MAX_METRICS 50
#define MONITOR_HISTORY_SIZE 3600

struct metric {
    char name[32];
    uint64_t value;
    uint64_t history[MONITOR_HISTORY_SIZE];
    time_t last_update;
    uint32_t history_pos;
    pthread_mutex_t lock;
};

struct monitor_stats {
    uint64_t packets_total;
    uint64_t packets_dropped;
    uint64_t packets_accepted;
    uint64_t bytes_total;
    uint64_t connections_active;
    uint64_t connections_total;
    uint64_t rules_matched;
    uint64_t ids_alerts;
    uint64_t nat_translations;
    uint64_t qos_drops;
    double cpu_usage;
    double memory_usage;
    uint64_t queue_depth;
    time_t last_update;
};

struct monitor_ctx {
    struct metric *metrics[MONITOR_MAX_METRICS];
    pthread_t thread;
    volatile int running;
    uint32_t metric_count;
    struct monitor_stats stats;
    pthread_mutex_t stats_lock;
    char stats_file[256];
    int log_fd;
};

struct monitor_ctx *monitor_init(void);
void monitor_cleanup(struct monitor_ctx *ctx);
int monitor_start(struct monitor_ctx *ctx);
void monitor_stop(struct monitor_ctx *ctx);
int monitor_add_metric(struct monitor_ctx *ctx, const char *name);
int monitor_update_metric(struct monitor_ctx *ctx, const char *name, uint64_t value);
uint64_t monitor_get_metric(struct monitor_ctx *ctx, const char *name);
void monitor_update_stats(struct monitor_ctx *ctx, struct monitor_stats *stats);
void monitor_get_stats(struct monitor_ctx *ctx, struct monitor_stats *stats);
void monitor_dump_stats(struct monitor_ctx *ctx);
int monitor_write_stats(struct monitor_ctx *ctx);
void monitor_alert(struct monitor_ctx *ctx, const char *type, const char *msg);

#endif
