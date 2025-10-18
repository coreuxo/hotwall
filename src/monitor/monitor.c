#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "monitor.h"
#include "../util/debug.h"

struct monitor_ctx *monitor_init(void) {
    struct monitor_ctx *ctx;
    int i;
    
    ctx = calloc(1, sizeof(struct monitor_ctx));
    if (!ctx) {
        ERROR("Failed to allocate monitor context\n");
        return NULL;
    }
    
    ctx->running = 0;
    ctx->metric_count = 0;
    
    if (pthread_mutex_init(&ctx->stats_lock, NULL) != 0) {
        ERROR("Failed to init stats lock\n");
        free(ctx);
        return NULL;
    }
    
    strcpy(ctx->stats_file, "/var/log/firewall/stats.log");
    
    ctx->log_fd = open("/var/log/firewall/monitor.log", O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (ctx->log_fd < 0) {
        DBG("Could not open monitor log file, using stderr\n");
        ctx->log_fd = STDERR_FILENO;
    }
    
    monitor_add_metric(ctx, "packets.total");
    monitor_add_metric(ctx, "packets.dropped");
    monitor_add_metric(ctx, "packets.accepted");
    monitor_add_metric(ctx, "bytes.total");
    monitor_add_metric(ctx, "connections.active");
    monitor_add_metric(ctx, "connections.total");
    monitor_add_metric(ctx, "rules.matched");
    monitor_add_metric(ctx, "ids.alerts");
    monitor_add_metric(ctx, "nat.translations");
    monitor_add_metric(ctx, "qos.drops");
    monitor_add_metric(ctx, "cpu.usage");
    monitor_add_metric(ctx, "memory.usage");
    monitor_add_metric(ctx, "queue.depth");
    
    DBG("Monitor initialized with %d metrics\n", ctx->metric_count);
    return ctx;
}

void monitor_cleanup(struct monitor_ctx *ctx) {
    int i;
    
    if (!ctx) return;
    
    monitor_stop(ctx);
    
    for (i = 0; i < ctx->metric_count; i++) {
        if (ctx->metrics[i]) {
            pthread_mutex_destroy(&ctx->metrics[i]->lock);
            free(ctx->metrics[i]);
        }
    }
    
    pthread_mutex_destroy(&ctx->stats_lock);
    
    if (ctx->log_fd != STDERR_FILENO && ctx->log_fd >= 0) {
        close(ctx->log_fd);
    }
    
    free(ctx);
    DBG("Monitor cleaned up\n");
}

int monitor_add_metric(struct monitor_ctx *ctx, const char *name) {
    struct metric *m;
    
    if (!ctx || !name || ctx->metric_count >= MONITOR_MAX_METRICS) {
        return -1;
    }
    
    m = calloc(1, sizeof(struct metric));
    if (!m) return -1;
    
    strncpy(m->name, name, sizeof(m->name) - 1);
    m->value = 0;
    m->last_update = time(NULL);
    m->history_pos = 0;
    
    if (pthread_mutex_init(&m->lock, NULL) != 0) {
        free(m);
        return -1;
    }
    
    ctx->metrics[ctx->metric_count++] = m;
    return 0;
}

int monitor_update_metric(struct monitor_ctx *ctx, const char *name, uint64_t value) {
    int i;
    
    if (!ctx || !name) return -1;
    
    for (i = 0; i < ctx->metric_count; i++) {
        if (strcmp(ctx->metrics[i]->name, name) == 0) {
            pthread_mutex_lock(&ctx->metrics[i]->lock);
            ctx->metrics[i]->value = value;
            ctx->metrics[i]->history[ctx->metrics[i]->history_pos] = value;
            ctx->metrics[i]->history_pos = (ctx->metrics[i]->history_pos + 1) % MONITOR_HISTORY_SIZE;
            ctx->metrics[i]->last_update = time(NULL);
            pthread_mutex_unlock(&ctx->metrics[i]->lock);
            return 0;
        }
    }
    
    return -1;
}

uint64_t monitor_get_metric(struct monitor_ctx *ctx, const char *name) {
    int i;
    uint64_t value = 0;
    
    if (!ctx || !name) return 0;
    
    for (i = 0; i < ctx->metric_count; i++) {
        if (strcmp(ctx->metrics[i]->name, name) == 0) {
            pthread_mutex_lock(&ctx->metrics[i]->lock);
            value = ctx->metrics[i]->value;
            pthread_mutex_unlock(&ctx->metrics[i]->lock);
            break;
        }
    }
    
    return value;
}

static void *monitor_thread_func(void *arg) {
    struct monitor_ctx *ctx = (struct monitor_ctx *)arg;
    time_t last_stats = 0;
    time_t last_alert_check = 0;
    
    DBG("Monitor thread started\n");
    
    while (ctx->running) {
        time_t now = time(NULL);
        
        if (now - last_stats >= MONITOR_STATS_INTERVAL) {
            monitor_write_stats(ctx);
            monitor_dump_stats(ctx);
            last_stats = now;
        }
        
        if (now - last_alert_check >= 10) {
            monitor_check_alerts(ctx);
            last_alert_check = now;
        }
        
        sleep(1);
    }
    
    DBG("Monitor thread stopped\n");
    return NULL;
}

int monitor_start(struct monitor_ctx *ctx) {
    int ret;
    
    if (!ctx || ctx->running) return -1;
    
    ctx->running = 1;
    
    ret = pthread_create(&ctx->thread, NULL, monitor_thread_func, ctx);
    if (ret != 0) {
        ctx->running = 0;
        ERROR("Failed to create monitor thread: %d\n", ret);
        return -1;
    }
    
    DBG("Monitor started\n");
    return 0;
}

void monitor_stop(struct monitor_ctx *ctx) {
    if (!ctx) return;
    
    ctx->running = 0;
    
    if (ctx->thread) {
        pthread_join(ctx->thread, NULL);
        ctx->thread = 0;
    }
    
    DBG("Monitor stopped\n");
}

void monitor_update_stats(struct monitor_ctx *ctx, struct monitor_stats *stats) {
    if (!ctx || !stats) return;
    
    pthread_mutex_lock(&ctx->stats_lock);
    memcpy(&ctx->stats, stats, sizeof(struct monitor_stats));
    ctx->stats.last_update = time(NULL);
    pthread_mutex_unlock(&ctx->stats_lock);
    
    monitor_update_metric(ctx, "packets.total", stats->packets_total);
    monitor_update_metric(ctx, "packets.dropped", stats->packets_dropped);
    monitor_update_metric(ctx, "packets.accepted", stats->packets_accepted);
    monitor_update_metric(ctx, "bytes.total", stats->bytes_total);
    monitor_update_metric(ctx, "connections.active", stats->connections_active);
    monitor_update_metric(ctx, "connections.total", stats->connections_total);
    monitor_update_metric(ctx, "rules.matched", stats->rules_matched);
    monitor_update_metric(ctx, "ids.alerts", stats->ids_alerts);
    monitor_update_metric(ctx, "nat.translations", stats->nat_translations);
    monitor_update_metric(ctx, "qos.drops", stats->qos_drops);
    monitor_update_metric(ctx, "cpu.usage", (uint64_t)(stats->cpu_usage * 100));
    monitor_update_metric(ctx, "memory.usage", (uint64_t)(stats->memory_usage * 100));
    monitor_update_metric(ctx, "queue.depth", stats->queue_depth);
}

void monitor_get_stats(struct monitor_ctx *ctx, struct monitor_stats *stats) {
    if (!ctx || !stats) return;
    
    pthread_mutex_lock(&ctx->stats_lock);
    memcpy(stats, &ctx->stats, sizeof(struct monitor_stats));
    pthread_mutex_unlock(&ctx->stats_lock);
}

void monitor_dump_stats(struct monitor_ctx *ctx) {
    struct monitor_stats stats;
    char time_buf[64];
    time_t now = time(NULL);
    struct tm *tm_info;
    
    monitor_get_stats(ctx, &stats);
    
    tm_info = localtime(&now);
    strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", tm_info);
    
    printf("\n=== Firewall Stats [%s] ===\n", time_buf);
    printf("Packets:  total=%lu dropped=%lu accepted=%lu\n", 
           stats.packets_total, stats.packets_dropped, stats.packets_accepted);
    printf("Bytes:    total=%lu\n", stats.bytes_total);
    printf("Connections: active=%lu total=%lu\n", 
           stats.connections_active, stats.connections_total);
    printf("Rules:    matched=%lu\n", stats.rules_matched);
    printf("IDS:      alerts=%lu\n", stats.ids_alerts);
    printf("NAT:      translations=%lu\n", stats.nat_translations);
    printf("QoS:      drops=%lu\n", stats.qos_drops);
    printf("System:   cpu=%.1f%% memory=%.1f%% queue=%lu\n",
           stats.cpu_usage, stats.memory_usage, stats.queue_depth);
    printf("================================\n");
}

int monitor_write_stats(struct monitor_ctx *ctx) {
    FILE *file;
    struct monitor_stats stats;
    char time_buf[64];
    time_t now = time(NULL);
    struct tm *tm_info;
    
    monitor_get_stats(ctx, &stats);
    
    file = fopen(ctx->stats_file, "a");
    if (!file) {
        DBG("Could not open stats file: %s\n", ctx->stats_file);
        return -1;
    }
    
    tm_info = localtime(&now);
    strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", tm_info);
    
    fprintf(file, "%s,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%.2f,%.2f,%lu\n",
            time_buf,
            stats.packets_total,
            stats.packets_dropped,
            stats.packets_accepted,
            stats.bytes_total,
            stats.connections_active,
            stats.connections_total,
            stats.rules_matched,
            stats.ids_alerts,
            stats.nat_translations,
            stats.qos_drops,
            stats.cpu_usage,
            stats.memory_usage,
            stats.queue_depth);
    
    fclose(file);
    return 0;
}

void monitor_check_alerts(struct monitor_ctx *ctx) {
    struct monitor_stats stats;
    static uint64_t last_packets = 0;
    static uint64_t last_drops = 0;
    static uint64_t last_alerts = 0;
    
    monitor_get_stats(ctx, &stats);
    
    if (last_packets > 0) {
        uint64_t packet_rate = (stats.packets_total - last_packets) / MONITOR_STATS_INTERVAL;
        uint64_t drop_rate = (stats.packets_dropped - last_drops) / MONITOR_STATS_INTERVAL;
        uint64_t alert_rate = (stats.ids_alerts - last_alerts) / MONITOR_STATS_INTERVAL;
        
        if (packet_rate > 10000) {
            monitor_alert(ctx, "HIGH_TRAFFIC", "High packet rate detected");
        }
        
        if (drop_rate > 1000) {
            monitor_alert(ctx, "HIGH_DROP_RATE", "High packet drop rate detected");
        }
        
        if (alert_rate > 100) {
            monitor_alert(ctx, "HIGH_ALERT_RATE", "High IDS alert rate detected");
        }
        
        if (stats.cpu_usage > 80.0) {
            monitor_alert(ctx, "HIGH_CPU", "High CPU usage detected");
        }
        
        if (stats.memory_usage > 90.0) {
            monitor_alert(ctx, "HIGH_MEMORY", "High memory usage detected");
        }
        
        if (stats.queue_depth > 10000) {
            monitor_alert(ctx, "HIGH_QUEUE", "High queue depth detected");
        }
    }
    
    last_packets = stats.packets_total;
    last_drops = stats.packets_dropped;
    last_alerts = stats.ids_alerts;
}

void monitor_alert(struct monitor_ctx *ctx, const char *type, const char *msg) {
    char time_buf[64];
    time_t now = time(NULL);
    struct tm *tm_info;
    char alert_buf[512];
    
    tm_info = localtime(&now);
    strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", tm_info);
    
    snprintf(alert_buf, sizeof(alert_buf), "[ALERT %s] %s: %s\n", time_buf, type, msg);
    
    write(ctx->log_fd, alert_buf, strlen(alert_buf));
    printf("%s", alert_buf);
}
