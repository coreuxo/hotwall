#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include "log.h"
#include "../capture/packet.h"

struct log_ctx *log_init(void) {
    struct log_ctx *ctx;
    
    ctx = malloc(sizeof(struct log_ctx));
    if (!ctx) {
        return NULL;
    }
    
    memset(ctx, 0, sizeof(struct log_ctx));
    
    strcpy(ctx->filename, "/var/log/firewall.log");
    ctx->level = LOG_LEVEL_INFO;
    
    ctx->file = fopen(ctx->filename, "a");
    if (!ctx->file) {
        /* Fall back to stderr */
        ctx->file = stderr;
    }
    
    return ctx;
}

void log_cleanup(struct log_ctx *ctx) {
    if (ctx) {
        if (ctx->file && ctx->file != stderr) {
            fclose(ctx->file);
        }
        free(ctx);
    }
}

void log_msg(struct log_ctx *ctx, int level, const char *fmt, ...) {
    va_list args;
    time_t now;
    struct tm *tm_info;
    char timestamp[64];
    const char *level_str;
    
    if (!ctx || level < ctx->level) {
        return;
    }
    
    now = time(NULL);
    tm_info = localtime(&now);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);
    
    switch (level) {
        case LOG_LEVEL_DEBUG: level_str = "DEBUG"; break;
        case LOG_LEVEL_INFO:  level_str = "INFO"; break;
        case LOG_LEVEL_WARN:  level_str = "WARN"; break;
        case LOG_LEVEL_ERROR: level_str = "ERROR"; break;
        default: level_str = "UNKNOWN"; break;
    }
    
    fprintf(ctx->file, "[%s] [%s] ", timestamp, level_str);
    
    va_start(args, fmt);
    vfprintf(ctx->file, fmt, args);
    va_end(args);
    
    fprintf(ctx->file, "\n");
    fflush(ctx->file);
}

void log_packet(struct log_ctx *ctx, int level, struct packet_info *pkt, const char *action) {
    char src_ip[16], dst_ip[16];
    
    if (!ctx || !pkt || level < ctx->level) {
        return;
    }
    
    inet_ntop(AF_INET, &pkt->src_ip, src_ip, sizeof(src_ip));
    inet_ntop(AF_INET, &pkt->dst_ip, dst_ip, sizeof(dst_ip));
    
    log_msg(ctx, level, "PACKET %s %s:%d -> %s:%d proto=%s len=%d action=%s",
            protocol_str(pkt->protocol),
            src_ip, pkt->src_port,
            dst_ip, pkt->dst_port,
            protocol_str(pkt->protocol),
            pkt->len, action);
}
