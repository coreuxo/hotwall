#ifndef LOG_H
#define LOG_H

#include <stdio.h>
#include <time.h>

#define LOG_LEVEL_DEBUG 0
#define LOG_LEVEL_INFO  1
#define LOG_LEVEL_WARN  2
#define LOG_LEVEL_ERROR 3

struct log_ctx {
    FILE *file;
    int level;
    char filename[256];
};

struct log_ctx *log_init(void);
void log_cleanup(struct log_ctx *ctx);
void log_msg(struct log_ctx *ctx, int level, const char *fmt, ...);
void log_packet(struct log_ctx *ctx, int level, struct packet_info *pkt, const char *action);

#endif
