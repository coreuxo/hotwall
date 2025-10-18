#ifndef CONFIG_H
#define CONFIG_H

#include <stdio.h>
#include <stdint.h>
#include "../filter/rules.h"
#include "../nat/nat.h"

#define MAX_CONFIG_LINE 1024
#define MAX_CONFIG_FILES 16

struct config_ctx {
    char *filename;
    FILE *file;
    int line_num;
    int error_count;
};

struct config_ctx *config_init(const char *filename);
void config_cleanup(struct config_ctx *ctx);
int config_parse(struct config_ctx *ctx, struct filter_ctx *filter, struct nat_ctx *nat);
int config_parse_rule(struct config_ctx *ctx, char *line, struct filter_ctx *filter);
int config_parse_nat_rule(struct config_ctx *ctx, char *line, struct nat_ctx *nat);
int config_validate_ip(const char *ip_str, uint32_t *ip, uint32_t *mask);
int config_validate_port(const char *port_str, uint16_t *port_start, uint16_t *port_end);
uint8_t config_parse_protocol(const char *proto_str);
void config_log_error(struct config_ctx *ctx, const char *fmt, ...);

#endif
