#ifndef PARSER_H
#define PARSER_H

#include <stdio.h>
#include "../filter/filter.h"
#include "../nat/nat.h"
#include "../ids/ids.h"
#include "../qos/qos.h"

struct parser_ctx {
    char *filename;
    FILE *file;
    int line_num;
    int errors;
};

struct parser_ctx *parser_init(const char *filename);
void parser_cleanup(struct parser_ctx *ctx);
int parser_parse(struct parser_ctx *ctx, struct filter_ctx *filter, 
                struct nat_ctx *nat, struct ids_ctx *ids, struct qos_ctx *qos);
int parser_parse_rule(struct parser_ctx *ctx, char *line, struct filter_ctx *filter);
int parser_parse_nat(struct parser_ctx *ctx, char *line, struct nat_ctx *nat);
int parser_parse_ids(struct parser_ctx *ctx, char *line, struct ids_ctx *ids);
int parser_parse_qos(struct parser_ctx *ctx, char *line, struct qos_ctx *qos);
void parser_error(struct parser_ctx *ctx, const char *fmt, ...);
int parser_parse_ip(const char *str, uint32_t *ip, uint32_t *mask);
int parser_parse_port(const char *str, uint16_t *start, uint16_t *end);
uint8_t parser_parse_proto(const char *str);

#endif
