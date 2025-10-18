#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <arpa/inet.h>
#include <ctype.h>
#include "parser.h"

struct parser_ctx *parser_init(const char *filename) {
    struct parser_ctx *ctx;
    
    ctx = calloc(1, sizeof(struct parser_ctx));
    if (!ctx) return NULL;
    
    ctx->filename = strdup(filename);
    if (!ctx->filename) {
        free(ctx);
        return NULL;
    }
    
    ctx->file = fopen(filename, "r");
    if (!ctx->file) {
        free(ctx->filename);
        free(ctx);
        return NULL;
    }
    
    ctx->line_num = 0;
    ctx->errors = 0;
    
    return ctx;
}

void parser_cleanup(struct parser_ctx *ctx) {
    if (ctx) {
        if (ctx->file) fclose(ctx->file);
        if (ctx->filename) free(ctx->filename);
        free(ctx);
    }
}

void parser_error(struct parser_ctx *ctx, const char *fmt, ...) {
    va_list args;
    
    fprintf(stderr, "Config error %s:%d: ", ctx->filename, ctx->line_num);
    
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    
    fprintf(stderr, "\n");
    ctx->errors++;
}

int parser_parse_ip(const char *str, uint32_t *ip, uint32_t *mask) {
    char buf[64];
    char *slash;
    int prefix = 32;
    
    strncpy(buf, str, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    
    slash = strchr(buf, '/');
    if (slash) {
        *slash = '\0';
        prefix = atoi(slash + 1);
        if (prefix < 0 || prefix > 32) return -1;
    }
    
    if (strcmp(buf, "any") == 0 || strcmp(buf, "0.0.0.0") == 0) {
        *ip = 0;
        *mask = 0;
        return 0;
    }
    
    if (inet_pton(AF_INET, buf, ip) != 1) return -1;
    
    if (prefix == 32) {
        *mask = 0xFFFFFFFF;
    } else if (prefix == 0) {
        *mask = 0;
    } else {
        *mask = htonl(~((1 << (32 - prefix)) - 1));
    }
    
    return 0;
}

int parser_parse_port(const char *str, uint16_t *start, uint16_t *end) {
    char *dash;
    
    if (strcmp(str, "any") == 0 || strcmp(str, "*") == 0) {
        *start = 0;
        *end = 0;
        return 0;
    }
    
    dash = strchr(str, ':');
    if (dash) {
        *dash = '\0';
        *start = atoi(str);
        *end = atoi(dash + 1);
    } else {
        *start = atoi(str);
        *end = *start;
    }
    
    if (*start > 65535 || *end > 65535 || *start > *end) return -1;
    return 0;
}

uint8_t parser_parse_proto(const char *str) {
    if (strcmp(str, "tcp") == 0) return 6;
    if (strcmp(str, "udp") == 0) return 17;
    if (strcmp(str, "icmp") == 0) return 1;
    if (strcmp(str, "any") == 0 || strcmp(str, "*") == 0) return 0;
    return (uint8_t)atoi(str);
}

int parser_parse_rule(struct parser_ctx *ctx, char *line, struct filter_ctx *filter) {
    char *token, *saveptr;
    struct rule r;
    uint8_t chain;
    
    memset(&r, 0, sizeof(r));
    
    token = strtok_r(line, " \t", &saveptr);
    if (!token) return -1;
    
    if (strcmp(token, "INPUT") == 0) {
        chain = 0;
    } else if (strcmp(token, "OUTPUT") == 0) {
        chain = 1;
    } else if (strcmp(token, "FORWARD") == 0) {
        chain = 2;
    } else {
        parser_error(ctx, "invalid chain: %s", token);
        return -1;
    }
    
    token = strtok_r(NULL, " \t", &saveptr);
    if (!token) {
        parser_error(ctx, "missing action");
        return -1;
    }
    
    if (strcmp(token, "ACCEPT") == 0) {
        r.action = 0;
    } else if (strcmp(token, "DROP") == 0) {
        r.action = 1;
    } else if (strcmp(token, "REJECT") == 0) {
        r.action = 2;
    } else if (strcmp(token, "LOG") == 0) {
        r.action = 3;
    } else {
        parser_error(ctx, "invalid action: %s", token);
        return -1;
    }
    
    r.direction = chain;
    r.enabled = 1;
    
    while ((token = strtok_r(NULL, " \t", &saveptr)) != NULL) {
        if (strncmp(token, "--proto", 7) == 0 || strncmp(token, "-p", 2) == 0) {
            token = strtok_r(NULL, " \t", &saveptr);
            if (!token) {
                parser_error(ctx, "missing protocol");
                return -1;
            }
            r.protocol = parser_parse_proto(token);
        } else if (strncmp(token, "--source", 8) == 0 || strncmp(token, "-s", 2) == 0) {
            token = strtok_r(NULL, " \t", &saveptr);
            if (!token) {
                parser_error(ctx, "missing source IP");
                return -1;
            }
            if (parser_parse_ip(token, &r.src_ip, &r.src_mask) != 0) {
                parser_error(ctx, "invalid source IP: %s", token);
                return -1;
            }
        } else if (strncmp(token, "--dest", 6) == 0 || strncmp(token, "-d", 2) == 0) {
            token = strtok_r(NULL, " \t", &saveptr);
            if (!token) {
                parser_error(ctx, "missing destination IP");
                return -1;
            }
            if (parser_parse_ip(token, &r.dst_ip, &r.dst_mask) != 0) {
                parser_error(ctx, "invalid destination IP: %s", token);
                return -1;
            }
        } else if (strncmp(token, "--sport", 7) == 0) {
            token = strtok_r(NULL, " \t", &saveptr);
            if (!token) {
                parser_error(ctx, "missing source port");
                return -1;
            }
            if (parser_parse_port(token, &r.src_port_start, &r.src_port_end) != 0) {
                parser_error(ctx, "invalid source port: %s", token);
                return -1;
            }
        } else if (strncmp(token, "--dport", 7) == 0) {
            token = strtok_r(NULL, " \t", &saveptr);
            if (!token) {
                parser_error(ctx, "missing destination port");
                return -1;
            }
            if (parser_parse_port(token, &r.dst_port_start, &r.dst_port_end) != 0) {
                parser_error(ctx, "invalid destination port: %s", token);
                return -1;
            }
        } else if (strcmp(token, "--log") == 0) {
            r.log = 1;
        }
    }
    
    if (filter_add_rule(filter, chain, &r) != 0) {
        parser_error(ctx, "failed to add rule");
        return -1;
    }
    
    return 0;
}

int parser_parse_nat(struct parser_ctx *ctx, char *line, struct nat_ctx *nat) {
    printf("NAT config parsing not implemented\n");
    return 0;
}

int parser_parse_ids(struct parser_ctx *ctx, char *line, struct ids_ctx *ids) {
    printf("IDS config parsing not implemented\n");
    return 0;
}

int parser_parse_qos(struct parser_ctx *ctx, char *line, struct qos_ctx *qos) {
    printf("QoS config parsing not implemented\n");
    return 0;
}

int parser_parse(struct parser_ctx *ctx, struct filter_ctx *filter, 
                struct nat_ctx *nat, struct ids_ctx *ids, struct qos_ctx *qos) {
    char line[1024];
    char *trimmed, *comment;
    
    if (!ctx || !ctx->file) return -1;
    
    while (fgets(line, sizeof(line), ctx->file)) {
        ctx->line_num++;
        
        trimmed = line;
        while (*trimmed && isspace(*trimmed)) trimmed++;
        
        if (*trimmed == '#' || *trimmed == '\0' || *trimmed == '\n') continue;
        
        comment = strchr(trimmed, '#');
        if (comment) *comment = '\0';
        
        char *end = trimmed + strlen(trimmed) - 1;
        while (end > trimmed && isspace(*end)) *end-- = '\0';
        
        if (strncmp(trimmed, "INPUT", 5) == 0 || 
            strncmp(trimmed, "OUTPUT", 6) == 0 || 
            strncmp(trimmed, "FORWARD", 7) == 0) {
            parser_parse_rule(ctx, trimmed, filter);
        } else if (strncmp(trimmed, "SNAT", 4) == 0 || 
                  strncmp(trimmed, "DNAT", 4) == 0 || 
                  strncmp(trimmed, "MASQUERADE", 10) == 0) {
            parser_parse_nat(ctx, trimmed, nat);
        } else if (strncmp(trimmed, "IDS", 3) == 0) {
            parser_parse_ids(ctx, trimmed, ids);
        } else if (strncmp(trimmed, "QOS", 3) == 0) {
            parser_parse_qos(ctx, trimmed, qos);
        } else {
            parser_error(ctx, "unknown command: %s", trimmed);
        }
    }
    
    return ctx->errors;
}
