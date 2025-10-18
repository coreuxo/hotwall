#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <arpa/inet.h>
#include <ctype.h>
#include "config.h"

struct config_ctx *config_init(const char *filename) {
    struct config_ctx *ctx;
    
    ctx = malloc(sizeof(struct config_ctx));
    if (!ctx) {
        return NULL;
    }
    
    memset(ctx, 0, sizeof(struct config_ctx));
    
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
    ctx->error_count = 0;
    
    return ctx;
}

void config_cleanup(struct config_ctx *ctx) {
    if (ctx) {
        if (ctx->file) {
            fclose(ctx->file);
        }
        if (ctx->filename) {
            free(ctx->filename);
        }
        free(ctx);
    }
}

void config_log_error(struct config_ctx *ctx, const char *fmt, ...) {
    va_list args;
    
    fprintf(stderr, "Config error at %s:%d: ", ctx->filename, ctx->line_num);
    
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    
    fprintf(stderr, "\n");
    ctx->error_count++;
}

int config_validate_ip(const char *ip_str, uint32_t *ip, uint32_t *mask) {
    char *slash, *ip_copy;
    char ip_buf[64];
    int prefix_len = 32;
    
    strncpy(ip_buf, ip_str, sizeof(ip_buf) - 1);
    ip_buf[sizeof(ip_buf) - 1] = '\0';
    
    slash = strchr(ip_buf, '/');
    if (slash) {
        *slash = '\0';
        prefix_len = atoi(slash + 1);
        if (prefix_len < 0 || prefix_len > 32) {
            return -1;
        }
    }
    
    if (strcmp(ip_buf, "any") == 0 || strcmp(ip_buf, "0.0.0.0") == 0) {
        *ip = 0;
        *mask = 0;
        return 0;
    }
    
    if (inet_pton(AF_INET, ip_buf, ip) != 1) {
        return -1;
    }
    
    if (prefix_len == 32) {
        *mask = 0xFFFFFFFF;
    } else if (prefix_len == 0) {
        *mask = 0;
    } else {
        *mask = htonl(~((1 << (32 - prefix_len)) - 1));
    }
    
    return 0;
}

int config_validate_port(const char *port_str, uint16_t *port_start, uint16_t *port_end) {
    char *dash;
    char port_buf[32];
    
    strncpy(port_buf, port_str, sizeof(port_buf) - 1);
    port_buf[sizeof(port_buf) - 1] = '\0';
    
    if (strcmp(port_buf, "any") == 0 || strcmp(port_buf, "*") == 0) {
        *port_start = 0;
        *port_end = 0;
        return 0;
    }
    
    dash = strchr(port_buf, ':');
    if (dash) {
        *dash = '\0';
        *port_start = atoi(port_buf);
        *port_end = atoi(dash + 1);
    } else {
        *port_start = atoi(port_buf);
        *port_end = *port_start;
    }
    
    if (*port_start > 65535 || *port_end > 65535 || *port_start > *port_end) {
        return -1;
    }
    
    return 0;
}

uint8_t config_parse_protocol(const char *proto_str) {
    if (strcmp(proto_str, "tcp") == 0) return 6;
    if (strcmp(proto_str, "udp") == 0) return 17;
    if (strcmp(proto_str, "icmp") == 0) return 1;
    if (strcmp(proto_str, "any") == 0 || strcmp(proto_str, "*") == 0) return 0;
    return (uint8_t)atoi(proto_str);
}

int config_parse_rule(struct config_ctx *ctx, char *line, struct filter_ctx *filter) {
    char *token, *saveptr;
    struct rule r;
    uint8_t chain = 0;
    char action_str[32], chain_str[32], proto_str[32];
    char src_ip_str[64], dst_ip_str[64], src_port_str[32], dst_port_str[32];
    
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
        config_log_error(ctx, "Invalid chain: %s", token);
        return -1;
    }
    
    token = strtok_r(NULL, " \t", &saveptr);
    if (!token) {
        config_log_error(ctx, "Missing action");
        return -1;
    }
    
    strncpy(action_str, token, sizeof(action_str) - 1);
    
    if (strcmp(action_str, "ACCEPT") == 0) {
        r.action = RULE_ACTION_ACCEPT;
    } else if (strcmp(action_str, "DROP") == 0) {
        r.action = RULE_ACTION_DROP;
    } else if (strcmp(action_str, "REJECT") == 0) {
        r.action = RULE_ACTION_REJECT;
    } else if (strcmp(action_str, "LOG") == 0) {
        r.action = RULE_ACTION_LOG;
    } else {
        config_log_error(ctx, "Invalid action: %s", action_str);
        return -1;
    }
    
    r.direction = chain;
    r.enabled = 1;
    
    while ((token = strtok_r(NULL, " \t", &saveptr)) != NULL) {
        if (strncmp(token, "--proto", 7) == 0 || strncmp(token, "-p", 2) == 0) {
            token = strtok_r(NULL, " \t", &saveptr);
            if (!token) {
                config_log_error(ctx, "Missing protocol");
                return -1;
            }
            r.protocol = config_parse_protocol(token);
        } else if (strncmp(token, "--source", 8) == 0 || strncmp(token, "-s", 2) == 0) {
            token = strtok_r(NULL, " \t", &saveptr);
            if (!token) {
                config_log_error(ctx, "Missing source IP");
                return -1;
            }
            if (config_validate_ip(token, &r.src_ip, &r.src_mask) != 0) {
                config_log_error(ctx, "Invalid source IP: %s", token);
                return -1;
            }
        } else if (strncmp(token, "--destination", 13) == 0 || strncmp(token, "-d", 2) == 0) {
            token = strtok_r(NULL, " \t", &saveptr);
            if (!token) {
                config_log_error(ctx, "Missing destination IP");
                return -1;
            }
            if (config_validate_ip(token, &r.dst_ip, &r.dst_mask) != 0) {
                config_log_error(ctx, "Invalid destination IP: %s", token);
                return -1;
            }
        } else if (strncmp(token, "--sport", 7) == 0) {
            token = strtok_r(NULL, " \t", &saveptr);
            if (!token) {
                config_log_error(ctx, "Missing source port");
                return -1;
            }
            if (config_validate_port(token, &r.src_port_start, &r.src_port_end) != 0) {
                config_log_error(ctx, "Invalid source port: %s", token);
                return -1;
            }
        } else if (strncmp(token, "--dport", 7) == 0) {
            token = strtok_r(NULL, " \t", &saveptr);
            if (!token) {
                config_log_error(ctx, "Missing destination port");
                return -1;
            }
            if (config_validate_port(token, &r.dst_port_start, &r.dst_port_end) != 0) {
                config_log_error(ctx, "Invalid destination port: %s", token);
                return -1;
            }
        } else if (strcmp(token, "--log") == 0) {
            r.log = 1;
        }
    }
    
    if (filter_add_rule(filter, chain, &r) != 0) {
        config_log_error(ctx, "Failed to add rule");
        return -1;
    }
    
    return 0;
}

int config_parse_nat_rule(struct config_ctx *ctx, char *line, struct nat_ctx *nat) {
    char *token, *saveptr;
    uint8_t type = 0;
    uint32_t src_ip = 0, src_mask = 0, dst_ip = 0, dst_mask = 0, nat_ip = 0;
    uint16_t src_port = 0, dst_port = 0, nat_port = 0;
    uint8_t protocol = 0;
    
    token = strtok_r(line, " \t", &saveptr);
    if (!token) return -1;
    
    if (strcmp(token, "SNAT") == 0) {
        type = NAT_TYPE_SNAT;
    } else if (strcmp(token, "DNAT") == 0) {
        type = NAT_TYPE_DNAT;
    } else if (strcmp(token, "MASQUERADE") == 0) {
        type = NAT_TYPE_MASQUERADE;
    } else if (strcmp(token, "REDIRECT") == 0) {
        type = NAT_TYPE_REDIRECT;
    } else {
        config_log_error(ctx, "Invalid NAT type: %s", token);
        return -1;
    }
    
    while ((token = strtok_r(NULL, " \t", &saveptr)) != NULL) {
        if (strncmp(token, "--proto", 7) == 0 || strncmp(token, "-p", 2) == 0) {
            token = strtok_r(NULL, " \t", &saveptr);
            if (!token) {
                config_log_error(ctx, "Missing protocol");
                return -1;
            }
            protocol = config_parse_protocol(token);
        } else if (strncmp(token, "--source", 8) == 0 || strncmp(token, "-s", 2) == 0) {
            token = strtok_r(NULL, " \t", &saveptr);
            if (!token) {
                config_log_error(ctx, "Missing source IP");
                return -1;
            }
            if (config_validate_ip(token, &src_ip, &src_mask) != 0) {
                config_log_error(ctx, "Invalid source IP: %s", token);
                return -1;
            }
        } else if (strncmp(token, "--destination", 13) == 0 || strncmp(token, "-d", 2) == 0) {
            token = strtok_r(NULL, " \t", &saveptr);
            if (!token) {
                config_log_error(ctx, "Missing destination IP");
                return -1;
            }
            if (config_validate_ip(token, &dst_ip, &dst_mask) != 0) {
                config_log_error(ctx, "Invalid destination IP: %s", token);
                return -1;
            }
        } else if (strncmp(token, "--to-source", 11) == 0) {
            token = strtok_r(NULL, " \t", &saveptr);
            if (!token) {
                config_log_error(ctx, "Missing NAT IP");
                return -1;
            }
            char *colon = strchr(token, ':');
            if (colon) {
                *colon = '\0';
                nat_port = atoi(colon + 1);
            }
            if (config_validate_ip(token, &nat_ip, NULL) != 0) {
                config_log_error(ctx, "Invalid NAT IP: %s", token);
                return -1;
            }
        } else if (strncmp(token, "--to-destination", 15) == 0) {
            token = strtok_r(NULL, " \t", &saveptr);
            if (!token) {
                config_log_error(ctx, "Missing NAT destination");
                return -1;
            }
            char *colon = strchr(token, ':');
            if (colon) {
                *colon = '\0';
                nat_port = atoi(colon + 1);
            }
            if (config_validate_ip(token, &nat_ip, NULL) != 0) {
                config_log_error(ctx, "Invalid NAT destination IP: %s", token);
                return -1;
            }
        } else if (strncmp(token, "--sport", 7) == 0) {
            token = strtok_r(NULL, " \t", &saveptr);
            if (!token) {
                config_log_error(ctx, "Missing source port");
                return -1;
            }
            uint16_t port_end;
            if (config_validate_port(token, &src_port, &port_end) != 0) {
                config_log_error(ctx, "Invalid source port: %s", token);
                return -1;
            }
        } else if (strncmp(token, "--dport", 7) == 0) {
            token = strtok_r(NULL, " \t", &saveptr);
            if (!token) {
                config_log_error(ctx, "Missing destination port");
                return -1;
            }
            uint16_t port_end;
            if (config_validate_port(token, &dst_port, &port_end) != 0) {
                config_log_error(ctx, "Invalid destination port: %s", token);
                return -1;
            }
        }
    }
    
    if (nat_add_rule(nat, type, src_ip, src_mask, dst_ip, dst_mask, 
                    src_port, dst_port, protocol, nat_ip, nat_port) < 0) {
        config_log_error(ctx, "Failed to add NAT rule");
        return -1;
    }
    
    return 0;
}

int config_parse(struct config_ctx *ctx, struct filter_ctx *filter, struct nat_ctx *nat) {
    char line[MAX_CONFIG_LINE];
    char *trimmed, *comment;
    
    if (!ctx || !ctx->file) return -1;
    
    while (fgets(line, sizeof(line), ctx->file)) {
        ctx->line_num++;
        
        trimmed = line;
        while (*trimmed && isspace(*trimmed)) trimmed++;
        
        if (*trimmed == '#' || *trimmed == '\0' || *trimmed == '\n') {
            continue;
        }
        
        comment = strchr(trimmed, '#');
        if (comment) {
            *comment = '\0';
        }
        
        char *end = trimmed + strlen(trimmed) - 1;
        while (end > trimmed && isspace(*end)) {
            *end = '\0';
            end--;
        }
        
        if (strncmp(trimmed, "INPUT", 5) == 0 || 
            strncmp(trimmed, "OUTPUT", 6) == 0 || 
            strncmp(trimmed, "FORWARD", 7) == 0) {
            config_parse_rule(ctx, trimmed, filter);
        } else if (strncmp(trimmed, "SNAT", 4) == 0 || 
                  strncmp(trimmed, "DNAT", 4) == 0 || 
                  strncmp(trimmed, "MASQUERADE", 10) == 0 || 
                  strncmp(trimmed, "REDIRECT", 8) == 0) {
            config_parse_nat_rule(ctx, trimmed, nat);
        } else {
            config_log_error(ctx, "Unknown command: %s", trimmed);
        }
    }
    
    return ctx->error_count;
}
