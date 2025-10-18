#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <arpa/inet.h>
#include "security.h"
#include "../util/debug.h"

struct security_ctx *security_init(void) {
    struct security_ctx *ctx;
    int ret;
    
    ctx = calloc(1, sizeof(struct security_ctx));
    if (!ctx) {
        ERROR("Failed to allocate security context\n");
        return NULL;
    }
    
    ret = pthread_mutex_init(&ctx->blacklist_lock, NULL);
    if (ret != 0) goto fail;
    
    ret = pthread_mutex_init(&ctx->whitelist_lock, NULL);
    if (ret != 0) {
        pthread_mutex_destroy(&ctx->blacklist_lock);
        goto fail;
    }
    
    ret = pthread_mutex_init(&ctx->rate_lock, NULL);
    if (ret != 0) {
        pthread_mutex_destroy(&ctx->blacklist_lock);
        pthread_mutex_destroy(&ctx->whitelist_lock);
        goto fail;
    }
    
    ctx->next_rule_id = 1;
    ctx->enabled = 1;
    
    DBG("Security module initialized\n");
    return ctx;

fail:
    free(ctx);
    return NULL;
}

void security_cleanup(struct security_ctx *ctx) {
    struct security_ip_entry *ip_entry, *ip_next;
    struct security_rate_rule *rate_rule, *rate_next;
    
    if (!ctx) return;
    
    pthread_mutex_lock(&ctx->blacklist_lock);
    ip_entry = ctx->blacklist;
    while (ip_entry) {
        ip_next = ip_entry->next;
        free(ip_entry);
        ip_entry = ip_next;
    }
    pthread_mutex_unlock(&ctx->blacklist_lock);
    
    pthread_mutex_lock(&ctx->whitelist_lock);
    ip_entry = ctx->whitelist;
    while (ip_entry) {
        ip_next = ip_entry->next;
        free(ip_entry);
        ip_entry = ip_next;
    }
    pthread_mutex_unlock(&ctx->whitelist_lock);
    
    pthread_mutex_lock(&ctx->rate_lock);
    rate_rule = ctx->rate_rules;
    while (rate_rule) {
        rate_next = rate_rule->next;
        free(rate_rule);
        rate_rule = rate_next;
    }
    pthread_mutex_unlock(&ctx->rate_lock);
    
    pthread_mutex_destroy(&ctx->blacklist_lock);
    pthread_mutex_destroy(&ctx->whitelist_lock);
    pthread_mutex_destroy(&ctx->rate_lock);
    
    free(ctx);
    DBG("Security module cleaned up\n");
}

int security_add_blacklist(struct security_ctx *ctx, uint32_t ip, time_t duration) {
    struct security_ip_entry *entry, *new_entry;
    
    if (!ctx || !ctx->enabled) return -1;
    
    new_entry = calloc(1, sizeof(struct security_ip_entry));
    if (!new_entry) return -1;
    
    new_entry->ip = ip;
    new_entry->expires = time(NULL) + duration;
    new_entry->hit_count = 0;
    
    pthread_mutex_lock(&ctx->blacklist_lock);
    
    entry = ctx->blacklist;
    while (entry) {
        if (entry->ip == ip) {
            entry->expires = new_entry->expires;
            free(new_entry);
            pthread_mutex_unlock(&ctx->blacklist_lock);
            return 0;
        }
        entry = entry->next;
    }
    
    new_entry->next = ctx->blacklist;
    ctx->blacklist = new_entry;
    
    pthread_mutex_unlock(&ctx->blacklist_lock);
    return 0;
}

int security_remove_blacklist(struct security_ctx *ctx, uint32_t ip) {
    struct security_ip_entry *entry, *prev = NULL;
    int ret = -1;
    
    if (!ctx) return -1;
    
    pthread_mutex_lock(&ctx->blacklist_lock);
    
    entry = ctx->blacklist;
    while (entry) {
        if (entry->ip == ip) {
            if (prev) {
                prev->next = entry->next;
            } else {
                ctx->blacklist = entry->next;
            }
            free(entry);
            ret = 0;
            break;
        }
        prev = entry;
        entry = entry->next;
    }
    
    pthread_mutex_unlock(&ctx->blacklist_lock);
    return ret;
}

int security_add_whitelist(struct security_ctx *ctx, uint32_t ip) {
    struct security_ip_entry *entry, *new_entry;
    
    if (!ctx) return -1;
    
    new_entry = calloc(1, sizeof(struct security_ip_entry));
    if (!new_entry) return -1;
    
    new_entry->ip = ip;
    new_entry->expires = 0;
    new_entry->hit_count = 0;
    
    pthread_mutex_lock(&ctx->whitelist_lock);
    
    entry = ctx->whitelist;
    while (entry) {
        if (entry->ip == ip) {
            free(new_entry);
            pthread_mutex_unlock(&ctx->whitelist_lock);
            return 0;
        }
        entry = entry->next;
    }
    
    new_entry->next = ctx->whitelist;
    ctx->whitelist = new_entry;
    
    pthread_mutex_unlock(&ctx->whitelist_lock);
    return 0;
}

int security_check_ip(struct security_ctx *ctx, uint32_t ip) {
    struct security_ip_entry *entry;
    time_t now;
    int result = 0;
    
    if (!ctx || !ctx->enabled) return 0;
    
    now = time(NULL);
    
    pthread_mutex_lock(&ctx->whitelist_lock);
    entry = ctx->whitelist;
    while (entry) {
        if (entry->ip == ip) {
            pthread_mutex_unlock(&ctx->whitelist_lock);
            return 0;
        }
        entry = entry->next;
    }
    pthread_mutex_unlock(&ctx->whitelist_lock);
    
    pthread_mutex_lock(&ctx->blacklist_lock);
    entry = ctx->blacklist;
    while (entry) {
        if (entry->ip == ip) {
            if (entry->expires == 0 || entry->expires > now) {
                entry->hit_count++;
                ctx->total_blocks++;
                result = 1;
            }
            break;
        }
        entry = entry->next;
    }
    pthread_mutex_unlock(&ctx->blacklist_lock);
    
    return result;
}

int security_add_rate_rule(struct security_ctx *ctx, uint32_t ip, uint32_t mask, 
                          uint16_t port, uint8_t protocol, uint32_t rate_limit) {
    struct security_rate_rule *rule, *new_rule;
    
    if (!ctx || !ctx->enabled) return -1;
    
    new_rule = calloc(1, sizeof(struct security_rate_rule));
    if (!new_rule) return -1;
    
    new_rule->id = ctx->next_rule_id++;
    new_rule->ip = ip;
    new_rule->mask = mask;
    new_rule->port = port;
    new_rule->protocol = protocol;
    new_rule->rate_limit = rate_limit;
    new_rule->current_count = 0;
    new_rule->window_start = time(NULL);
    new_rule->enabled = 1;
    
    pthread_mutex_lock(&ctx->rate_lock);
    
    if (!ctx->rate_rules) {
        ctx->rate_rules = new_rule;
    } else {
        rule = ctx->rate_rules;
        while (rule->next) rule = rule->next;
        rule->next = new_rule;
    }
    
    pthread_mutex_unlock(&ctx->rate_lock);
    return new_rule->id;
}

int security_check_rate_limit(struct security_ctx *ctx, uint32_t ip, uint16_t port, uint8_t protocol) {
    struct security_rate_rule *rule;
    time_t now = time(NULL);
    int result = 0;
    
    if (!ctx || !ctx->enabled) return 0;
    
    pthread_mutex_lock(&ctx->rate_lock);
    
    rule = ctx->rate_rules;
    while (rule) {
        if (!rule->enabled) {
            rule = rule->next;
            continue;
        }
        
        if (rule->protocol != 0 && rule->protocol != protocol) {
            rule = rule->next;
            continue;
        }
        
        if (rule->port != 0 && rule->port != port) {
            rule = rule->next;
            continue;
        }
        
        if (rule->mask != 0) {
            uint32_t ip_net = ip & rule->mask;
            if (ip_net != (rule->ip & rule->mask)) {
                rule = rule->next;
                continue;
            }
        } else if (rule->ip != 0 && rule->ip != ip) {
            rule = rule->next;
            continue;
        }
        
        if (now - rule->window_start >= SECURITY_RATE_LIMIT_WINDOW) {
            rule->current_count = 0;
            rule->window_start = now;
        }
        
        rule->current_count++;
        if (rule->current_count > rule->rate_limit) {
            ctx->total_rate_limits++;
            result = 1;
            break;
        }
        
        rule = rule->next;
    }
    
    pthread_mutex_unlock(&ctx->rate_lock);
    return result;
}

void security_cleanup_expired(struct security_ctx *ctx) {
    struct security_ip_entry *entry, *prev, *next;
    time_t now = time(NULL);
    uint32_t cleaned = 0;
    
    if (!ctx) return;
    
    pthread_mutex_lock(&ctx->blacklist_lock);
    
    prev = NULL;
    entry = ctx->blacklist;
    while (entry) {
        next = entry->next;
        
        if (entry->expires > 0 && entry->expires <= now) {
            if (prev) {
                prev->next = next;
            } else {
                ctx->blacklist = next;
            }
            free(entry);
            cleaned++;
        } else {
            prev = entry;
        }
        
        entry = next;
    }
    
    pthread_mutex_unlock(&ctx->blacklist_lock);
    
    if (cleaned > 0) {
        DBG("Cleaned %u expired blacklist entries\n", cleaned);
    }
}

void security_dump_stats(struct security_ctx *ctx) {
    struct security_ip_entry *entry;
    uint32_t blacklist_count = 0, whitelist_count = 0, rate_rules_count = 0;
    
    if (!ctx) return;
    
    pthread_mutex_lock(&ctx->blacklist_lock);
    entry = ctx->blacklist;
    while (entry) {
        blacklist_count++;
        entry = entry->next;
    }
    pthread_mutex_unlock(&ctx->blacklist_lock);
    
    pthread_mutex_lock(&ctx->whitelist_lock);
    entry = ctx->whitelist;
    while (entry) {
        whitelist_count++;
        entry = entry->next;
    }
    pthread_mutex_unlock(&ctx->whitelist_lock);
    
    pthread_mutex_lock(&ctx->rate_lock);
    struct security_rate_rule *rule = ctx->rate_rules;
    while (rule) {
        rate_rules_count++;
        rule = rule->next;
    }
    pthread_mutex_unlock(&ctx->rate_lock);
    
    printf("\n=== Security Statistics ===\n");
    printf("Blacklist entries:  %u\n", blacklist_count);
    printf("Whitelist entries:  %u\n", whitelist_count);
    printf("Rate limit rules:   %u\n", rate_rules_count);
    printf("Total blocks:       %lu\n", ctx->total_blocks);
    printf("Rate limit hits:    %lu\n", ctx->total_rate_limits);
    printf("Module enabled:     %s\n", ctx->enabled ? "yes" : "no");
    printf("===========================\n");
}
