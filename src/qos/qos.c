#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <arpa/inet.h>
#include "qos.h"

struct qos_ctx *qos_init(void) {
    struct qos_ctx *ctx;
    int i, ret;
    
    ctx = calloc(1, sizeof(struct qos_ctx));
    if (!ctx) goto fail;
    
    ret = pthread_mutex_init(&ctx->rule_lock, NULL);
    if (ret != 0) goto fail;
    
    ctx->class_count = 6;
    
    strcpy(ctx->classes[0].name, "best_effort");
    ctx->classes[0].class_id = QOS_CLASS_BEST_EFFORT;
    ctx->classes[0].bandwidth = 1000000;
    ctx->classes[0].priority = 0;
    pthread_mutex_init(&ctx->classes[0].bucket.lock, NULL);
    ctx->classes[0].bucket.tokens = QOS_TOKEN_BUCKET_SIZE;
    ctx->classes[0].bucket.rate = QOS_TOKEN_RATE;
    ctx->classes[0].bucket.burst = QOS_TOKEN_BUCKET_SIZE;
    ctx->classes[0].bucket.last_update = time(NULL);
    
    strcpy(ctx->classes[1].name, "background");
    ctx->classes[1].class_id = QOS_CLASS_BACKGROUND;
    ctx->classes[1].bandwidth = 500000;
    ctx->classes[1].priority = 1;
    pthread_mutex_init(&ctx->classes[1].bucket.lock, NULL);
    ctx->classes[1].bucket.tokens = QOS_TOKEN_BUCKET_SIZE;
    ctx->classes[1].bucket.rate = QOS_TOKEN_RATE / 2;
    ctx->classes[1].bucket.burst = QOS_TOKEN_BUCKET_SIZE / 2;
    ctx->classes[1].bucket.last_update = time(NULL);
    
    strcpy(ctx->classes[2].name, "standard");
    ctx->classes[2].class_id = QOS_CLASS_STANDARD;
    ctx->classes[2].bandwidth = 2000000;
    ctx->classes[2].priority = 2;
    pthread_mutex_init(&ctx->classes[2].bucket.lock, NULL);
    ctx->classes[2].bucket.tokens = QOS_TOKEN_BUCKET_SIZE;
    ctx->classes[2].bucket.rate = QOS_TOKEN_RATE * 2;
    ctx->classes[2].bucket.burst = QOS_TOKEN_BUCKET_SIZE * 2;
    ctx->classes[2].bucket.last_update = time(NULL);
    
    strcpy(ctx->classes[3].name, "video");
    ctx->classes[3].class_id = QOS_CLASS_VIDEO;
    ctx->classes[3].bandwidth = 5000000;
    ctx->classes[3].priority = 3;
    pthread_mutex_init(&ctx->classes[3].bucket.lock, NULL);
    ctx->classes[3].bucket.tokens = QOS_TOKEN_BUCKET_SIZE;
    ctx->classes[3].bucket.rate = QOS_TOKEN_RATE * 5;
    ctx->classes[3].bucket.burst = QOS_TOKEN_BUCKET_SIZE * 5;
    ctx->classes[3].bucket.last_update = time(NULL);
    
    strcpy(ctx->classes[4].name, "voice");
    ctx->classes[4].class_id = QOS_CLASS_VOICE;
    ctx->classes[4].bandwidth = 1000000;
    ctx->classes[4].priority = 4;
    pthread_mutex_init(&ctx->classes[4].bucket.lock, NULL);
    ctx->classes[4].bucket.tokens = QOS_TOKEN_BUCKET_SIZE;
    ctx->classes[4].bucket.rate = QOS_TOKEN_RATE;
    ctx->classes[4].bucket.burst = QOS_TOKEN_BUCKET_SIZE;
    ctx->classes[4].bucket.last_update = time(NULL);
    
    strcpy(ctx->classes[5].name, "control");
    ctx->classes[5].class_id = QOS_CLASS_CONTROL;
    ctx->classes[5].bandwidth = 100000;
    ctx->classes[5].priority = 5;
    pthread_mutex_init(&ctx->classes[5].bucket.lock, NULL);
    ctx->classes[5].bucket.tokens = QOS_TOKEN_BUCKET_SIZE;
    ctx->classes[5].bucket.rate = QOS_TOKEN_RATE / 10;
    ctx->classes[5].bucket.burst = QOS_TOKEN_BUCKET_SIZE / 10;
    ctx->classes[5].bucket.last_update = time(NULL);
    
    ctx->enabled = 1;
    return ctx;

fail:
    if (ctx) {
        for (i = 0; i < ctx->class_count; i++) {
            pthread_mutex_destroy(&ctx->classes[i].bucket.lock);
        }
        pthread_mutex_destroy(&ctx->rule_lock);
        free(ctx);
    }
    return NULL;
}

void qos_cleanup(struct qos_ctx *ctx) {
    struct qos_rule *rule, *next_rule;
    int i;
    
    if (!ctx) return;
    
    pthread_mutex_lock(&ctx->rule_lock);
    rule = ctx->rules;
    while (rule) {
        next_rule = rule->next;
        free(rule);
        rule = next_rule;
    }
    pthread_mutex_unlock(&ctx->rule_lock);
    
    for (i = 0; i < ctx->class_count; i++) {
        pthread_mutex_destroy(&ctx->classes[i].bucket.lock);
    }
    
    pthread_mutex_destroy(&ctx->rule_lock);
    free(ctx);
}

int qos_add_rule(struct qos_ctx *ctx, uint32_t src_ip, uint32_t src_mask,
                uint32_t dst_ip, uint32_t dst_mask, uint16_t src_port,
                uint16_t dst_port, uint8_t protocol, qos_class_t class_id,
                qos_action_t action, uint32_t rate_limit) {
    struct qos_rule *rule, *new_rule;
    
    if (!ctx || class_id >= ctx->class_count) return -1;
    
    new_rule = calloc(1, sizeof(struct qos_rule));
    if (!new_rule) return -1;
    
    new_rule->id = ctx->next_rule_id++;
    new_rule->src_ip = src_ip;
    new_rule->src_mask = src_mask;
    new_rule->dst_ip = dst_ip;
    new_rule->dst_mask = dst_mask;
    new_rule->src_port = src_port;
    new_rule->dst_port = dst_port;
    new_rule->protocol = protocol;
    new_rule->class_id = class_id;
    new_rule->action = action;
    new_rule->rate_limit = rate_limit;
    new_rule->enabled = 1;
    
    pthread_mutex_lock(&ctx->rule_lock);
    
    if (!ctx->rules) {
        ctx->rules = new_rule;
    } else {
        rule = ctx->rules;
        while (rule->next) rule = rule->next;
        rule->next = new_rule;
    }
    
    pthread_mutex_unlock(&ctx->rule_lock);
    return new_rule->id;
}

int qos_token_bucket_consume(struct qos_token_bucket *bucket, uint32_t tokens) {
    time_t now;
    uint32_t new_tokens;
    int ret = 0;
    
    if (!bucket || tokens == 0) return 1;
    
    pthread_mutex_lock(&bucket->lock);
    
    now = time(NULL);
    new_tokens = (uint32_t)((now - bucket->last_update) * bucket->rate);
    bucket->tokens += new_tokens;
    if (bucket->tokens > bucket->burst) {
        bucket->tokens = bucket->burst;
    }
    bucket->last_update = now;
    
    if (bucket->tokens >= tokens) {
        bucket->tokens -= tokens;
        ret = 1;
    }
    
    pthread_mutex_unlock(&bucket->lock);
    return ret;
}

int qos_process_packet(struct qos_ctx *ctx, struct packet_info *pkt) {
    struct qos_rule *rule;
    struct qos_class *qclass;
    int action = QOS_ACTION_PASS;
    uint32_t tokens_needed;
    
    if (!ctx || !pkt || !ctx->enabled) return QOS_ACTION_PASS;
    
    ctx->total_packets++;
    
    pthread_mutex_lock(&ctx->rule_lock);
    
    rule = ctx->rules;
    while (rule) {
        if (!rule->enabled) {
            rule = rule->next;
            continue;
        }
        
        if (rule->protocol != 0 && rule->protocol != pkt->protocol) {
            rule = rule->next;
            continue;
        }
        
        if (rule->src_mask != 0) {
            uint32_t src_net = pkt->src_ip & rule->src_mask;
            if (src_net != (rule->src_ip & rule->src_mask)) {
                rule = rule->next;
                continue;
            }
        }
        
        if (rule->dst_mask != 0) {
            uint32_t dst_net = pkt->dst_ip & rule->dst_mask;
            if (dst_net != (rule->dst_ip & rule->dst_mask)) {
                rule = rule->next;
                continue;
            }
        }
        
        if (rule->src_port != 0 && rule->src_port != pkt->src_port) {
            rule = rule->next;
            continue;
        }
        
        if (rule->dst_port != 0 && rule->dst_port != pkt->dst_port) {
            rule = rule->next;
            continue;
        }
        
        qclass = &ctx->classes[rule->class_id];
        tokens_needed = pkt->len / 100 + 1;
        
        if (!qos_token_bucket_consume(&qclass->bucket, tokens_needed)) {
            action = QOS_ACTION_DROP;
            ctx->total_drops++;
            qclass->packet_count++;
            break;
        }
        
        qclass->packet_count++;
        qclass->byte_count += pkt->len;
        action = rule->action;
        break;
        
        rule = rule->next;
    }
    
    pthread_mutex_unlock(&ctx->rule_lock);
    return action;
}

void qos_update_buckets(struct qos_ctx *ctx) {
    int i;
    time_t now = time(NULL);
    
    if (!ctx) return;
    
    for (i = 0; i < ctx->class_count; i++) {
        pthread_mutex_lock(&ctx->classes[i].bucket.lock);
        
        uint32_t new_tokens = (uint32_t)((now - ctx->classes[i].bucket.last_update) * 
                                        ctx->classes[i].bucket.rate);
        ctx->classes[i].bucket.tokens += new_tokens;
        if (ctx->classes[i].bucket.tokens > ctx->classes[i].bucket.burst) {
            ctx->classes[i].bucket.tokens = ctx->classes[i].bucket.burst;
        }
        ctx->classes[i].bucket.last_update = now;
        
        pthread_mutex_unlock(&ctx->classes[i].bucket.lock);
    }
}

void qos_dump_stats(struct qos_ctx *ctx) {
    int i;
    
    if (!ctx) return;
    
    printf("\n=== QoS Statistics (%lu packets, %lu drops) ===\n",
           ctx->total_packets, ctx->total_drops);
    printf("Class        Packets    Bytes      Bandwidth Priority\n");
    printf("------------ ---------- ---------- --------- --------\n");
    
    for (i = 0; i < ctx->class_count; i++) {
        printf("%-12s %-10u %-10lu %-9u %-8u\n",
               ctx->classes[i].name,
               ctx->classes[i].packet_count,
               ctx->classes[i].byte_count,
               ctx->classes[i].bandwidth,
               ctx->classes[i].priority);
    }
}
