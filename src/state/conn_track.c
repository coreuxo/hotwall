#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "conn_track.h"
#include "../util/util.h"

struct conn_track_ctx *conn_track_init(uint32_t max_conn) {
    struct conn_track_ctx *ctx;
    uint32_t i;
    
    ctx = malloc(sizeof(struct conn_track_ctx));
    if (!ctx) {
        return NULL;
    }
    
    ctx->table = malloc(sizeof(struct conn_table));
    if (!ctx->table) {
        free(ctx);
        return NULL;
    }
    
    ctx->table->size = CONN_TABLE_SIZE;
    ctx->table->count = 0;
    ctx->table->cleanup_counter = 0;
    
    ctx->table->buckets = calloc(CONN_TABLE_SIZE, sizeof(struct conn_entry*));
    if (!ctx->table->buckets) {
        free(ctx->table);
        free(ctx);
        return NULL;
    }
    
    ctx->max_connections = max_conn;
    ctx->current_connections = 0;
    
    return ctx;
}

void conn_track_cleanup(struct conn_track_ctx *ctx) {
    uint32_t i;
    struct conn_entry *entry, *next;
    
    if (!ctx) return;
    
    if (ctx->table && ctx->table->buckets) {
        for (i = 0; i < ctx->table->size; i++) {
            entry = ctx->table->buckets[i];
            while (entry) {
                next = entry->next;
                free(entry);
                entry = next;
            }
        }
        free(ctx->table->buckets);
    }
    
    free(ctx->table);
    free(ctx);
}

uint32_t conn_track_hash(struct conn_key *key) {
    uint32_t h = 0;
    
    h = hash32(key->src_ip);
    h ^= hash32(key->dst_ip);
    h ^= hash32((key->src_port << 16) | key->dst_port);
    h ^= hash32(key->protocol);
    
    return h % CONN_TABLE_SIZE;
}

struct conn_entry *conn_track_find(struct conn_track_ctx *ctx, struct conn_key *key) {
    uint32_t idx;
    struct conn_entry *entry;
    
    if (!ctx || !key) {
        return NULL;
    }
    
    idx = conn_track_hash(key);
    entry = ctx->table->buckets[idx];
    
    while (entry) {
        if (entry->key.src_ip == key->src_ip &&
            entry->key.dst_ip == key->dst_ip &&
            entry->key.src_port == key->src_port &&
            entry->key.dst_port == key->dst_port &&
            entry->key.protocol == key->protocol) {
            return entry;
        }
        entry = entry->next;
    }
    
    /* also check reply direction */
    idx = conn_track_hash(key);
    entry = ctx->table->buckets[idx];
    
    while (entry) {
        if (entry->reply_key.src_ip == key->src_ip &&
            entry->reply_key.dst_ip == key->dst_ip &&
            entry->reply_key.src_port == key->src_port &&
            entry->reply_key.dst_port == key->dst_port &&
            entry->reply_key.protocol == key->protocol) {
            return entry;
        }
        entry = entry->next;
    }
    
    return NULL;
}

struct conn_entry *conn_track_add(struct conn_track_ctx *ctx, struct conn_key *key) {
    uint32_t idx;
    struct conn_entry *entry, *new_entry;
    
    if (!ctx || !key || ctx->current_connections >= ctx->max_connections) {
        return NULL;
    }
    
    /* check if already exists */
    entry = conn_track_find(ctx, key);
    if (entry) {
        return entry;
    }
    
    new_entry = malloc(sizeof(struct conn_entry));
    if (!new_entry) {
        return NULL;
    }
    
    memset(new_entry, 0, sizeof(struct conn_entry));
    memcpy(&new_entry->key, key, sizeof(struct conn_key));
    
    /* setup reply key */
    new_entry->reply_key.src_ip = key->dst_ip;
    new_entry->reply_key.dst_ip = key->src_ip;
    new_entry->reply_key.src_port = key->dst_port;
    new_entry->reply_key.dst_port = key->src_port;
    new_entry->reply_key.protocol = key->protocol;
    
    new_entry->state = CONN_STATE_NONE;
    new_entry->last_seen = time(NULL);
    
    /* set initial timeout based on protocol */
    switch (key->protocol) {
        case 6: /* TCP */
            new_entry->timeout = CONN_TIMEOUT_TCP_CLOSE;
            break;
        case 17: /* UDP */
            new_entry->timeout = CONN_TIMEOUT_UDP;
            break;
        default:
            new_entry->timeout = 300; /* 5 minutes for other protocols */
    }
    
    idx = conn_track_hash(key);
    new_entry->next = ctx->table->buckets[idx];
    ctx->table->buckets[idx] = new_entry;
    
    ctx->table->count++;
    ctx->current_connections++;
    
    return new_entry;
}

int conn_track_remove(struct conn_track_ctx *ctx, struct conn_key *key) {
    uint32_t idx;
    struct conn_entry *entry, *prev = NULL;
    
    if (!ctx || !key) {
        return -1;
    }
    
    idx = conn_track_hash(key);
    entry = ctx->table->buckets[idx];
    
    while (entry) {
        if (entry->key.src_ip == key->src_ip &&
            entry->key.dst_ip == key->dst_ip &&
            entry->key.src_port == key->src_port &&
            entry->key.dst_port == key->dst_port &&
            entry->key.protocol == key->protocol) {
            
            if (prev) {
                prev->next = entry->next;
            } else {
                ctx->table->buckets[idx] = entry->next;
            }
            
            free(entry);
            ctx->table->count--;
            ctx->current_connections--;
            return 0;
        }
        prev = entry;
        entry = entry->next;
    }
    
    return -1;
}

int conn_track_update(struct conn_track_ctx *ctx, struct conn_key *key, 
                      conn_dir_t direction, uint32_t seq, uint32_t ack) {
    struct conn_entry *entry;
    time_t now = time(NULL);
    
    if (!ctx || !key) {
        return -1;
    }
    
    entry = conn_track_find(ctx, key);
    if (!entry) {
        entry = conn_track_add(ctx, key);
        if (!entry) {
            return -1;
        }
    }
    
    entry->last_seen = now;
    
    if (direction == CONN_DIR_ORIGINAL) {
        entry->packets_orig++;
        /* simplistic byte counting */
        entry->bytes_orig += 60; /* approximate */
    } else {
        entry->packets_reply++;
        entry->bytes_reply += 60;
        entry->seen_reply = 1;
    }
    
    /* basic TCP state tracking */
    if (key->protocol == 6) { /* TCP */
        /* very simplified state machine */
        if (entry->state == CONN_STATE_NONE) {
            entry->state = CONN_STATE_SYN_SENT;
        } else if (entry->state == CONN_STATE_SYN_SENT && direction == CONN_DIR_REPLY) {
            entry->state = CONN_STATE_ESTABLISHED;
            entry->timeout = CONN_TIMEOUT_ESTABLISHED;
        }
        
        /* update sequence tracking */
        if (seq > 0) {
            entry->seq = seq;
        }
        if (ack > 0) {
            entry->ack = ack;
        }
    }
    
    return 0;
}

void conn_track_cleanup_old(struct conn_track_ctx *ctx) {
    uint32_t i;
    struct conn_entry *entry, *prev, *next;
    time_t now = time(NULL);
    
    if (!ctx) return;
    
    ctx->table->cleanup_counter++;
    
    /* only do full cleanup every 1000 calls to reduce overhead */
    if (ctx->table->cleanup_counter % 1000 != 0) {
        return;
    }
    
    for (i = 0; i < ctx->table->size; i++) {
        prev = NULL;
        entry = ctx->table->buckets[i];
        
        while (entry) {
            next = entry->next;
            
            if (now - entry->last_seen > entry->timeout) {
                if (prev) {
                    prev->next = next;
                } else {
                    ctx->table->buckets[i] = next;
                }
                
                free(entry);
                ctx->table->count--;
                ctx->current_connections--;
                entry = next;
                continue;
            }
            
            prev = entry;
            entry = next;
        }
    }
}
