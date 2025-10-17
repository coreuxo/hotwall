#ifndef CONN_TRACK_H
#define CONN_TRACK_H

#include <stdint.h>
#include <netinet/in.h>
#include <time.h>

#define CONN_TABLE_SIZE 65536
#define CONN_TIMEOUT_ESTABLISHED 432000  /* 5 days in seconds */
#define CONN_TIMEOUT_TCP_CLOSE 120       /* 2 minutes */
#define CONN_TIMEOUT_UDP 180             /* 3 minutes */

typedef enum {
    CONN_STATE_NONE = 0,
    CONN_STATE_SYN_SENT,
    CONN_STATE_SYN_RECV,
    CONN_STATE_ESTABLISHED,
    CONN_STATE_FIN_WAIT,
    CONN_STATE_CLOSE_WAIT,
    CONN_STATE_LAST_ACK,
    CONN_STATE_TIME_WAIT,
    CONN_STATE_CLOSED
} tcp_state_t;

typedef enum {
    CONN_DIR_ORIGINAL = 0,
    CONN_DIR_REPLY
} conn_dir_t;

struct conn_key {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
};

struct conn_entry {
    struct conn_key key;
    struct conn_key reply_key;  /* for NAT */
    
    tcp_state_t state;
    uint32_t seq;               /* TCP sequence tracking */
    uint32_t ack;               /* TCP ack tracking */
    uint32_t window;
    
    uint64_t packets_orig;
    uint64_t bytes_orig;
    uint64_t packets_reply;
    uint64_t bytes_reply;
    
    time_t last_seen;
    time_t timeout;
    
    uint8_t assured:1;          /* connection is assured */
    uint8_t seen_reply:1;       /* seen reply traffic */
    
    struct conn_entry *next;
};

struct conn_table {
    struct conn_entry **buckets;
    uint32_t size;
    uint32_t count;
    uint64_t cleanup_counter;
};

struct conn_track_ctx {
    struct conn_table *table;
    uint32_t max_connections;
    uint32_t current_connections;
};

struct conn_track_ctx *conn_track_init(uint32_t max_conn);
void conn_track_cleanup(struct conn_track_ctx *ctx);
struct conn_entry *conn_track_find(struct conn_track_ctx *ctx, struct conn_key *key);
struct conn_entry *conn_track_add(struct conn_track_ctx *ctx, struct conn_key *key);
int conn_track_remove(struct conn_track_ctx *ctx, struct conn_key *key);
int conn_track_update(struct conn_track_ctx *ctx, struct conn_key *key, 
                      conn_dir_t direction, uint32_t seq, uint32_t ack);
void conn_track_cleanup_old(struct conn_track_ctx *ctx);
uint32_t conn_track_hash(struct conn_key *key);

#endif
