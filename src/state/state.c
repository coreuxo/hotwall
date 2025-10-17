#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "state.h"
#include "../capture/packet.h"

struct state_ctx *state_init(uint32_t max_conn) {
    struct state_ctx *ctx;
    
    ctx = malloc(sizeof(struct state_ctx));
    if (!ctx) {
        return NULL;
    }
    
    ctx->conn_track = conn_track_init(max_conn);
    if (!ctx->conn_track) {
        free(ctx);
        return NULL;
    }
    
    ctx->max_connections = max_conn;
    
    return ctx;
}

void state_cleanup(struct state_ctx *ctx) {
    if (ctx) {
        conn_track_cleanup(ctx->conn_track);
        free(ctx);
    }
}

static conn_dir_t get_packet_direction(struct packet_info *pkt, struct conn_key *key) {
    /* Check if packet matches original connection direction */
    if (pkt->src_ip == key->src_ip && pkt->dst_ip == key->dst_ip &&
        pkt->src_port == key->src_port && pkt->dst_port == key->dst_port) {
        return CONN_DIR_ORIGINAL;
    }
    /* Check if packet matches reply direction */
    if (pkt->src_ip == key->dst_ip && pkt->dst_ip == key->src_ip &&
        pkt->src_port == key->dst_port && pkt->dst_port == key->src_port) {
        return CONN_DIR_REPLY;
    }
    return CONN_DIR_ORIGINAL; /* default */
}

static void update_tcp_state(struct conn_entry *conn, struct packet_info *pkt, conn_dir_t direction) {
    struct tcphdr *tcp = pkt->tcp;
    int syn_flag = tcp->syn;
    int ack_flag = tcp->ack;
    int fin_flag = tcp->fin;
    int rst_flag = tcp->rst;
    
    /* Full TCP state machine based on RFC 793 */
    switch (conn->state) {
        case CONN_STATE_NONE:
            if (syn_flag && !ack_flag && direction == CONN_DIR_ORIGINAL) {
                conn->state = CONN_STATE_SYN_SENT;
            } else if (syn_flag && !ack_flag && direction == CONN_DIR_REPLY) {
                conn->state = CONN_STATE_SYN_RECV;
            }
            break;
            
        case CONN_STATE_SYN_SENT:
            if (syn_flag && ack_flag && direction == CONN_DIR_REPLY) {
                conn->state = CONN_STATE_ESTABLISHED;
                conn->timeout = CONN_TIMEOUT_ESTABLISHED;
            } else if (rst_flag) {
                conn->state = CONN_STATE_CLOSED;
            }
            break;
            
        case CONN_STATE_SYN_RECV:
            if (ack_flag && direction == CONN_DIR_ORIGINAL) {
                conn->state = CONN_STATE_ESTABLISHED;
                conn->timeout = CONN_TIMEOUT_ESTABLISHED;
            } else if (rst_flag) {
                conn->state = CONN_STATE_CLOSED;
            }
            break;
            
        case CONN_STATE_ESTABLISHED:
            if (fin_flag && direction == CONN_DIR_ORIGINAL) {
                conn->state = CONN_STATE_FIN_WAIT;
            } else if (fin_flag && direction == CONN_DIR_REPLY) {
                conn->state = CONN_STATE_CLOSE_WAIT;
            } else if (rst_flag) {
                conn->state = CONN_STATE_CLOSED;
            }
            break;
            
        case CONN_STATE_FIN_WAIT:
            if (fin_flag && direction == CONN_DIR_REPLY) {
                conn->state = CONN_STATE_TIME_WAIT;
                conn->timeout = CONN_TIMEOUT_TCP_CLOSE;
            } else if (ack_flag && direction == CONN_DIR_REPLY) {
                conn->state = CONN_STATE_FIN_WAIT;
            }
            break;
            
        case CONN_STATE_CLOSE_WAIT:
            if (fin_flag && direction == CONN_DIR_ORIGINAL) {
                conn->state = CONN_STATE_LAST_ACK;
            }
            break;
            
        case CONN_STATE_LAST_ACK:
            if (ack_flag && direction == CONN_DIR_REPLY) {
                conn->state = CONN_STATE_CLOSED;
            }
            break;
            
        case CONN_STATE_TIME_WAIT:
            /* Wait for 2MSL timeout */
            if (time(NULL) - conn->last_seen > CONN_TIMEOUT_TCP_CLOSE) {
                conn->state = CONN_STATE_CLOSED;
            }
            break;
            
        case CONN_STATE_CLOSED:
            /* Connection is closed, remove it on next cleanup */
            break;
    }
    
    /* Update sequence tracking for TCP */
    if (pkt->is_tcp) {
        if (direction == CONN_DIR_ORIGINAL) {
            if (tcp->seq) {
                conn->seq = ntohl(tcp->seq);
                if (pkt->payload_len > 0) {
                    conn->seq += pkt->payload_len;
                }
                if (syn_flag || fin_flag) {
                    conn->seq++; /* SYN and FIN consume one sequence number */
                }
            }
            if (tcp->ack_seq) {
                conn->ack = ntohl(tcp->ack_seq);
            }
        } else { /* REPLY direction */
            if (tcp->seq) {
                /* For reply, we track the sequence in the opposite direction */
                conn->ack = ntohl(tcp->seq);
                if (pkt->payload_len > 0) {
                    conn->ack += pkt->payload_len;
                }
                if (syn_flag || fin_flag) {
                    conn->ack++;
                }
            }
        }
        
        /* Update window size */
        conn->window = ntohs(tcp->window);
    }
}

int state_process_packet(struct state_ctx *ctx, struct packet_info *pkt) {
    struct conn_key key;
    struct conn_entry *conn;
    conn_dir_t direction;
    uint32_t seq = 0, ack = 0;
    
    if (!ctx || !pkt) {
        return -1;
    }
    
    /* Only track TCP, UDP, and ICMP */
    if (!pkt->is_tcp && !pkt->is_udp && !pkt->is_icmp) {
        return 0;
    }
    
    /* Create connection key */
    memset(&key, 0, sizeof(key));
    key.src_ip = pkt->src_ip;
    key.dst_ip = pkt->dst_ip;
    key.src_port = pkt->src_port;
    key.dst_port = pkt->dst_port;
    key.protocol = pkt->protocol;
    
    /* Find or create connection */
    conn = conn_track_find(ctx->conn_track, &key);
    if (!conn) {
        conn = conn_track_add(ctx->conn_track, &key);
        if (!conn) {
            return -1; /* Couldn't add connection (table full) */
        }
    }
    
    /* Determine packet direction */
    direction = get_packet_direction(pkt, &conn->key);
    
    /* Extract sequence numbers for TCP */
    if (pkt->is_tcp && pkt->tcp) {
        seq = ntohl(pkt->tcp->seq);
        ack = ntohl(pkt->tcp->ack_seq);
    }
    
    /* Update connection tracking */
    conn_track_update(ctx->conn_track, &key, direction, seq, ack);
    
    /* Update TCP state machine */
    if (pkt->is_tcp) {
        update_tcp_state(conn, pkt, direction);
    }
    
    /* Mark as assured if we've seen bidirectional traffic */
    if (conn->packets_orig > 0 && conn->packets_reply > 0) {
        conn->assured = 1;
    }
    
    return 0;
}

struct conn_entry *state_find_connection(struct state_ctx *ctx, struct packet_info *pkt) {
    struct conn_key key;
    
    if (!ctx || !pkt) {
        return NULL;
    }
    
    memset(&key, 0, sizeof(key));
    key.src_ip = pkt->src_ip;
    key.dst_ip = pkt->dst_ip;
    key.src_port = pkt->src_port;
    key.dst_port = pkt->dst_port;
    key.protocol = pkt->protocol;
    
    return conn_track_find(ctx->conn_track, &key);
}

void state_cleanup_old(struct state_ctx *ctx) {
    if (ctx && ctx->conn_track) {
        conn_track_cleanup_old(ctx->conn_track);
    }
}

uint32_t state_get_connection_count(struct state_ctx *ctx) {
    if (ctx && ctx->conn_track) {
        return ctx->conn_track->current_connections;
    }
    return 0;
}
