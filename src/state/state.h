#ifndef STATE_H
#define STATE_H

#include "conn_track.h"
#include "../capture/packet.h"

struct state_ctx {
    struct conn_track_ctx *conn_track;
    uint32_t max_connections;
};

struct state_ctx *state_init(uint32_t max_conn);
void state_cleanup(struct state_ctx *ctx);
int state_process_packet(struct state_ctx *ctx, struct packet_info *pkt);
struct conn_entry *state_find_connection(struct state_ctx *ctx, struct packet_info *pkt);
void state_cleanup_old(struct state_ctx *ctx);
uint32_t state_get_connection_count(struct state_ctx *ctx);

#endif
