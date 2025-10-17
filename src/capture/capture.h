#ifndef CAPTURE_H
#define CAPTURE_H

#include "packet.h"

struct capture_ctx;

typedef int (*packet_handler)(struct packet_info *pkt, void *user_data);

struct capture_ctx *capture_init(const char *iface, int promisc, int timeout_ms);
int capture_start(struct capture_ctx *ctx, packet_handler handler, void *user_data);
void capture_stop(struct capture_ctx *ctx);
void capture_cleanup(struct capture_ctx *ctx);

#endif
