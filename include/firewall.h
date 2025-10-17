#ifndef FIREWALL_H
#define FIREWALL_H

struct firewall_ctx;

struct firewall_ctx *firewall_init(void);
int firewall_start(struct firewall_ctx *ctx);
void firewall_stop(struct firewall_ctx *ctx);
void firewall_cleanup(struct firewall_ctx *ctx);

#endif
