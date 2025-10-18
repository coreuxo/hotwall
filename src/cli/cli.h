#ifndef CLI_H
#define CLI_H

#include <stdio.h>
#include "../filter/filter.h"
#include "../state/state.h"
#include "../nat/nat.h"

struct cli_ctx {
    struct filter_ctx *filter;
    struct state_ctx *state;
    struct nat_ctx *nat;
    int running;
};

struct cli_ctx *cli_init(struct filter_ctx *filter, struct state_ctx *state, struct nat_ctx *nat);
void cli_cleanup(struct cli_ctx *ctx);
void cli_run(struct cli_ctx *ctx);
void cli_show_help(void);
void cli_show_rules(struct cli_ctx *ctx, const char *chain);
void cli_show_connections(struct cli_ctx *ctx);
void cli_show_nat(struct cli_ctx *ctx);
void cli_add_rule(struct cli_ctx *ctx, int argc, char **argv);
void cli_delete_rule(struct cli_ctx *ctx, int argc, char **argv);
void cli_add_nat_rule(struct cli_ctx *ctx, int argc, char **argv);

#endif
