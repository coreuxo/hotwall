#ifndef CLI_H
#define CLI_H

#include <stdio.h>
#include "../filter/filter.h"
#include "../state/state.h"
#include "../nat/nat.h"
#include "../ids/ids.h"
#include "../qos/qos.h"

struct cli_ctx {
    struct filter_ctx *filter;
    struct state_ctx *state;
    struct nat_ctx *nat;
    struct ids_ctx *ids;
    struct qos_ctx *qos;
    int running;
    char config_file[256];
};

struct cli_ctx *cli_init(struct filter_ctx *filter, struct state_ctx *state, 
                        struct nat_ctx *nat, struct ids_ctx *ids, struct qos_ctx *qos);
void cli_cleanup(struct cli_ctx *ctx);
void cli_run(struct cli_ctx *ctx);
void cli_process_command(struct cli_ctx *ctx, int argc, char **argv);
void cli_show_help(void);
void cli_show_status(struct cli_ctx *ctx);
void cli_show_rules(struct cli_ctx *ctx, char *chain);
void cli_show_connections(struct cli_ctx *ctx);
void cli_show_nat(struct cli_ctx *ctx);
void cli_show_ids(struct cli_ctx *ctx);
void cli_show_qos(struct cli_ctx *ctx);
void cli_add_rule(struct cli_ctx *ctx, int argc, char **argv);
void cli_delete_rule(struct cli_ctx *ctx, int argc, char **argv);
void cli_add_nat_rule(struct cli_ctx *ctx, int argc, char **argv);
void cli_add_ids_sig(struct cli_ctx *ctx, int argc, char **argv);
void cli_load_config(struct cli_ctx *ctx, char *filename);
void cli_save_config(struct cli_ctx *ctx, char *filename);

#endif
