#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <readline/readline.h>
#include <readline/history.h>
#include <arpa/inet.h>
#include "cli.h"

struct cli_ctx *cli_init(struct filter_ctx *filter, struct state_ctx *state, struct nat_ctx *nat) {
    struct cli_ctx *ctx;
    
    ctx = malloc(sizeof(struct cli_ctx));
    if (!ctx) return NULL;
    
    ctx->filter = filter;
    ctx->state = state;
    ctx->nat = nat;
    ctx->running = 1;
    
    return ctx;
}

void cli_cleanup(struct cli_ctx *ctx) {
    if (ctx) {
        free(ctx);
    }
}

void cli_show_help(void) {
    printf("\nFirewall CLI Commands:\n");
    printf("  help                          Show this help\n");
    printf("  show rules [chain]            Show firewall rules\n");
    printf("  show connections              Show active connections\n");
    printf("  show nat                      Show NAT rules and mappings\n");
    printf("  add rule <chain> <spec>       Add firewall rule\n");
    printf("  delete rule <chain> <id>      Delete firewall rule\n");
    printf("  add nat <type> <spec>         Add NAT rule\n");
    printf("  quit                          Exit CLI\n");
    printf("\nRule Examples:\n");
    printf("  add rule INPUT -p tcp --dport 22 -j ACCEPT\n");
    printf("  add rule FORWARD -s 192.168.1.0/24 -j DROP\n");
    printf("  add nat SNAT --to-source 1.2.3.4\n");
    printf("\n");
}

void cli_show_rules(struct cli_ctx *ctx, const char *chain) {
    if (!ctx || !ctx->filter) return;
    
    if (!chain || strcmp(chain, "INPUT") == 0) {
        printf("\n=== INPUT CHAIN ===\n");
        filter_dump_rules(ctx->filter, 0);
    }
    if (!chain || strcmp(chain, "OUTPUT") == 0) {
        printf("\n=== OUTPUT CHAIN ===\n");
        filter_dump_rules(ctx->filter, 1);
    }
    if (!chain || strcmp(chain, "FORWARD") == 0) {
        printf("\n=== FORWARD CHAIN ===\n");
        filter_dump_rules(ctx->filter, 2);
    }
}

void cli_show_connections(struct cli_ctx *ctx) {
    printf("Connection display not yet implemented\n");
}

void cli_show_nat(struct cli_ctx *ctx) {
    printf("NAT display not yet implemented\n");
}

void cli_add_rule(struct cli_ctx *ctx, int argc, char **argv) {
    printf("Rule addition via CLI not yet implemented\n");
}

void cli_delete_rule(struct cli_ctx *ctx, int argc, char **argv) {
    if (argc < 3) {
        printf("Usage: delete rule <chain> <rule_id>\n");
        return;
    }
    
    uint8_t chain;
    if (strcmp(argv[1], "INPUT") == 0) {
        chain = 0;
    } else if (strcmp(argv[1], "OUTPUT") == 0) {
        chain = 1;
    } else if (strcmp(argv[1], "FORWARD") == 0) {
        chain = 2;
    } else {
        printf("Invalid chain: %s\n", argv[1]);
        return;
    }
    
    uint32_t rule_id = atoi(argv[2]);
    if (filter_delete_rule(ctx->filter, chain, rule_id) == 0) {
        printf("Rule %d deleted from %s chain\n", rule_id, argv[1]);
    } else {
        printf("Failed to delete rule %d\n", rule_id);
    }
}

void cli_run(struct cli_ctx *ctx) {
    char *line;
    
    printf("Firewall CLI - Type 'help' for commands\n");
    
    while (ctx->running) {
        line = readline("firewall> ");
        if (!line) break;
        
        if (*line) {
            add_history(line);
        }
        
        char *argv[32];
        int argc = 0;
        char *token = strtok(line, " \t");
        
        while (token && argc < 31) {
            argv[argc++] = token;
            token = strtok(NULL, " \t");
        }
        argv[argc] = NULL;
        
        if (argc > 0) {
            if (strcmp(argv[0], "help") == 0) {
                cli_show_help();
            } else if (strcmp(argv[0], "show") == 0 && argc > 1) {
                if (strcmp(argv[1], "rules") == 0) {
                    cli_show_rules(ctx, argc > 2 ? argv[2] : NULL);
                } else if (strcmp(argv[1], "connections") == 0) {
                    cli_show_connections(ctx);
                } else if (strcmp(argv[1], "nat") == 0) {
                    cli_show_nat(ctx);
                }
            } else if (strcmp(argv[0], "delete") == 0 && argc > 1) {
                if (strcmp(argv[1], "rule") == 0) {
                    cli_delete_rule(ctx, argc, argv);
                }
            } else if (strcmp(argv[0], "quit") == 0 || strcmp(argv[0], "exit") == 0) {
                ctx->running = 0;
            } else {
                printf("Unknown command: %s\n", argv[0]);
            }
        }
        
        free(line);
    }
}
