#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <readline/readline.h>
#include <readline/history.h>
#include <arpa/inet.h>
#include "cli.h"

struct cli_ctx *cli_init(struct filter_ctx *filter, struct state_ctx *state, 
                        struct nat_ctx *nat, struct ids_ctx *ids, struct qos_ctx *qos) {
    struct cli_ctx *ctx;
    
    ctx = calloc(1, sizeof(struct cli_ctx));
    if (!ctx) return NULL;
    
    ctx->filter = filter;
    ctx->state = state;
    ctx->nat = nat;
    ctx->ids = ids;
    ctx->qos = qos;
    ctx->running = 1;
    strcpy(ctx->config_file, "/etc/firewall.conf");
    
    return ctx;
}

void cli_cleanup(struct cli_ctx *ctx) {
    if (ctx) free(ctx);
}

void cli_show_help(void) {
    printf("\nFirewall Management CLI\n");
    printf("=======================\n\n");
    
    printf("Status and Monitoring:\n");
    printf("  status                    Show firewall status\n");
    printf("  show rules [chain]        Show filtering rules\n");
    printf("  show connections          Show active connections\n");
    printf("  show nat                  Show NAT rules\n");
    printf("  show ids                  Show IDS signatures\n");
    printf("  show qos                  Show QoS statistics\n\n");
    
    printf("Rule Management:\n");
    printf("  add rule <chain> <spec>   Add firewall rule\n");
    printf("  delete rule <id>          Delete rule by ID\n");
    printf("  flush rules               Remove all rules\n\n");
    
    printf("NAT Management:\n");
    printf("  add nat <type> <spec>     Add NAT rule\n");
    printf("  delete nat <id>           Delete NAT rule\n\n");
    
    printf("IDS Management:\n");
    printf("  add ids <spec>            Add IDS signature\n");
    printf("  delete ids <id>           Delete IDS signature\n");
    printf("  ids enable|disable        Toggle IDS\n\n");
    
    printf("Configuration:\n");
    printf("  load [file]               Load configuration\n");
    printf("  save [file]               Save configuration\n");
    printf("  reload                    Reload configuration\n\n");
    
    printf("System:\n");
    printf("  quit, exit                Exit firewall\n");
    printf("  help                      Show this help\n\n");
    
    printf("Examples:\n");
    printf("  add rule INPUT -p tcp --dport 22 -j ACCEPT\n");
    printf("  add rule FORWARD -s 192.168.1.0/24 -j DROP\n");
    printf("  add nat SNAT --to-source 1.2.3.4\n");
    printf("  add ids --name xss --pattern '<script>' --proto http --dport 80\n");
}

void cli_show_status(struct cli_ctx *ctx) {
    if (!ctx) return;
    
    printf("\nFirewall Status\n");
    printf("===============\n");
    
    if (ctx->filter) {
        printf("Filter:      Enabled\n");
    } else {
        printf("Filter:      Disabled\n");
    }
    
    if (ctx->state) {
        printf("State:       Enabled\n");
    } else {
        printf("State:       Disabled\n");
    }
    
    if (ctx->nat) {
        printf("NAT:         Enabled\n");
    } else {
        printf("NAT:         Disabled\n");
    }
    
    if (ctx->ids && ctx->ids->enabled) {
        printf("IDS:         Enabled\n");
    } else {
        printf("IDS:         Disabled\n");
    }
    
    if (ctx->qos && ctx->qos->enabled) {
        printf("QoS:         Enabled\n");
    } else {
        printf("QoS:         Disabled\n");
    }
    
    printf("Config:      %s\n", ctx->config_file);
    printf("\n");
}

void cli_show_rules(struct cli_ctx *ctx, char *chain) {
    if (!ctx || !ctx->filter) return;
    
    if (!chain || strcmp(chain, "INPUT") == 0) {
        printf("\nINPUT Chain:\n");
        filter_dump_rules(ctx->filter, 0);
    }
    if (!chain || strcmp(chain, "OUTPUT") == 0) {
        printf("\nOUTPUT Chain:\n");
        filter_dump_rules(ctx->filter, 1);
    }
    if (!chain || strcmp(chain, "FORWARD") == 0) {
        printf("\nFORWARD Chain:\n");
        filter_dump_rules(ctx->filter, 2);
    }
}

void cli_show_connections(struct cli_ctx *ctx) {
    if (!ctx || !ctx->state) {
        printf("State tracking not available\n");
        return;
    }
    printf("Connection tracking active (%u connections)\n", 
           state_get_connection_count(ctx->state));
}

void cli_show_nat(struct cli_ctx *ctx) {
    if (!ctx || !ctx->nat) {
        printf("NAT not available\n");
        return;
    }
    printf("NAT engine active\n");
}

void cli_show_ids(struct cli_ctx *ctx) {
    if (!ctx || !ctx->ids) {
        printf("IDS not available\n");
        return;
    }
    ids_dump_sigs(ctx->ids);
}

void cli_show_qos(struct cli_ctx *ctx) {
    if (!ctx || !ctx->qos) {
        printf("QoS not available\n");
        return;
    }
    qos_dump_stats(ctx->qos);
}

void cli_add_rule(struct cli_ctx *ctx, int argc, char **argv) {
    struct rule r;
    uint8_t chain;
    int i;
    
    if (argc < 4) {
        printf("Usage: add rule <chain> <options>\n");
        return;
    }
    
    if (strcmp(argv[2], "INPUT") == 0) {
        chain = 0;
    } else if (strcmp(argv[2], "OUTPUT") == 0) {
        chain = 1;
    } else if (strcmp(argv[2], "FORWARD") == 0) {
        chain = 2;
    } else {
        printf("Invalid chain: %s\n", argv[2]);
        return;
    }
    
    memset(&r, 0, sizeof(r));
    r.direction = chain;
    r.enabled = 1;
    
    for (i = 3; i < argc; i++) {
        if (strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--proto") == 0) {
            if (++i >= argc) goto error;
            if (strcmp(argv[i], "tcp") == 0) r.protocol = 6;
            else if (strcmp(argv[i], "udp") == 0) r.protocol = 17;
            else if (strcmp(argv[i], "icmp") == 0) r.protocol = 1;
            else if (strcmp(argv[i], "any") == 0) r.protocol = 0;
            else r.protocol = atoi(argv[i]);
        } else if (strcmp(argv[i], "-s") == 0 || strcmp(argv[i], "--source") == 0) {
            if (++i >= argc) goto error;
            char *slash = strchr(argv[i], '/');
            if (slash) {
                *slash = '\0';
                r.src_mask = inet_addr("255.255.255.255") >> (32 - atoi(slash + 1));
            }
            r.src_ip = inet_addr(argv[i]);
        } else if (strcmp(argv[i], "-d") == 0 || strcmp(argv[i], "--dest") == 0) {
            if (++i >= argc) goto error;
            char *slash = strchr(argv[i], '/');
            if (slash) {
                *slash = '\0';
                r.dst_mask = inet_addr("255.255.255.255") >> (32 - atoi(slash + 1));
            }
            r.dst_ip = inet_addr(argv[i]);
        } else if (strcmp(argv[i], "--sport") == 0) {
            if (++i >= argc) goto error;
            r.src_port_start = atoi(argv[i]);
            r.src_port_end = r.src_port_start;
        } else if (strcmp(argv[i], "--dport") == 0) {
            if (++i >= argc) goto error;
            r.dst_port_start = atoi(argv[i]);
            r.dst_port_end = r.dst_port_start;
        } else if (strcmp(argv[i], "-j") == 0 || strcmp(argv[i], "--jump") == 0) {
            if (++i >= argc) goto error;
            if (strcmp(argv[i], "ACCEPT") == 0) r.action = 0;
            else if (strcmp(argv[i], "DROP") == 0) r.action = 1;
            else if (strcmp(argv[i], "REJECT") == 0) r.action = 2;
            else if (strcmp(argv[i], "LOG") == 0) r.action = 3;
        } else if (strcmp(argv[i], "--log") == 0) {
            r.log = 1;
        }
    }
    
    if (filter_add_rule(ctx->filter, chain, &r) == 0) {
        printf("Rule added to %s chain\n", argv[2]);
    } else {
        printf("Failed to add rule\n");
    }
    return;

error:
    printf("Invalid rule syntax\n");
}

void cli_delete_rule(struct cli_ctx *ctx, int argc, char **argv) {
    uint32_t rule_id;
    
    if (argc < 3) {
        printf("Usage: delete rule <rule_id>\n");
        return;
    }
    
    rule_id = atoi(argv[2]);
    
    if (filter_delete_rule(ctx->filter, 0, rule_id) == 0 ||
        filter_delete_rule(ctx->filter, 1, rule_id) == 0 ||
        filter_delete_rule(ctx->filter, 2, rule_id) == 0) {
        printf("Rule %d deleted\n", rule_id);
    } else {
        printf("Rule %d not found\n", rule_id);
    }
}

void cli_add_nat_rule(struct cli_ctx *ctx, int argc, char **argv) {
    printf("NAT rule addition via CLI not yet implemented\n");
}

void cli_add_ids_sig(struct cli_ctx *ctx, int argc, char **argv) {
    printf("IDS signature addition via CLI not yet implemented\n");
}

void cli_load_config(struct cli_ctx *ctx, char *filename) {
    if (filename) {
        strncpy(ctx->config_file, filename, sizeof(ctx->config_file) - 1);
    }
    printf("Loading configuration from %s\n", ctx->config_file);
}

void cli_save_config(struct cli_ctx *ctx, char *filename) {
    if (filename) {
        strncpy(ctx->config_file, filename, sizeof(ctx->config_file) - 1);
    }
    printf("Saving configuration to %s\n", ctx->config_file);
}

void cli_process_command(struct cli_ctx *ctx, int argc, char **argv) {
    if (argc == 0) return;
    
    if (strcmp(argv[0], "help") == 0) {
        cli_show_help();
    } else if (strcmp(argv[0], "status") == 0) {
        cli_show_status(ctx);
    } else if (strcmp(argv[0], "show") == 0 && argc > 1) {
        if (strcmp(argv[1], "rules") == 0) {
            cli_show_rules(ctx, argc > 2 ? argv[2] : NULL);
        } else if (strcmp(argv[1], "connections") == 0) {
            cli_show_connections(ctx);
        } else if (strcmp(argv[1], "nat") == 0) {
            cli_show_nat(ctx);
        } else if (strcmp(argv[1], "ids") == 0) {
            cli_show_ids(ctx);
        } else if (strcmp(argv[1], "qos") == 0) {
            cli_show_qos(ctx);
        }
    } else if (strcmp(argv[0], "add") == 0 && argc > 1) {
        if (strcmp(argv[1], "rule") == 0) {
            cli_add_rule(ctx, argc, argv);
        } else if (strcmp(argv[1], "nat") == 0) {
            cli_add_nat_rule(ctx, argc, argv);
        } else if (strcmp(argv[1], "ids") == 0) {
            cli_add_ids_sig(ctx, argc, argv);
        }
    } else if (strcmp(argv[0], "delete") == 0 && argc > 1) {
        if (strcmp(argv[1], "rule") == 0) {
            cli_delete_rule(ctx, argc, argv);
        }
    } else if (strcmp(argv[0], "load") == 0) {
        cli_load_config(ctx, argc > 1 ? argv[1] : NULL);
    } else if (strcmp(argv[0], "save") == 0) {
        cli_save_config(ctx, argc > 1 ? argv[1] : NULL);
    } else if (strcmp(argv[0], "reload") == 0) {
        cli_load_config(ctx, NULL);
    } else if (strcmp(argv[0], "ids") == 0 && argc > 1) {
        if (ctx->ids) {
            if (strcmp(argv[1], "enable") == 0) {
                ctx->ids->enabled = 1;
                printf("IDS enabled\n");
            } else if (strcmp(argv[1], "disable") == 0) {
                ctx->ids->enabled = 0;
                printf("IDS disabled\n");
            }
        }
    } else if (strcmp(argv[0], "quit") == 0 || strcmp(argv[0], "exit") == 0) {
        ctx->running = 0;
    } else {
        printf("Unknown command: %s\n", argv[0]);
    }
}

void cli_run(struct cli_ctx *ctx) {
    char *line;
    
    printf("Firewall CLI - Type 'help' for commands\n");
    
    while (ctx->running) {
        line = readline("fw> ");
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
            cli_process_command(ctx, argc, argv);
        }
        
        free(line);
    }
}
