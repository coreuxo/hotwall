#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <sys/select.h>
#include <termios.h>
#include "firewall.h"
#include "capture/capture.h"
#include "filter/filter.h"
#include "state/state.h"
#include "nat/nat.h"
#include "ids/ids.h"
#include "qos/qos.h"
#include "worker/worker.h"
#include "cli/cli.h"
#include "config/parser.h"
#include "log/log.h"

static volatile int running = 1;
static struct firewall_ctx *fw_ctx = NULL;

void sig_handler(int sig) {
    running = 0;
    if (fw_ctx) {
        firewall_stop(fw_ctx);
    }
}

void print_banner(void) {
    printf("\n");
    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║                   FIREWALL v1.0 - PRODUCTION                ║\n");
    printf("║                 Built: %s %s              ║\n", __DATE__, __TIME__);
    printf("║                      PID: %d                                ║\n", getpid());
    printf("╚══════════════════════════════════════════════════════════════╝\n");
    printf("\n");
}

void print_usage(void) {
    printf("Usage: firewall [interface] [options]\n");
    printf("Options:\n");
    printf("  -d, --debug          Enable debug output\n");
    printf("  -p, --promisc        Disable promiscuous mode\n");
    printf("  -c, --config FILE    Load configuration file\n");
    printf("  -C, --cli            Start CLI interface\n");
    printf("  -h, --help           Show this help\n");
    printf("\n");
}

int kbhit(void) {
    struct timeval tv = {0L, 0L};
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(0, &fds);
    return select(1, &fds, NULL, NULL, &tv);
}

int getch(void) {
    struct termios oldt, newt;
    int ch;
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~(ICANON | ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    ch = getchar();
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    return ch;
}

void show_rules(struct firewall_ctx *ctx) {
    if (!ctx || !ctx->filter) return;
    
    printf("\n=== INPUT CHAIN ===\n");
    filter_dump_rules(ctx->filter, 0);
    printf("\n=== OUTPUT CHAIN ===\n");
    filter_dump_rules(ctx->filter, 1);
    printf("\n=== FORWARD CHAIN ===\n");
    filter_dump_rules(ctx->filter, 2);
}

void show_statistics(struct firewall_ctx *ctx) {
    if (!ctx) return;
    
    printf("\n=== FIREWALL STATISTICS ===\n");
    printf("Total packets:    %lu\n", firewall_get_stats(ctx, 0));
    printf("Dropped packets:  %lu\n", firewall_get_stats(ctx, 1));
    printf("Rejected packets: %lu\n", firewall_get_stats(ctx, 2));
    printf("Injected packets: %lu\n", firewall_get_stats(ctx, 3));
    printf("NAT packets:      %lu\n", firewall_get_stats(ctx, 4));
    printf("Worker packets:   %lu\n", firewall_get_stats(ctx, 5));
    printf("IDS alerts:       %lu\n", firewall_get_stats(ctx, 7));
    printf("QoS drops:        %lu\n", firewall_get_stats(ctx, 8));
    
    if (ctx->state) {
        printf("Active connections: %u\n", state_get_connection_count(ctx->state));
    }
    
    uint64_t accepted = firewall_get_stats(ctx, 0) - firewall_get_stats(ctx, 1) - firewall_get_stats(ctx, 2);
    printf("Accepted packets: %lu (%.1f%%)\n", accepted, 
           firewall_get_stats(ctx, 0) > 0 ? (accepted * 100.0) / firewall_get_stats(ctx, 0) : 0.0);
    printf("============================\n");
}

void add_default_rules(struct firewall_ctx *ctx) {
    struct rule r;
    
    if (!ctx || !ctx->filter) return;
    
    memset(&r, 0, sizeof(r));
    r.action = RULE_ACTION_ACCEPT;
    r.direction = RULE_DIR_IN;
    r.protocol = PROTO_ANY;
    r.enabled = 1;
    filter_add_rule(ctx->filter, RULE_DIR_IN, &r);
    
    memset(&r, 0, sizeof(r));
    r.action = RULE_ACTION_ACCEPT;
    r.direction = RULE_DIR_IN;
    r.protocol = PROTO_TCP;
    r.dst_port_start = 22;
    r.dst_port_end = 22;
    r.enabled = 1;
    filter_add_rule(ctx->filter, RULE_DIR_IN, &r);
    
    memset(&r, 0, sizeof(r));
    r.action = RULE_ACTION_ACCEPT;
    r.direction = RULE_DIR_IN;
    r.protocol = PROTO_TCP;
    r.dst_port_start = 80;
    r.dst_port_end = 80;
    r.enabled = 1;
    filter_add_rule(ctx->filter, RULE_DIR_IN, &r);
    
    memset(&r, 0, sizeof(r));
    r.action = RULE_ACTION_ACCEPT;
    r.direction = RULE_DIR_IN;
    r.protocol = PROTO_TCP;
    r.dst_port_start = 443;
    r.dst_port_end = 443;
    r.enabled = 1;
    filter_add_rule(ctx->filter, RULE_DIR_IN, &r);
    
    memset(&r, 0, sizeof(r));
    r.action = RULE_ACTION_DROP;
    r.direction = RULE_DIR_IN;
    r.protocol = PROTO_ANY;
    r.enabled = 1;
    r.log = 1;
    filter_add_rule(ctx->filter, RULE_DIR_IN, &r);
    
    printf("Added default rule set\n");
}

static int packet_handler(struct packet_info *pkt, void *user_data) {
    return 0;
}

void *capture_loop(void *arg) {
    struct firewall_ctx *ctx = (struct firewall_ctx *)arg;
    
    if (!ctx || !ctx->capture) {
        return NULL;
    }
    
    printf("Starting packet capture loop...\n");
    capture_start(ctx->capture, packet_handler, ctx);
    printf("Packet capture loop ended\n");
    
    return NULL;
}

int main(int argc, char *argv[]) {
    pthread_t capture_thread;
    const char *iface = "eth0";
    const char *config_file = NULL;
    int promisc = 1;
    int debug = 0;
    int cli_mode = 0;
    int i;
    
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage();
            return 0;
        } else if (strcmp(argv[i], "-d") == 0 || strcmp(argv[i], "--debug") == 0) {
            debug = 1;
        } else if (strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--promisc") == 0) {
            promisc = 0;
        } else if (strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--config") == 0) {
            if (++i < argc) config_file = argv[i];
        } else if (strcmp(argv[i], "-C") == 0 || strcmp(argv[i], "--cli") == 0) {
            cli_mode = 1;
        } else if (argv[i][0] != '-') {
            iface = argv[i];
        }
    }
    
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    
    print_banner();
    printf("Interface: %s, Promiscuous: %s, Debug: %s\n", 
           iface, promisc ? "enabled" : "disabled", debug ? "enabled" : "disabled");
    
    fw_ctx = firewall_init();
    if (!fw_ctx) {
        fprintf(stderr, "ERROR: Failed to initialize firewall\n");
        return 1;
    }
    
    add_default_rules(fw_ctx);
    
    if (config_file) {
        printf("Loading configuration from %s\n", config_file);
    }
    
    fw_ctx->capture = capture_init(iface, promisc, 100);
    if (!fw_ctx->capture) {
        fprintf(stderr, "ERROR: Failed to initialize capture on %s\n", iface);
        firewall_cleanup(fw_ctx);
        return 1;
    }
    
    if (pthread_create(&capture_thread, NULL, capture_loop, fw_ctx) != 0) {
        fprintf(stderr, "ERROR: Failed to create capture thread\n");
        firewall_cleanup(fw_ctx);
        return 1;
    }
    
    if (cli_mode) {
        struct cli_ctx *cli = cli_init(fw_ctx->filter, fw_ctx->state, fw_ctx->nat, fw_ctx->ids, fw_ctx->qos);
        if (cli) {
            cli_run(cli);
            cli_cleanup(cli);
        }
    } else {
        printf("\nFirewall started successfully. Controls: r=rules, s=stats, q=quit\n");
        
        while (running) {
            if (kbhit()) {
                int ch = getch();
                switch (ch) {
                    case 'r':
                    case 'R':
                        show_rules(fw_ctx);
                        break;
                    case 's':
                    case 'S':
                        show_statistics(fw_ctx);
                        break;
                    case 'q':
                    case 'Q':
                        running = 0;
                        break;
                    case '\n':
                        break;
                    default:
                        printf("Unknown command: '%c' (0x%02x)\n", ch, ch);
                        printf("Controls: r=rules, s=stats, q=quit\n");
                        break;
                }
            }
            
            static time_t last_stats = 0;
            time_t now = time(NULL);
            if (now - last_stats >= 30) {
                show_statistics(fw_ctx);
                last_stats = now;
            }
            
            usleep(100000);
        }
    }
    
    printf("\nShutting down firewall...\n");
    
    if (fw_ctx->capture) {
        capture_stop(fw_ctx->capture);
    }
    
    pthread_join(capture_thread, NULL);
    
    show_statistics(fw_ctx);
    
    firewall_cleanup(fw_ctx);
    fw_ctx = NULL;
    
    printf("Firewall shutdown complete.\n");
    return 0;
}
