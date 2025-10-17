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
    printf("║                   FIREWALL v0.1_drop - DEV                   ║\n");
    printf("║                 Built: %s %s              ║\n", __DATE__, __TIME__);
    printf("║                      PID: %d                                ║\n", getpid());
    printf("╚══════════════════════════════════════════════════════════════╝\n");
    printf("\n");
}

void print_usage(void) {
    printf("Usage: firewall [interface] [options]\n");
    printf("Options:\n");
    printf("  -d, --debug     Enable debug output\n");
    printf("  -p, --promisc   Disable promiscuous mode\n");
    printf("  -h, --help      Show this help\n");
    printf("\n");
    printf("Controls:\n");
    printf("  r - Show rules\n");
    printf("  s - Show statistics\n");
    printf("  c - Show connections\n");
    printf("  q - Quit\n");
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
    printf("Total packets:    %lu\n", ctx->stats_total_packets);
    printf("Dropped packets:  %lu\n", ctx->stats_dropped_packets);
    printf("Rejected packets: %lu\n", ctx->stats_rejected_packets);
    printf("Injected packets: %lu\n", ctx->stats_injected_packets);
    
    if (ctx->state) {
        printf("Active connections: %u\n", state_get_connection_count(ctx->state));
    }
    
    uint64_t accepted = ctx->stats_total_packets - ctx->stats_dropped_packets - ctx->stats_rejected_packets;
    printf("Accepted packets: %lu (%.1f%%)\n", accepted, 
           ctx->stats_total_packets > 0 ? (accepted * 100.0) / ctx->stats_total_packets : 0.0);
    printf("============================\n");
}

void show_connections(struct firewall_ctx *ctx) {
    /* This would dump the connection table */
    printf("\nConnection table dump not yet implemented\n");
}

void add_default_rules(struct firewall_ctx *ctx) {
    struct rule r;
    
    if (!ctx || !ctx->filter) return;
    
    /* Drop invalid packets */
    memset(&r, 0, sizeof(r));
    r.action = RULE_ACTION_DROP;
    r.direction = RULE_DIR_IN;
    r.protocol = PROTO_ANY;
    r.enabled = 1;
    r.log = 0;
    filter_add_rule(ctx->filter, RULE_DIR_IN, &r);
    
    /* Allow loopback */
    memset(&r, 0, sizeof(r));
    r.action = RULE_ACTION_ACCEPT;
    r.direction = RULE_DIR_IN;
    r.protocol = PROTO_ANY;
    r.src_ip = inet_addr("127.0.0.1");
    r.src_mask = inet_addr("255.0.0.0");
    r.enabled = 1;
    filter_add_rule(ctx->filter, RULE_DIR_IN, &r);
    
    /* Allow established connections */
    memset(&r, 0, sizeof(r));
    r.action = RULE_ACTION_ACCEPT;
    r.direction = RULE_DIR_IN;
    r.protocol = PROTO_TCP;
    r.enabled = 1;
    filter_add_rule(ctx->filter, RULE_DIR_IN, &r);
    
    /* Allow related UDP traffic */
    memset(&r, 0, sizeof(r));
    r.action = RULE_ACTION_ACCEPT;
    r.direction = RULE_DIR_IN;
    r.protocol = PROTO_UDP;
    r.enabled = 1;
    filter_add_rule(ctx->filter, RULE_DIR_IN, &r);
    
    /* Allow ICMP */
    memset(&r, 0, sizeof(r));
    r.action = RULE_ACTION_ACCEPT;
    r.direction = RULE_DIR_IN;
    r.protocol = PROTO_ICMP;
    r.enabled = 1;
    filter_add_rule(ctx->filter, RULE_DIR_IN, &r);
    
    /* Drop telnet */
    memset(&r, 0, sizeof(r));
    r.action = RULE_ACTION_DROP;
    r.direction = RULE_DIR_IN;
    r.protocol = PROTO_TCP;
    r.dst_port_start = 23;
    r.dst_port_end = 23;
    r.enabled = 1;
    r.log = 1;
    filter_add_rule(ctx->filter, RULE_DIR_IN, &r);
    
    /* Drop netbios */
    memset(&r, 0, sizeof(r));
    r.action = RULE_ACTION_DROP;
    r.direction = RULE_DIR_IN;
    r.protocol = PROTO_TCP;
    r.dst_port_start = 135;
    r.dst_port_end = 139;
    r.enabled = 1;
    filter_add_rule(ctx->filter, RULE_DIR_IN, &r);
    
    /* Default drop for input */
    memset(&r, 0, sizeof(r));
    r.action = RULE_ACTION_DROP;
    r.direction = RULE_DIR_IN;
    r.protocol = PROTO_ANY;
    r.enabled = 1;
    r.log = 1;
    filter_add_rule(ctx->filter, RULE_DIR_IN, &r);
    
    /* Default accept for output */
    memset(&r, 0, sizeof(r));
    r.action = RULE_ACTION_ACCEPT;
    r.direction = RULE_DIR_OUT;
    r.protocol = PROTO_ANY;
    r.enabled = 1;
    filter_add_rule(ctx->filter, RULE_DIR_OUT, &r);
    
    printf("Added default rule set\n");
}

static int packet_handler(struct packet_info *pkt, void *user_data) {
    struct firewall_ctx *ctx = (struct firewall_ctx *)user_data;
    static uint64_t pkt_count = 0;
    int action = RULE_ACTION_ACCEPT;
    char src_ip[16], dst_ip[16];
    
    if (!ctx || !pkt) return 0;
    
    pkt_count++;
    ctx->stats_total_packets++;
    
    inet_ntop(AF_INET, &pkt->src_ip, src_ip, sizeof(src_ip));
    inet_ntop(AF_INET, &pkt->dst_ip, dst_ip, sizeof(dst_ip));
    
    /* Update state tracking */
    if (ctx->state) {
        state_process_packet(ctx->state, pkt);
    }
    
    /* Apply filtering rules */
    if (ctx->filter) {
        action = filter_packet(ctx->filter, pkt);
    }
    
    /* Handle packet actions */
    switch (action) {
        case RULE_ACTION_ACCEPT:
            /* Let packet through */
            break;
            
        case RULE_ACTION_DROP:
            ctx->stats_dropped_packets++;
            if (pkt_count % 100 == 0) {
                printf("[%lu] DROP %s %s:%d -> %s:%d proto=%d\n",
                       pkt_count, protocol_str(pkt->protocol),
                       src_ip, pkt->src_port, dst_ip, pkt->dst_port, pkt->protocol);
            }
            return 1;
            
        case RULE_ACTION_REJECT:
            ctx->stats_rejected_packets++;
            if (ctx->inject) {
                if (pkt->is_tcp && pkt->tcp) {
                    inject_tcp_rst(ctx->inject, pkt->dst_ip, pkt->src_ip,
                                  pkt->dst_port, pkt->src_port,
                                  ntohl(pkt->tcp->ack_seq),
                                  ntohl(pkt->tcp->seq) + 1);
                    ctx->stats_injected_packets++;
                }
            }
            if (pkt_count % 100 == 0) {
                printf("[%lu] REJECT %s %s:%d -> %s:%d proto=%d\n",
                       pkt_count, protocol_str(pkt->protocol),
                       src_ip, pkt->src_port, dst_ip, pkt->dst_port, pkt->protocol);
            }
            return 1;
            
        case RULE_ACTION_LOG:
            /* Log and accept */
            printf("[%lu] LOG %s %s:%d -> %s:%d proto=%d len=%d\n",
                   pkt_count, protocol_str(pkt->protocol),
                   src_ip, pkt->src_port, dst_ip, pkt->dst_port, pkt->protocol, pkt->len);
            break;
    }
    
    /* Only print every 100 packets to avoid flooding */
    if (pkt_count % 100 == 0) {
        printf("[%lu] %s %s:%d -> %s:%d proto=%d len=%d\n",
               pkt_count, protocol_str(pkt->protocol),
               src_ip, pkt->src_port, dst_ip, pkt->dst_port, pkt->protocol, pkt->len);
    }
    
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
    int promisc = 1;
    int debug = 0;
    int i;
    
    /* Parse command line arguments */
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage();
            return 0;
        } else if (strcmp(argv[i], "-d") == 0 || strcmp(argv[i], "--debug") == 0) {
            debug = 1;
        } else if (strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--promisc") == 0) {
            promisc = 0;
        } else if (argv[i][0] != '-') {
            iface = argv[i];
        }
    }
    
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    
    print_banner();
    printf("Interface: %s, Promiscuous: %s, Debug: %s\n", 
           iface, promisc ? "enabled" : "disabled", debug ? "enabled" : "disabled");
    
    /* Initialize firewall */
    fw_ctx = firewall_init();
    if (!fw_ctx) {
        fprintf(stderr, "ERROR: Failed to initialize firewall\n");
        return 1;
    }
    
    /* Add default rules */
    add_default_rules(fw_ctx);
    
    /* Initialize packet capture */
    fw_ctx->capture = capture_init(iface, promisc, 100);
    if (!fw_ctx->capture) {
        fprintf(stderr, "ERROR: Failed to initialize capture on %s\n", iface);
        firewall_cleanup(fw_ctx);
        return 1;
    }
    
    /* Start capture thread */
    if (pthread_create(&capture_thread, NULL, capture_loop, fw_ctx) != 0) {
        fprintf(stderr, "ERROR: Failed to create capture thread\n");
        firewall_cleanup(fw_ctx);
        return 1;
    }
    
    printf("\nFirewall started successfully. Controls: r=rules, s=stats, c=conns, q=quit\n");
    
    /* Main control loop */
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
                case 'c':
                case 'C':
                    show_connections(fw_ctx);
                    break;
                case 'q':
                case 'Q':
                    running = 0;
                    break;
                case '\n':
                    break;
                default:
                    printf("Unknown command: '%c' (0x%02x)\n", ch, ch);
                    printf("Controls: r=rules, s=stats, c=conns, q=quit\n");
                    break;
            }
        }
        
        /* Print stats every 30 seconds */
        static time_t last_stats = 0;
        time_t now = time(NULL);
        if (now - last_stats >= 30) {
            show_statistics(fw_ctx);
            last_stats = now;
        }
        
        usleep(100000); /* 100ms */
    }
    
    /* Shutdown */
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
