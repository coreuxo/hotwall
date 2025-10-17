#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include "firewall.h"
#include "capture/capture.h"
#include "filter/filter.h"

static volatile int running = 1;
static struct capture_ctx *capture_ctx = NULL;
static struct filter_ctx *filter_ctx = NULL;

void sig_handler(int sig) {
    running = 0;
    if (capture_ctx) {
        capture_stop(capture_ctx);
    }
}

void print_banner(void) {
    printf("Firewall v0.1 - starting up...\n");
    printf("PID: %d\n", getpid());
}

static void add_sample_rules(void) {
    struct rule r;
    
    /* drop all incoming traffic on port 23 (telnet) */
    memset(&r, 0, sizeof(r));
    r.action = RULE_ACTION_DROP;
    r.direction = RULE_DIR_IN;
    r.protocol = PROTO_TCP;
    r.dst_port_start = 23;
    r.dst_port_end = 23;
    r.enabled = 1;
    r.log = 1;
    filter_add_rule(filter_ctx, RULE_DIR_IN, &r);
    
    /* allow established connections */
    memset(&r, 0, sizeof(r));
    r.action = RULE_ACTION_ACCEPT;
    r.direction = RULE_DIR_IN;
    r.protocol = PROTO_TCP;
    r.enabled = 1;
    filter_add_rule(filter_ctx, RULE_DIR_IN, &r);
    
    printf("Added sample rules\n");
}

static int handle_packet(struct packet_info *pkt, void *user_data) {
    char src_ip[16], dst_ip[16];
    static uint64_t packet_count = 0;
    int action;
    
    packet_count++;
    
    inet_ntop(AF_INET, &pkt->src_ip, src_ip, sizeof(src_ip));
    inet_ntop(AF_INET, &pkt->dst_ip, dst_ip, sizeof(dst_ip));
    
    if (filter_ctx) {
        action = filter_packet(filter_ctx, pkt);
        
        const char *action_str;
        switch (action) {
            case RULE_ACTION_ACCEPT: action_str = "ACCEPT"; break;
            case RULE_ACTION_DROP: action_str = "DROP"; break;
            case RULE_ACTION_REJECT: action_str = "REJECT"; break;
            default: action_str = "UNKNOWN"; break;
        }
        
        printf("[%lu] %s %s:%d -> %s:%d proto=%d len=%d [%s]\n",
               packet_count,
               protocol_str(pkt->protocol),
               src_ip, pkt->src_port,
               dst_ip, pkt->dst_port,
               pkt->protocol, pkt->len, action_str);
               
        return action; /* return the action for potential packet dropping */
    } else {
        printf("[%lu] %s %s:%d -> %s:%d proto=%d len=%d\n",
               packet_count,
               protocol_str(pkt->protocol),
               src_ip, pkt->src_port,
               dst_ip, pkt->dst_port,
               pkt->protocol, pkt->len);
    }
    
    return RULE_ACTION_ACCEPT;
}

int main(int argc, char *argv[]) {
    struct firewall_ctx *ctx;
    const char *iface = "eth0";
    
    if (argc > 1) {
        iface = argv[1];
    }
    
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    
    print_banner();
    
    /* init filter engine */
    filter_ctx = filter_init();
    if (!filter_ctx) {
        fprintf(stderr, "Failed to initialize filter engine\n");
        return 1;
    }
    
    /* add some sample rules */
    add_sample_rules();
    
    ctx = firewall_init();
    if (!ctx) {
        fprintf(stderr, "Failed to initialize firewall\n");
        filter_cleanup(filter_ctx);
        return 1;
    }
    
    if (firewall_start(ctx) != 0) {
        fprintf(stderr, "Failed to start firewall\n");
        firewall_cleanup(ctx);
        filter_cleanup(filter_ctx);
        return 1;
    }
    
    /* test packet capture */
    capture_ctx = capture_init(iface, 1, 100);
    if (capture_ctx) {
        printf("Starting packet capture on %s...\n", iface);
        printf("Current rules:\n");
        filter_dump_rules(filter_ctx, RULE_DIR_IN);
        printf("\n");
        capture_start(capture_ctx, handle_packet, NULL);
        capture_cleanup(capture_ctx);
        capture_ctx = NULL;
    } else {
        fprintf(stderr, "Failed to initialize capture on %s\n", iface);
    }
    
    while (running) {
        sleep(1);
    }
    
    printf("\nFirewall statistics:\n");
    printf("Total packets: %lu\n", filter_ctx->total_packets);
    printf("Total bytes: %lu\n", filter_ctx->total_bytes);
    printf("Accepted: %lu\n", filter_ctx->accepted_packets);
    printf("Dropped: %lu\n", filter_ctx->dropped_packets);
    
    printf("Shutting down firewall...\n");
    firewall_stop(ctx);
    firewall_cleanup(ctx);
    filter_cleanup(filter_ctx);
    
    return 0;
}
