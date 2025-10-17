#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include "firewall.h"
#include "capture/capture.h"

static volatile int running = 1;
static struct capture_ctx *capture_ctx = NULL;

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

static int handle_packet(struct packet_info *pkt, void *user_data) {
    char src_ip[16], dst_ip[16];
    static uint64_t packet_count = 0;
    
    packet_count++;
    
    inet_ntop(AF_INET, &pkt->src_ip, src_ip, sizeof(src_ip));
    inet_ntop(AF_INET, &pkt->dst_ip, dst_ip, sizeof(dst_ip));
    
    printf("[%lu] %s %s:%d -> %s:%d proto=%d len=%d\n",
           packet_count,
           protocol_str(pkt->protocol),
           src_ip, pkt->src_port,
           dst_ip, pkt->dst_port,
           pkt->protocol, pkt->len);
    
    return 0;
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
    
    ctx = firewall_init();
    if (!ctx) {
        fprintf(stderr, "Failed to initialize firewall\n");
        return 1;
    }
    
    if (firewall_start(ctx) != 0) {
        fprintf(stderr, "Failed to start firewall\n");
        firewall_cleanup(ctx);
        return 1;
    }
    
    /* test packet capture */
    capture_ctx = capture_init(iface, 1, 100);
    if (capture_ctx) {
        printf("Starting packet capture on %s...\n", iface);
        capture_start(capture_ctx, handle_packet, NULL);
        capture_cleanup(capture_ctx);
        capture_ctx = NULL;
    } else {
        fprintf(stderr, "Failed to initialize capture on %s\n", iface);
    }
    
    while (running) {
        sleep(1);
    }
    
    printf("Shutting down firewall...\n");
    firewall_stop(ctx);
    firewall_cleanup(ctx);
    
    return 0;
}
