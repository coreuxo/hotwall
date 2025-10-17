#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include "firewall.h"
#include "capture/capture.h"

static volatile int running = 1;

void sig_handler(int sig) {
    running = 0;
}

void print_banner(void) {
    printf("Firewall v0.1 - starting up...\n");
    printf("PID: %d\n", getpid());
}

static int handle_packet(struct packet_info *pkt, void *user_data) {
    /* just print basic info for now */
    char src_ip[16], dst_ip[16];
    
    inet_ntop(AF_INET, &pkt->src_ip, src_ip, sizeof(src_ip));
    inet_ntop(AF_INET, &pkt->dst_ip, dst_ip, sizeof(dst_ip));
    
    printf("%s %s:%d -> %s:%d proto=%d len=%d\n",
           protocol_str(pkt->protocol),
           src_ip, pkt->src_port,
           dst_ip, pkt->dst_port,
           pkt->protocol, pkt->len);
    
    return 0;
}

int main(int argc, char *argv[]) {
    struct firewall_ctx *ctx;
    
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
    
    /* temp: test packet capture */
    struct capture_ctx *cap = capture_init("eth0", 1, 1000);
    if (cap) {
        printf("Starting packet capture on eth0...\n");
        capture_start(cap, handle_packet, NULL);
        capture_cleanup(cap);
    }
    
    while (running) {
        sleep(1);
    }
    
    printf("Shutting down firewall...\n");
    firewall_stop(ctx);
    firewall_cleanup(ctx);
    
    return 0;
}
