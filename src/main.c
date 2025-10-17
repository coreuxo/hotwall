#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include "firewall.h"

static volatile int running = 1;

void sig_handler(int sig) {
    running = 0;
}

void print_banner(void) {
    printf("Firewall v0.1 - starting up...\n");
    printf("PID: %d\n", getpid());
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
    
    while (running) {
        sleep(1);
    }
    
    printf("Shutting down firewall...\n");
    firewall_stop(ctx);
    firewall_cleanup(ctx);
    
    return 0;
}
