#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include "firewall.h"
#include "capture/capture.h"
#include "capture/inject.h"
#include "filter/filter.h"
#include "state/state.h"
#include "log/log.h"

struct firewall_ctx {
    struct capture_ctx *capture;
    struct inject_ctx *inject;
    struct filter_ctx *filter;
    struct state_ctx *state;
    struct log_ctx *logger;
    
    pthread_t capture_thread;
    pthread_t cleanup_thread;
    
    volatile int running;
    char iface[16];
    
    uint64_t stats_total_packets;
    uint64_t stats_dropped_packets;
    uint64_t stats_rejected_packets;
    uint64_t stats_injected_packets;
};

static struct firewall_ctx *g_ctx = NULL;

static void *capture_thread_func(void *arg) {
    struct firewall_ctx *ctx = (struct firewall_ctx *)arg;
    
    if (!ctx || !ctx->capture) {
        return NULL;
    }
    
    printf("Capture thread started on %s\n", ctx->iface);
    
    while (ctx->running) {
        /* This would normally process packets */
        usleep(100000); /* 100ms */
    }
    
    printf("Capture thread stopped\n");
    return NULL;
}

static void *cleanup_thread_func(void *arg) {
    struct firewall_ctx *ctx = (struct firewall_ctx *)arg;
    
    if (!ctx) {
        return NULL;
    }
    
    printf("Cleanup thread started\n");
    
    while (ctx->running) {
        if (ctx->state) {
            state_cleanup_old(ctx->state);
        }
        sleep(30); /* Cleanup every 30 seconds */
    }
    
    printf("Cleanup thread stopped\n");
    return NULL;
}

static int firewall_packet_handler(struct packet_info *pkt, void *user_data) {
    struct firewall_ctx *ctx = (struct firewall_ctx *)user_data;
    int action;
    
    if (!ctx || !pkt) {
        return 0;
    }
    
    ctx->stats_total_packets++;
    
    /* Process through state tracking */
    if (ctx->state) {
        state_process_packet(ctx->state, pkt);
    }
    
    /* Process through filter engine */
    if (ctx->filter) {
        action = filter_packet(ctx->filter, pkt);
        
        switch (action) {
            case RULE_ACTION_ACCEPT:
                /* Packet is accepted, let it through */
                break;
                
            case RULE_ACTION_DROP:
                ctx->stats_dropped_packets++;
                return 1; /* Drop packet */
                
            case RULE_ACTION_REJECT:
                ctx->stats_rejected_packets++;
                /* Send TCP RST or ICMP unreachable */
                if (ctx->inject && pkt->is_tcp) {
                    inject_tcp_rst(ctx->inject, pkt->dst_ip, pkt->src_ip,
                                  pkt->dst_port, pkt->src_port, 
                                  pkt->tcp ? ntohl(pkt->tcp->ack_seq) : 0,
                                  pkt->tcp ? ntohl(pkt->tcp->seq) + 1 : 0);
                    ctx->stats_injected_packets++;
                } else if (ctx->inject) {
                    inject_icmp_unreach(ctx->inject, pkt->dst_ip, pkt->src_ip,
                                       pkt->data, pkt->len, 3); /* port unreachable */
                    ctx->stats_injected_packets++;
                }
                return 1; /* Reject packet */
                
            case RULE_ACTION_LOG:
                /* Log and accept */
                break;
        }
    }
    
    return 0; /* Accept packet */
}

struct firewall_ctx *firewall_init(void) {
    struct firewall_ctx *ctx;
    
    if (g_ctx) {
        return g_ctx;
    }
    
    ctx = malloc(sizeof(struct firewall_ctx));
    if (!ctx) {
        return NULL;
    }
    
    memset(ctx, 0, sizeof(struct firewall_ctx));
    
    /* Default interface */
    strcpy(ctx->iface, "eth0");
    
    /* Initialize components */
    ctx->state = state_init(100000); /* 100k max connections */
    ctx->filter = filter_init();
    ctx->logger = log_init();
    
    if (!ctx->state || !ctx->filter) {
        firewall_cleanup(ctx);
        return NULL;
    }
    
    ctx->running = 0;
    g_ctx = ctx;
    
    return ctx;
}

int firewall_start(struct firewall_ctx *ctx) {
    int ret;
    
    if (!ctx || ctx->running) {
        return -1;
    }
    
    /* Initialize packet injection */
    ctx->inject = inject_init(ctx->iface);
    if (!ctx->inject) {
        fprintf(stderr, "Warning: Could not initialize packet injection\n");
    }
    
    /* Initialize packet capture */
    ctx->capture = capture_init(ctx->iface, 1, 100);
    if (!ctx->capture) {
        fprintf(stderr, "Failed to initialize packet capture on %s\n", ctx->iface);
        return -1;
    }
    
    ctx->running = 1;
    
    /* Start capture thread */
    ret = pthread_create(&ctx->capture_thread, NULL, capture_thread_func, ctx);
    if (ret != 0) {
        fprintf(stderr, "Failed to create capture thread\n");
        ctx->running = 0;
        return -1;
    }
    
    /* Start cleanup thread */
    ret = pthread_create(&ctx->cleanup_thread, NULL, cleanup_thread_func, ctx);
    if (ret != 0) {
        fprintf(stderr, "Failed to create cleanup thread\n");
        ctx->running = 0;
        pthread_join(ctx->capture_thread, NULL);
        return -1;
    }
    
    printf("Firewall started successfully on %s\n", ctx->iface);
    return 0;
}

void firewall_stop(struct firewall_ctx *ctx) {
    if (!ctx) return;
    
    ctx->running = 0;
    
    if (ctx->capture) {
        capture_stop(ctx->capture);
    }
    
    /* Wait for threads to finish */
    pthread_join(ctx->capture_thread, NULL);
    pthread_join(ctx->cleanup_thread, NULL);
    
    printf("Firewall stopped\n");
}

void firewall_cleanup(struct firewall_ctx *ctx) {
    if (!ctx) return;
    
    firewall_stop(ctx);
    
    if (ctx->capture) {
        capture_cleanup(ctx->capture);
    }
    if (ctx->inject) {
        inject_cleanup(ctx->inject);
    }
    if (ctx->filter) {
        filter_cleanup(ctx->filter);
    }
    if (ctx->state) {
        state_cleanup(ctx->state);
    }
    if (ctx->logger) {
        log_cleanup(ctx->logger);
    }
    
    free(ctx);
    g_ctx = NULL;
}
