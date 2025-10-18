#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "firewall.h"
#include "capture/capture.h"
#include "capture/inject.h"
#include "filter/filter.h"
#include "state/state.h"
#include "nat/nat.h"
#include "worker/worker.h"
#include "util/mempool.h"
#include "log/log.h"

struct firewall_ctx {
    struct capture_ctx *capture;
    struct inject_ctx *inject;
    struct filter_ctx *filter;
    struct state_ctx *state;
    struct nat_ctx *nat;
    struct worker_pool *workers;
    struct mempool *mempool;
    struct log_ctx *logger;
    
    pthread_t capture_thread;
    pthread_t cleanup_thread;
    pthread_t stats_thread;
    
    volatile int running;
    char iface[16];
    uint32_t local_ip;
    int num_workers;
    
    uint64_t stats_total_packets;
    uint64_t stats_dropped_packets;
    uint64_t stats_rejected_packets;
    uint64_t stats_injected_packets;
    uint64_t stats_nat_packets;
    uint64_t stats_worker_packets;
    uint64_t stats_worker_bytes;
};

static struct firewall_ctx *g_ctx = NULL;

static int is_local_ip(uint32_t ip) {
    uint32_t local_nets[] = {
        inet_addr("127.0.0.0"),
        inet_addr("10.0.0.0"), 
        inet_addr("192.168.0.0"),
        inet_addr("172.16.0.0")
    };
    uint32_t local_masks[] = {
        inet_addr("255.0.0.0"),
        inet_addr("255.0.0.0"),
        inet_addr("255.255.0.0"), 
        inet_addr("255.240.0.0")
    };
    
    for (int i = 0; i < 4; i++) {
        if ((ip & local_masks[i]) == (local_nets[i] & local_masks[i])) {
            return 1;
        }
    }
    return 0;
}

static int get_packet_direction(struct packet_info *pkt, uint32_t local_ip) {
    int src_local = is_local_ip(pkt->src_ip);
    int dst_local = is_local_ip(pkt->dst_ip);
    
    if (src_local && !dst_local) {
        return 0;
    } else if (!src_local && dst_local) {
        return 1;
    } else if (src_local && dst_local) {
        if (pkt->src_ip == local_ip) return 0;
        if (pkt->dst_ip == local_ip) return 1;
        return 2;
    } else {
        return 2;
    }
}

static void update_packet_checksums(struct packet_info *pkt) {
    if (pkt->ip) {
        pkt->ip->check = 0;
        pkt->ip->check = checksum((uint16_t *)pkt->ip, pkt->ip->ihl * 4);
    }
    
    if (pkt->tcp && pkt->ip) {
        struct pseudo_header {
            uint32_t src_ip;
            uint32_t dst_ip;
            uint8_t zero;
            uint8_t protocol;
            uint16_t tcp_len;
        } pseudo;
        
        pseudo.src_ip = pkt->src_ip;
        pseudo.dst_ip = pkt->dst_ip;
        pseudo.zero = 0;
        pseudo.protocol = IPPROTO_TCP;
        pseudo.tcp_len = htons(sizeof(struct tcphdr) + pkt->payload_len);
        
        pkt->tcp->check = 0;
        
        uint32_t csum = 0;
        uint16_t *ptr = (uint16_t *)&pseudo;
        for (int i = 0; i < sizeof(pseudo)/2; i++) {
            csum += *ptr++;
        }
        
        ptr = (uint16_t *)pkt->tcp;
        int tcp_words = (sizeof(struct tcphdr) + pkt->payload_len + 1) / 2;
        for (int i = 0; i < tcp_words; i++) {
            csum += *ptr++;
        }
        
        csum = (csum >> 16) + (csum & 0xffff);
        csum += (csum >> 16);
        pkt->tcp->check = ~csum;
    }
    
    if (pkt->udp && pkt->ip) {
        struct pseudo_header {
            uint32_t src_ip;
            uint32_t dst_ip;
            uint8_t zero;
            uint8_t protocol;
            uint16_t udp_len;
        } pseudo;
        
        pseudo.src_ip = pkt->src_ip;
        pseudo.dst_ip = pkt->dst_ip;
        pseudo.zero = 0;
        pseudo.protocol = IPPROTO_UDP;
        pseudo.udp_len = htons(sizeof(struct udphdr) + pkt->payload_len);
        
        pkt->udp->check = 0;
        
        uint32_t csum = 0;
        uint16_t *ptr = (uint16_t *)&pseudo;
        for (int i = 0; i < sizeof(pseudo)/2; i++) {
            csum += *ptr++;
        }
        
        ptr = (uint16_t *)pkt->udp;
        int udp_words = (sizeof(struct udphdr) + pkt->payload_len + 1) / 2;
        for (int i = 0; i < udp_words; i++) {
            csum += *ptr++;
        }
        
        csum = (csum >> 16) + (csum & 0xffff);
        csum += (csum >> 16);
        pkt->udp->check = ~csum;
    }
}

static int firewall_packet_handler(struct packet_info *pkt, void *user_data) {
    struct firewall_ctx *ctx = (struct firewall_ctx *)user_data;
    int action = RULE_ACTION_ACCEPT;
    int direction;
    int nat_applied = 0;
    
    if (!ctx || !pkt) return 1;
    
    ctx->stats_total_packets++;
    
    direction = get_packet_direction(pkt, ctx->local_ip);
    pkt->direction = direction;
    
    if (ctx->nat) {
        nat_applied = nat_process_packet(ctx->nat, pkt, direction);
        if (nat_applied) {
            ctx->stats_nat_packets++;
            update_packet_checksums(pkt);
        }
    }
    
    if (ctx->state) {
        state_process_packet(ctx->state, pkt);
    }
    
    if (ctx->filter) {
        action = filter_packet(ctx->filter, pkt);
    }
    
    switch (action) {
        case RULE_ACTION_ACCEPT:
            if (nat_applied && ctx->inject) {
                inject_packet(ctx->inject, pkt->data, pkt->len);
                return 1;
            }
            break;
            
        case RULE_ACTION_DROP:
            ctx->stats_dropped_packets++;
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
                } else {
                    inject_icmp_unreach(ctx->inject, pkt->dst_ip, pkt->src_ip,
                                       pkt->data, pkt->len, 3);
                    ctx->stats_injected_packets++;
                }
            }
            return 1;
            
        case RULE_ACTION_LOG:
            break;
    }
    
    return 0;
}

static int capture_packet_handler(struct packet_info *pkt, void *user_data) {
    struct firewall_ctx *ctx = (struct firewall_ctx *)user_data;
    struct packet_info *worker_pkt;
    
    if (!ctx || !pkt || !ctx->workers) {
        return 0;
    }
    
    worker_pkt = malloc(sizeof(struct packet_info));
    if (!worker_pkt) {
        return 0;
    }
    
    memcpy(worker_pkt, pkt, sizeof(struct packet_info));
    
    worker_pkt->data = malloc(pkt->len);
    if (!worker_pkt->data) {
        free(worker_pkt);
        return 0;
    }
    
    memcpy(worker_pkt->data, pkt->data, pkt->len);
    
    if (worker_pool_submit_packet(ctx->workers, worker_pkt) != 0) {
        free(worker_pkt->data);
        free(worker_pkt);
    }
    
    return 0;
}

static void *capture_thread_func(void *arg) {
    struct firewall_ctx *ctx = (struct firewall_ctx *)arg;
    
    if (!ctx || !ctx->capture) {
        return NULL;
    }
    
    printf("Packet capture running on %s with %d workers\n", ctx->iface, ctx->num_workers);
    capture_start(ctx->capture, capture_packet_handler, ctx);
    printf("Packet capture stopped\n");
    
    return NULL;
}

static void *cleanup_thread_func(void *arg) {
    struct firewall_ctx *ctx = (struct firewall_ctx *)arg;
    
    if (!ctx) {
        return NULL;
    }
    
    while (ctx->running) {
        if (ctx->state) {
            state_cleanup_old(ctx->state);
        }
        if (ctx->nat) {
            nat_cleanup_old(ctx->nat);
        }
        if (ctx->mempool) {
            mempool_reset(ctx->mempool);
        }
        sleep(60);
    }
    
    return NULL;
}

static void *stats_thread_func(void *arg) {
    struct firewall_ctx *ctx = (struct firewall_ctx *)arg;
    
    if (!ctx) {
        return NULL;
    }
    
    while (ctx->running) {
        sleep(10);
        
        if (ctx->workers) {
            worker_pool_get_stats(ctx->workers, &ctx->stats_worker_packets, &ctx->stats_worker_bytes);
        }
        
        printf("Firewall stats: total=%lu drop=%lu reject=%lu nat=%lu worker=%lu\n",
               ctx->stats_total_packets, ctx->stats_dropped_packets,
               ctx->stats_rejected_packets, ctx->stats_nat_packets,
               ctx->stats_worker_packets);
    }
    
    return NULL;
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
    strcpy(ctx->iface, "eth0");
    ctx->local_ip = inet_addr("192.168.1.100");
    ctx->num_workers = 4;
    
    ctx->state = state_init(100000);
    ctx->filter = filter_init();
    ctx->nat = nat_init(inet_addr("1.2.3.4"));
    ctx->workers = worker_pool_create(ctx->num_workers);
    ctx->mempool = mempool_create();
    ctx->logger = log_init();
    
    if (!ctx->state || !ctx->filter || !ctx->workers) {
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
    
    ctx->inject = inject_init(ctx->iface);
    ctx->capture = capture_init(ctx->iface, 1, 100);
    
    if (!ctx->capture) {
        fprintf(stderr, "Failed to initialize packet capture\n");
        return -1;
    }
    
    if (!ctx->workers) {
        fprintf(stderr, "Worker pool not initialized\n");
        return -1;
    }
    
    if (worker_pool_start(ctx->workers, firewall_packet_handler, ctx) != 0) {
        fprintf(stderr, "Failed to start worker pool\n");
        return -1;
    }
    
    ctx->running = 1;
    
    ret = pthread_create(&ctx->capture_thread, NULL, capture_thread_func, ctx);
    if (ret != 0) {
        fprintf(stderr, "Failed to create capture thread\n");
        ctx->running = 0;
        worker_pool_stop(ctx->workers);
        return -1;
    }
    
    ret = pthread_create(&ctx->cleanup_thread, NULL, cleanup_thread_func, ctx);
    if (ret != 0) {
        fprintf(stderr, "Failed to create cleanup thread\n");
        ctx->running = 0;
        worker_pool_stop(ctx->workers);
        pthread_join(ctx->capture_thread, NULL);
        return -1;
    }
    
    ret = pthread_create(&ctx->stats_thread, NULL, stats_thread_func, ctx);
    if (ret != 0) {
        fprintf(stderr, "Failed to create stats thread\n");
        ctx->running = 0;
        worker_pool_stop(ctx->workers);
        pthread_join(ctx->capture_thread, NULL);
        pthread_join(ctx->cleanup_thread, NULL);
        return -1;
    }
    
    printf("Firewall engine started with %d workers\n", ctx->num_workers);
    return 0;
}

void firewall_stop(struct firewall_ctx *ctx) {
    if (!ctx) return;
    
    ctx->running = 0;
    
    if (ctx->capture) {
        capture_stop(ctx->capture);
    }
    
    if (ctx->workers) {
        worker_pool_stop(ctx->workers);
    }
    
    pthread_join(ctx->capture_thread, NULL);
    pthread_join(ctx->cleanup_thread, NULL);
    pthread_join(ctx->stats_thread, NULL);
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
    if (ctx->nat) {
        nat_cleanup(ctx->nat);
    }
    if (ctx->workers) {
        worker_pool_destroy(ctx->workers);
    }
    if (ctx->mempool) {
        mempool_destroy(ctx->mempool);
    }
    if (ctx->logger) {
        log_cleanup(ctx->logger);
    }
    
    free(ctx);
    g_ctx = NULL;
}

void firewall_add_nat_rule(struct firewall_ctx *ctx, int type, uint32_t src_ip, uint32_t src_mask,
                          uint32_t dst_ip, uint32_t dst_mask, uint16_t src_port, uint16_t dst_port,
                          int protocol, uint32_t nat_ip, uint16_t nat_port) {
    if (!ctx || !ctx->nat) return;
    
    nat_add_rule(ctx->nat, type, src_ip, src_mask, dst_ip, dst_mask, 
                src_port, dst_port, protocol, nat_ip, nat_port);
}

uint64_t firewall_get_stats(struct firewall_ctx *ctx, int stat_type) {
    if (!ctx) return 0;
    
    switch (stat_type) {
        case 0: return ctx->stats_total_packets;
        case 1: return ctx->stats_dropped_packets;
        case 2: return ctx->stats_rejected_packets;
        case 3: return ctx->stats_injected_packets;
        case 4: return ctx->stats_nat_packets;
        case 5: return ctx->stats_worker_packets;
        case 6: return ctx->stats_worker_bytes;
        default: return 0;
    }
}
