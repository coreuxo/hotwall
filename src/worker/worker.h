#ifndef WORKER_H
#define WORKER_H

#include <pthread.h>
#include "../capture/packet.h"

#define MAX_WORKERS 16
#define WORKER_QUEUE_SIZE 65536

struct packet_queue {
    struct packet_info *packets[WORKER_QUEUE_SIZE];
    uint32_t head;
    uint32_t tail;
    uint32_t count;
    pthread_mutex_t lock;
    pthread_cond_t not_empty;
    pthread_cond_t not_full;
};

struct worker_ctx {
    pthread_t thread;
    int id;
    volatile int running;
    struct packet_queue *queue;
    int (*packet_handler)(struct packet_info *pkt, void *user_data);
    void *user_data;
    uint64_t processed_packets;
    uint64_t processed_bytes;
};

struct worker_pool {
    struct worker_ctx workers[MAX_WORKERS];
    struct packet_queue queue;
    int worker_count;
    volatile int running;
};

struct worker_pool *worker_pool_create(int num_workers);
void worker_pool_destroy(struct worker_pool *pool);
int worker_pool_start(struct worker_pool *pool, 
                     int (*packet_handler)(struct packet_info *pkt, void *user_data),
                     void *user_data);
void worker_pool_stop(struct worker_pool *pool);
int worker_pool_submit_packet(struct worker_pool *pool, struct packet_info *pkt);
void worker_pool_get_stats(struct worker_pool *pool, uint64_t *total_packets, uint64_t *total_bytes);

#endif
