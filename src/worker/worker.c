#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include "worker.h"

struct packet_queue *packet_queue_create(void) {
    struct packet_queue *queue;
    
    queue = malloc(sizeof(struct packet_queue));
    if (!queue) return NULL;
    
    memset(queue, 0, sizeof(struct packet_queue));
    queue->head = 0;
    queue->tail = 0;
    queue->count = 0;
    
    pthread_mutex_init(&queue->lock, NULL);
    pthread_cond_init(&queue->not_empty, NULL);
    pthread_cond_init(&queue->not_full, NULL);
    
    return queue;
}

void packet_queue_destroy(struct packet_queue *queue) {
    if (!queue) return;
    
    pthread_mutex_destroy(&queue->lock);
    pthread_cond_destroy(&queue->not_empty);
    pthread_cond_destroy(&queue->not_full);
    free(queue);
}

int packet_queue_push(struct packet_queue *queue, struct packet_info *pkt) {
    int ret = -1;
    
    if (!queue || !pkt) return -1;
    
    pthread_mutex_lock(&queue->lock);
    
    while (queue->count >= WORKER_QUEUE_SIZE) {
        pthread_cond_wait(&queue->not_full, &queue->lock);
    }
    
    queue->packets[queue->tail] = pkt;
    queue->tail = (queue->tail + 1) % WORKER_QUEUE_SIZE;
    queue->count++;
    
    pthread_cond_signal(&queue->not_empty);
    ret = 0;
    
    pthread_mutex_unlock(&queue->lock);
    return ret;
}

struct packet_info *packet_queue_pop(struct packet_queue *queue) {
    struct packet_info *pkt = NULL;
    
    if (!queue) return NULL;
    
    pthread_mutex_lock(&queue->lock);
    
    while (queue->count == 0) {
        pthread_cond_wait(&queue->not_empty, &queue->lock);
    }
    
    pkt = queue->packets[queue->head];
    queue->head = (queue->head + 1) % WORKER_QUEUE_SIZE;
    queue->count--;
    
    pthread_cond_signal(&queue->not_full);
    
    pthread_mutex_unlock(&queue->lock);
    return pkt;
}

static void *worker_thread_func(void *arg) {
    struct worker_ctx *worker = (struct worker_ctx *)arg;
    struct packet_info *pkt;
    
    printf("Worker %d started\n", worker->id);
    
    while (worker->running) {
        pkt = packet_queue_pop(worker->queue);
        if (!pkt) continue;
        
        if (worker->packet_handler) {
            worker->packet_handler(pkt, worker->user_data);
        }
        
        worker->processed_packets++;
        worker->processed_bytes += pkt->len;
        
        free(pkt->data);
        free(pkt);
    }
    
    printf("Worker %d stopped\n", worker->id);
    return NULL;
}

struct worker_pool *worker_pool_create(int num_workers) {
    struct worker_pool *pool;
    int i;
    
    if (num_workers <= 0 || num_workers > MAX_WORKERS) {
        return NULL;
    }
    
    pool = malloc(sizeof(struct worker_pool));
    if (!pool) return NULL;
    
    memset(pool, 0, sizeof(struct worker_pool));
    
    pool->queue.head = 0;
    pool->queue.tail = 0;
    pool->queue.count = 0;
    
    if (pthread_mutex_init(&pool->queue.lock, NULL) != 0) {
        free(pool);
        return NULL;
    }
    
    if (pthread_cond_init(&pool->queue.not_empty, NULL) != 0) {
        pthread_mutex_destroy(&pool->queue.lock);
        free(pool);
        return NULL;
    }
    
    if (pthread_cond_init(&pool->queue.not_full, NULL) != 0) {
        pthread_mutex_destroy(&pool->queue.lock);
        pthread_cond_destroy(&pool->queue.not_empty);
        free(pool);
        return NULL;
    }
    
    pool->worker_count = num_workers;
    pool->running = 0;
    
    for (i = 0; i < num_workers; i++) {
        pool->workers[i].id = i;
        pool->workers[i].running = 0;
        pool->workers[i].queue = &pool->queue;
        pool->workers[i].packet_handler = NULL;
        pool->workers[i].user_data = NULL;
        pool->workers[i].processed_packets = 0;
        pool->workers[i].processed_bytes = 0;
    }
    
    return pool;
}

void worker_pool_destroy(struct worker_pool *pool) {
    int i;
    
    if (!pool) return;
    
    worker_pool_stop(pool);
    
    pthread_mutex_destroy(&pool->queue.lock);
    pthread_cond_destroy(&pool->queue.not_empty);
    pthread_cond_destroy(&pool->queue.not_full);
    
    free(pool);
}

int worker_pool_start(struct worker_pool *pool, 
                     int (*packet_handler)(struct packet_info *pkt, void *user_data),
                     void *user_data) {
    int i, ret;
    
    if (!pool || pool->running) return -1;
    
    pool->running = 1;
    
    for (i = 0; i < pool->worker_count; i++) {
        pool->workers[i].packet_handler = packet_handler;
        pool->workers[i].user_data = user_data;
        pool->workers[i].running = 1;
        pool->workers[i].processed_packets = 0;
        pool->workers[i].processed_bytes = 0;
        
        ret = pthread_create(&pool->workers[i].thread, NULL, 
                           worker_thread_func, &pool->workers[i]);
        if (ret != 0) {
            pool->running = 0;
            while (i > 0) {
                pool->workers[--i].running = 0;
            }
            return -1;
        }
    }
    
    printf("Worker pool started with %d workers\n", pool->worker_count);
    return 0;
}

void worker_pool_stop(struct worker_pool *pool) {
    int i;
    
    if (!pool || !pool->running) return;
    
    pool->running = 0;
    
    for (i = 0; i < pool->worker_count; i++) {
        pool->workers[i].running = 0;
    }
    
    pthread_cond_broadcast(&pool->queue.not_empty);
    
    for (i = 0; i < pool->worker_count; i++) {
        if (pool->workers[i].thread) {
            pthread_join(pool->workers[i].thread, NULL);
        }
    }
    
    printf("Worker pool stopped\n");
}

int worker_pool_submit_packet(struct worker_pool *pool, struct packet_info *pkt) {
    if (!pool || !pkt) return -1;
    
    return packet_queue_push(&pool->queue, pkt);
}

void worker_pool_get_stats(struct worker_pool *pool, uint64_t *total_packets, uint64_t *total_bytes) {
    int i;
    
    if (!pool || !total_packets || !total_bytes) return;
    
    *total_packets = 0;
    *total_bytes = 0;
    
    for (i = 0; i < pool->worker_count; i++) {
        *total_packets += pool->workers[i].processed_packets;
        *total_bytes += pool->workers[i].processed_bytes;
    }
}
