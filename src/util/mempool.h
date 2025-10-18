#ifndef MEMPOOL_H
#define MEMPOOL_H

#include <stdint.h>
#include <pthread.h>

#define MEMPOOL_CHUNK_SIZE 2048
#define MEMPOOL_MAX_CHUNKS 1024

struct mempool_chunk {
    uint8_t data[MEMPOOL_CHUNK_SIZE];
    uint32_t used;
    struct mempool_chunk *next;
};

struct mempool {
    struct mempool_chunk *chunks;
    struct mempool_chunk *current_chunk;
    pthread_mutex_t lock;
    uint32_t total_allocated;
    uint32_t total_used;
};

struct mempool *mempool_create(void);
void mempool_destroy(struct mempool *pool);
void *mempool_alloc(struct mempool *pool, uint32_t size);
void mempool_reset(struct mempool *pool);
void mempool_stats(struct mempool *pool, uint32_t *allocated, uint32_t *used);

#endif
