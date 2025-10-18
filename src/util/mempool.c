#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include "mempool.h"

struct mempool *mempool_create(void) {
    struct mempool *pool;
    
    pool = malloc(sizeof(struct mempool));
    if (!pool) return NULL;
    
    memset(pool, 0, sizeof(struct mempool));
    
    pool->chunks = NULL;
    pool->current_chunk = NULL;
    pool->total_allocated = 0;
    pool->total_used = 0;
    
    if (pthread_mutex_init(&pool->lock, NULL) != 0) {
        free(pool);
        return NULL;
    }
    
    return pool;
}

void mempool_destroy(struct mempool *pool) {
    struct mempool_chunk *chunk, *next;
    
    if (!pool) return;
    
    pthread_mutex_lock(&pool->lock);
    
    chunk = pool->chunks;
    while (chunk) {
        next = chunk->next;
        free(chunk);
        chunk = next;
    }
    
    pthread_mutex_unlock(&pool->lock);
    pthread_mutex_destroy(&pool->lock);
    free(pool);
}

void *mempool_alloc(struct mempool *pool, uint32_t size) {
    struct mempool_chunk *chunk;
    void *ptr = NULL;
    
    if (!pool || size == 0 || size > MEMPOOL_CHUNK_SIZE) {
        return NULL;
    }
    
    pthread_mutex_lock(&pool->lock);
    
    if (!pool->current_chunk || 
        (pool->current_chunk->used + size) > MEMPOOL_CHUNK_SIZE) {
        
        chunk = malloc(sizeof(struct mempool_chunk));
        if (!chunk) {
            pthread_mutex_unlock(&pool->lock);
            return NULL;
        }
        
        memset(chunk, 0, sizeof(struct mempool_chunk));
        chunk->next = pool->chunks;
        pool->chunks = chunk;
        pool->current_chunk = chunk;
        pool->total_allocated += MEMPOOL_CHUNK_SIZE;
    }
    
    ptr = pool->current_chunk->data + pool->current_chunk->used;
    pool->current_chunk->used += size;
    pool->total_used += size;
    
    pthread_mutex_unlock(&pool->lock);
    return ptr;
}

void mempool_reset(struct mempool *pool) {
    struct mempool_chunk *chunk;
    
    if (!pool) return;
    
    pthread_mutex_lock(&pool->lock);
    
    chunk = pool->chunks;
    while (chunk) {
        chunk->used = 0;
        chunk = chunk->next;
    }
    
    pool->current_chunk = pool->chunks;
    pool->total_used = 0;
    
    pthread_mutex_unlock(&pool->lock);
}

void mempool_stats(struct mempool *pool, uint32_t *allocated, uint32_t *used) {
    if (!pool) return;
    
    pthread_mutex_lock(&pool->lock);
    
    if (allocated) *allocated = pool->total_allocated;
    if (used) *used = pool->total_used;
    
    pthread_mutex_unlock(&pool->lock);
}
