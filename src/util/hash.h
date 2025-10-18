#ifndef HASH_H
#define HASH_H

#include <stdint.h>
#include <pthread.h>

#define HASH_TABLE_SIZE 65536
#define LOCK_FREE_THRESHOLD 1000

struct hash_entry {
    uint32_t key;
    void *value;
    struct hash_entry *next;
};

struct hash_bucket {
    pthread_spinlock_t lock;
    struct hash_entry *head;
    uint32_t count;
};

struct hash_table {
    struct hash_bucket *buckets;
    uint32_t size;
    uint32_t count;
    uint32_t (*hash_func)(uint32_t key);
};

struct hash_table *hash_table_create(uint32_t size);
void hash_table_destroy(struct hash_table *table);
int hash_table_insert(struct hash_table *table, uint32_t key, void *value);
void *hash_table_lookup(struct hash_table *table, uint32_t key);
int hash_table_remove(struct hash_table *table, uint32_t key);
uint32_t hash_table_count(struct hash_table *table);
void hash_table_clear(struct hash_table *table);

#endif
