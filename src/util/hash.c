#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include "hash.h"

struct hash_table *hash_table_create(uint32_t size) {
    struct hash_table *table;
    uint32_t i;
    
    table = malloc(sizeof(struct hash_table));
    if (!table) return NULL;
    
    table->size = size;
    table->count = 0;
    table->buckets = calloc(size, sizeof(struct hash_bucket));
    if (!table->buckets) {
        free(table);
        return NULL;
    }
    
    for (i = 0; i < size; i++) {
        if (pthread_spin_init(&table->buckets[i].lock, PTHREAD_PROCESS_PRIVATE) != 0) {
            while (i > 0) {
                pthread_spin_destroy(&table->buckets[--i].lock);
            }
            free(table->buckets);
            free(table);
            return NULL;
        }
        table->buckets[i].head = NULL;
        table->buckets[i].count = 0;
    }
    
    table->hash_func = NULL;
    
    return table;
}

void hash_table_destroy(struct hash_table *table) {
    uint32_t i;
    struct hash_entry *entry, *next;
    
    if (!table) return;
    
    for (i = 0; i < table->size; i++) {
        pthread_spin_destroy(&table->buckets[i].lock);
        
        entry = table->buckets[i].head;
        while (entry) {
            next = entry->next;
            free(entry);
            entry = next;
        }
    }
    
    free(table->buckets);
    free(table);
}

static uint32_t default_hash_func(uint32_t key) {
    key = ((key >> 16) ^ key) * 0x45d9f3b;
    key = ((key >> 16) ^ key) * 0x45d9f3b;
    key = (key >> 16) ^ key;
    return key;
}

int hash_table_insert(struct hash_table *table, uint32_t key, void *value) {
    uint32_t index;
    struct hash_entry *new_entry, *entry;
    struct hash_bucket *bucket;
    
    if (!table) return -1;
    
    if (!table->hash_func) {
        table->hash_func = default_hash_func;
    }
    
    index = table->hash_func(key) % table->size;
    bucket = &table->buckets[index];
    
    pthread_spin_lock(&bucket->lock);
    
    entry = bucket->head;
    while (entry) {
        if (entry->key == key) {
            entry->value = value;
            pthread_spin_unlock(&bucket->lock);
            return 0;
        }
        entry = entry->next;
    }
    
    new_entry = malloc(sizeof(struct hash_entry));
    if (!new_entry) {
        pthread_spin_unlock(&bucket->lock);
        return -1;
    }
    
    new_entry->key = key;
    new_entry->value = value;
    new_entry->next = bucket->head;
    bucket->head = new_entry;
    bucket->count++;
    table->count++;
    
    pthread_spin_unlock(&bucket->lock);
    return 0;
}

void *hash_table_lookup(struct hash_table *table, uint32_t key) {
    uint32_t index;
    struct hash_entry *entry;
    struct hash_bucket *bucket;
    void *value = NULL;
    
    if (!table) return NULL;
    
    if (!table->hash_func) {
        table->hash_func = default_hash_func;
    }
    
    index = table->hash_func(key) % table->size;
    bucket = &table->buckets[index];
    
    pthread_spin_lock(&bucket->lock);
    
    entry = bucket->head;
    while (entry) {
        if (entry->key == key) {
            value = entry->value;
            break;
        }
        entry = entry->next;
    }
    
    pthread_spin_unlock(&bucket->lock);
    return value;
}

int hash_table_remove(struct hash_table *table, uint32_t key) {
    uint32_t index;
    struct hash_entry *entry, *prev = NULL;
    struct hash_bucket *bucket;
    int ret = -1;
    
    if (!table) return -1;
    
    if (!table->hash_func) {
        table->hash_func = default_hash_func;
    }
    
    index = table->hash_func(key) % table->size;
    bucket = &table->buckets[index];
    
    pthread_spin_lock(&bucket->lock);
    
    entry = bucket->head;
    while (entry) {
        if (entry->key == key) {
            if (prev) {
                prev->next = entry->next;
            } else {
                bucket->head = entry->next;
            }
            free(entry);
            bucket->count--;
            table->count--;
            ret = 0;
            break;
        }
        prev = entry;
        entry = entry->next;
    }
    
    pthread_spin_unlock(&bucket->lock);
    return ret;
}

uint32_t hash_table_count(struct hash_table *table) {
    return table ? table->count : 0;
}

void hash_table_clear(struct hash_table *table) {
    uint32_t i;
    struct hash_entry *entry, *next;
    
    if (!table) return;
    
    for (i = 0; i < table->size; i++) {
        pthread_spin_lock(&table->buckets[i].lock);
        
        entry = table->buckets[i].head;
        while (entry) {
            next = entry->next;
            free(entry);
            entry = next;
        }
        
        table->buckets[i].head = NULL;
        table->buckets[i].count = 0;
        pthread_spin_unlock(&table->buckets[i].lock);
    }
    
    table->count = 0;
}
