/* references: xHook (MIT), bhook (MIT) */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include "raplt_hash.h"
#include "raplt_elf.h"
#include "raplt_log.h"

static inline uint32_t raplt_str_hash(const char *str, unsigned seed)
{
    uint32_t h = 5381 + seed;
    for(int c; (c = *str); str++)
        h = h * 33 + c;
    return h;
}

static void raplt_bloom_add(raplt_bloom_t *bloom, const char *str)
{
    for(int i = 0; i < RAPLT_BLOOM_HASHES; i++) {
        uint32_t h = raplt_str_hash(str, (unsigned)i) % RAPLT_BLOOM_BITS;
        bloom->bits[h / 8] |= (1 << (h % 8));
    }
}

static int raplt_bloom_test(raplt_bloom_t *bloom, const char *str)
{
    for(int i = 0; i < RAPLT_BLOOM_HASHES; i++) {
        uint32_t h = raplt_str_hash(str, (unsigned)i) % RAPLT_BLOOM_BITS;
        if(!(bloom->bits[h / 8] & (1 << (h % 8))))
            return 0;
    }
    return 1;
}

void raplt_sym_index_init(raplt_sym_index_t *idx)
{
    memset(idx, 0, sizeof(raplt_sym_index_t));
    idx->bucket_count = 64;
    idx->buckets = calloc(idx->bucket_count, sizeof(raplt_hash_entry_t *));
}

static void raplt_sym_index_grow(raplt_sym_index_t *idx)
{
    size_t old_count = idx->bucket_count;
    raplt_hash_entry_t **old_buckets = idx->buckets;
    idx->bucket_count = old_count * 2;
    idx->buckets = calloc(idx->bucket_count, sizeof(raplt_hash_entry_t *));
    for(size_t i = 0; i < old_count; i++) {
        raplt_hash_entry_t *entry = old_buckets[i];
        while(entry) {
            raplt_hash_entry_t *next = entry->next;
            uint32_t b = entry->hash % (uint32_t)idx->bucket_count;
            entry->next = idx->buckets[b];
            idx->buckets[b] = entry;
            entry = next;
        }
    }
    free(old_buckets);
}

int raplt_sym_index_insert(raplt_sym_index_t  *idx,
                            const char         *symbol,
                            raplt_got_entry_t  *entry)
{
    if(!idx->buckets) raplt_sym_index_init(idx);
    if(idx->entry_count > idx->bucket_count * 2)
        raplt_sym_index_grow(idx);

    uint32_t hash = raplt_str_hash(symbol, 0);
    raplt_bloom_add(&idx->bloom, symbol);

    uint32_t b = hash % (uint32_t)idx->bucket_count;
    raplt_hash_entry_t *cur = idx->buckets[b];
    while(cur) {
        if(cur->hash == hash && strcmp(cur->symbol, symbol) == 0)
            break;
        cur = cur->next;
    }
    if(cur) {
        raplt_got_entry_t *new_entries = realloc(
            cur->entries, (cur->entry_count + 1) * sizeof(raplt_got_entry_t));
        if(!new_entries) return -ENOMEM;
        cur->entries = new_entries;
        cur->entries[cur->entry_count] = *entry;
        cur->entry_count++;
    } else {
        raplt_hash_entry_t *new_entry = calloc(1, sizeof(raplt_hash_entry_t));
        if(!new_entry) return -ENOMEM;
        new_entry->hash   = hash;
        new_entry->symbol = strdup(symbol);
        if(!new_entry->symbol) { free(new_entry); return -ENOMEM; }
        new_entry->entries = malloc(sizeof(raplt_got_entry_t));
        if(!new_entry->entries) {
            free(new_entry->symbol); free(new_entry); return -ENOMEM;
        }
        new_entry->entries[0] = *entry;
        new_entry->entry_count = 1;
        new_entry->next = idx->buckets[b];
        idx->buckets[b] = new_entry;
        idx->entry_count++;
    }
    return 0;
}

int raplt_sym_index_lookup(raplt_sym_index_t  *idx,
                            const char         *symbol,
                            raplt_got_entry_t **entries,
                            size_t             *count)
{
    if(!idx->buckets) return -1;
    if(!raplt_bloom_test(&idx->bloom, symbol)) return -1;

    uint32_t hash = raplt_str_hash(symbol, 0);
    raplt_hash_entry_t *cur = idx->buckets[hash % (uint32_t)idx->bucket_count];
    while(cur) {
        if(cur->hash == hash && strcmp(cur->symbol, symbol) == 0) {
            *entries = cur->entries;
            *count = cur->entry_count;
            return 0;
        }
        cur = cur->next;
    }
    return -1;
}

int raplt_sym_index_might_contain(raplt_sym_index_t *idx, const char *symbol)
{
    return raplt_bloom_test(&idx->bloom, symbol);
}

void raplt_sym_index_destroy(raplt_sym_index_t *idx)
{
    if(!idx->buckets) return;
    for(size_t i = 0; i < idx->bucket_count; i++) {
        raplt_hash_entry_t *entry = idx->buckets[i];
        while(entry) {
            raplt_hash_entry_t *next = entry->next;
            free(entry->symbol);
            free(entry->entries);
            free(entry);
            entry = next;
        }
    }
    free(idx->buckets);
    idx->buckets = NULL;
    idx->bucket_count = 0;
    idx->entry_count = 0;
    memset(&idx->bloom, 0, sizeof(idx->bloom));
}

int raplt_sym_index_build(raplt_sym_index_t *idx, raplt_lib_t *lib)
{
    (void)idx; (void)lib;
    return 0;
}
