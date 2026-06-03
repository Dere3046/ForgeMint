/* references: xHook (MIT), libelfmaster (BSD-2-Clause), bhook (MIT) */

#ifndef RAPLT_HASH_H
#define RAPLT_HASH_H 1

#include <stdint.h>
#include <stddef.h>
#include "raplt_elf.h"

#ifdef __cplusplus
extern "C" {
#endif

#define RAPLT_BLOOM_BITS   2048
#define RAPLT_BLOOM_HASHES 4

typedef struct {
    uint8_t bits[RAPLT_BLOOM_BITS / 8];
} raplt_bloom_t;

typedef struct raplt_hash_entry {
    uint32_t                 hash;
    char                    *symbol;
    raplt_got_entry_t       *entries;
    size_t                   entry_count;
    struct raplt_hash_entry *next;
} raplt_hash_entry_t;

typedef struct raplt_sym_index {
    raplt_bloom_t      bloom;
    raplt_hash_entry_t **buckets;
    size_t             bucket_count;
    size_t             entry_count;
} raplt_sym_index_t;

void raplt_sym_index_init(raplt_sym_index_t *idx);

int raplt_sym_index_build(raplt_sym_index_t *idx, raplt_lib_t *lib);

int raplt_sym_index_lookup(raplt_sym_index_t  *idx,
                           const char         *symbol,
                           raplt_got_entry_t **entries,
                           size_t             *count);

int raplt_sym_index_might_contain(raplt_sym_index_t *idx, const char *symbol);

void raplt_sym_index_destroy(raplt_sym_index_t *idx);

int raplt_sym_index_insert(raplt_sym_index_t  *idx,
                           const char         *symbol,
                           raplt_got_entry_t  *entry);

#ifdef __cplusplus
}
#endif

#endif /* RAPLT_HASH_H */
