/* test: hash index table + bloom filter */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "raplt_hash.h"
#include "raplt_elf.h"
#include "test_runner.h"

int main(void)
{
    raplt_sym_index_t idx;
    raplt_got_entry_t entry = { .addr = (void *)0xdead, .symidx = 1 };

    T("init empty");
    raplt_sym_index_init(&idx);
    ASSERT(idx.bucket_count == 64, "expected 64, got %zu",
           idx.bucket_count);

    T("insert one symbol");
    ASSERT(raplt_sym_index_insert(&idx, "malloc", &entry) == 0,
           "insert failed");

    T("lookup existing symbol");
    raplt_got_entry_t *entries;
    size_t count;
    int r = raplt_sym_index_lookup(&idx, "malloc", &entries, &count);
    ASSERT(r == 0, "not found");

    T("lookup count correct");
    ASSERT(count == 1, "expected 1, got %zu", count);

    T("lookup missing symbol");
    r = raplt_sym_index_lookup(&idx, "nonexistent", &entries, &count);
    ASSERT(r == -1, "should not be found");

    T("bloom filter excludes missing");
    ASSERT(raplt_sym_index_might_contain(&idx, "nonexistent") == 0,
           "false positive");

    T("bloom filter includes existing");
    ASSERT(raplt_sym_index_might_contain(&idx, "malloc") == 1,
           "false negative");

    T("insert duplicate symbol");
    raplt_got_entry_t entry2 = { .addr = (void *)0xbeef, .symidx = 2 };
    ASSERT(raplt_sym_index_insert(&idx, "malloc", &entry2) == 0,
           "insert dup failed");

    T("dup lookup count = 2");
    r = raplt_sym_index_lookup(&idx, "malloc", &entries, &count);
    ASSERT(r == 0 && count == 2, "expected 2, got %zu", count);

    T("mass insert 10000 symbols");
    char buf[64];
    raplt_got_entry_t mass_entry = { .addr = (void *)0x1000 };
    int fail = 0;
    for(int i = 0; i < 10000; i++) {
        snprintf(buf, sizeof(buf), "symbol_%d", i);
        mass_entry.symidx = i;
        mass_entry.addr = (void *)(uintptr_t)(0x1000 + i);
        if(raplt_sym_index_insert(&idx, buf, &mass_entry)) {
            fail = 1; break;
        }
    }
    ASSERT(!fail, "insert #%d failed", 10000);

    T("mass lookup all 10000");
    fail = 0;
    int fp_count = 0;
    for(int i = 0; i < 10000; i++) {
        snprintf(buf, sizeof(buf), "symbol_%d", i);
        if(raplt_sym_index_lookup(&idx, buf, &entries, &count)) {
            fail = 1; break;
        }
        if(raplt_sym_index_might_contain(&idx, buf) == 0)
            fail = 1;
    }
    ASSERT(!fail, "lookup #%d failed", 10000);

    T("bloom filter false positive rate");
    raplt_sym_index_t bf_idx;
    raplt_sym_index_init(&bf_idx);
    char bf_buf[64];
    raplt_got_entry_t bf_entry = { .addr = (void *)0x5000 };
    for(int i = 0; i < 200; i++) {
        snprintf(bf_buf, sizeof(bf_buf), "bf_test_%d", i);
        bf_entry.symidx = i;
        raplt_sym_index_insert(&bf_idx, bf_buf, &bf_entry);
    }
    for(int i = 5000; i < 5500; i++) {
        snprintf(bf_buf, sizeof(bf_buf), "ghost_%d", i);
        if(raplt_sym_index_might_contain(&bf_idx, bf_buf))
            fp_count++;
    }
    double rate = (double)fp_count / 500.0 * 100.0;
    printf("\n    bloom fp rate: %.1f%% (%d/500) with 200 entries\n",
           rate, fp_count);
    ASSERT(rate < 15.0, "fp rate too high: %.1f%%", rate);
    raplt_sym_index_destroy(&bf_idx);

    T("grow worked (bucket_count > 64)");
    ASSERT(idx.bucket_count > 64,
           "did not grow from initial (was %zu)", idx.bucket_count);

    T("destroy frees memory");
    raplt_sym_index_destroy(&idx);
    ASSERT(idx.buckets == NULL, "not NULL after destroy");
    ASSERT(idx.bucket_count == 0, "not 0 after destroy");

    SUMMARY();
    return g_fail ? 1 : 0;
}
