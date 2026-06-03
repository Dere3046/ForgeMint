/* test: ELF parsing engine */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <elf.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "raplt_elf.h"
#include "raplt_hash.h"
#include "raplt_recon.h"
#include "test_runner.h"

int main(void)
{
    void *handle;
    raplt_lib_t lib;

    handle = dlopen("./libtestfixture.so", RTLD_NOW);
    if(!handle) {
        printf("SKIP: cannot dlopen libtestfixture.so (build it first)\n");
        return 77; /* skip code for test harnesses */
    }

    Dl_info dli;
    if(!dladdr(dlsym(handle, "test_strlen"), &dli)) {
        printf("SKIP: dladdr failed\n");
        dlclose(handle);
        return 77;
    }

    T("init ELF header validation");
    ASSERT(raplt_elf_check_header((uintptr_t)dli.dli_fbase) == 0,
           "expected valid ELF header");

    T("init raplt_elf_init");
    struct stat st;
    stat(dli.dli_fname, &st);
    ASSERT(raplt_elf_init(&lib, (uintptr_t)dli.dli_fbase,
                           dli.dli_fname, st.st_dev, st.st_ino) == 0,
           "init failed");

    T("symbol_count > 0");
    ASSERT(lib.symbol_count > 0, "got %u", lib.symbol_count);

    T("string_table valid");
    ASSERT(lib.string_table != NULL, "NULL");

    T("symbol_table valid");
    ASSERT(lib.symbol_table != NULL, "NULL");

    T("memory_base matches dli_fbase");
    ASSERT(lib.memory_base == (uintptr_t)dli.dli_fbase,
           "mismatch: %lx vs %lx",
           (unsigned long)lib.memory_base,
           (unsigned long)dli.dli_fbase);

    T("load_bias non-negative");
    ASSERT((intptr_t)lib.load_bias >= 0, "negative bias");

    T("hash method detected");
    ASSERT(lib.use_gnu_hash || lib.hash_bucket_count > 0,
           "no hash method");

    T("build GOT index");
    int r = raplt_elf_build_got_index(&lib);
    ASSERT(r == 0, "build failed with %d", r);

    T("GOT index not empty");
    ASSERT(lib.got_index && lib.got_index->entry_count > 0,
           "empty index");

    T("find strlen in GOT index (fixture calls it)");
    raplt_got_entry_t *entries = NULL;
    size_t count = 0;
    int found = raplt_sym_index_lookup(lib.got_index,
                                        "strlen",
                                        &entries, &count);
    ASSERT(found == 0 && entries != NULL && count > 0,
           "not found (found=%d entries=%p count=%zu)",
           found, (void*)entries, count);

    T("strlen GOT addr valid");
    ASSERT(entries[0].addr != NULL, "NULL addr");
    T("strlen GOT addr within lib");
    ASSERT((uintptr_t)entries[0].addr >= lib.memory_base,
           "addr outside lib base");

    T("recon: stripped header detection");
    int needed = raplt_recon_needed(&lib);
    ASSERT(needed == 0 || needed == 1, "unexpected return %d", needed);

    raplt_elf_fini(&lib);
    dlclose(handle);

    SUMMARY();
    return g_fail ? 1 : 0;
}
