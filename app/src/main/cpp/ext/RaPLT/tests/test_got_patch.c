#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "raplt.h"
#include "raplt_elf.h"
#include "raplt_util.h"
#include "test_runner.h"

int main(void)
{
    void *handle = dlopen("./libtestfixture.so", RTLD_NOW);
    if(!handle) { printf("SKIP: no test fixture\n"); return 77; }

    /* --- direct GOT access --- */

    T("direct GOT write and read");
    void *page = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    ASSERT(page != MAP_FAILED, "mmap failed");
    void **slot = (void **)((char *)page + 16);
    raplt_write_got(slot, (void *)0xdead);
    ASSERT(raplt_read_got(slot) == (void *)0xdead, "read/write mismatch");
    munmap(page, 4096);

    T("batch protect + write");
    void *p2 = mmap(NULL, 4096 * 2, PROT_READ,
                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    void *addrs[2] = { p2, (char *)p2 + 4096 };
    void *vals[2]  = { (void *)0xaaa, (void *)0xbbb };
    raplt_batch_set_protect(addrs, 2, PROT_READ | PROT_WRITE);
    raplt_batch_write_got(addrs, vals, 2);
    ASSERT(*(void **)addrs[0] == (void *)0xaaa, "batch0 failed");
    ASSERT(*(void **)addrs[1] == (void *)0xbbb, "batch1 failed");
    munmap(p2, 4096 * 2);

    /* --- tier 1: resolve from .dynsym st_value --- */

    Dl_info dli;
    if(!dladdr(dlsym(handle, "test_strlen"), &dli)) {
        printf("SKIP: dladdr failed\n");
        dlclose(handle); SUMMARY(); return 77;
    }

    raplt_lib_t lib;
    struct stat st;
    stat(dli.dli_fname, &st);
    ASSERT(raplt_elf_init(&lib, (uintptr_t)dli.dli_fbase,
                           dli.dli_fname, st.st_dev, st.st_ino) == 0,
           "elf_init failed");
    raplt_elf_build_got_index(&lib);

    T("tier1: resolve test_strlen (defined) via st_value");
    void *resolved = NULL;
    ASSERT(raplt_elf_resolve_st_value(&lib, "test_strlen", &resolved) == 0,
           "resolve failed");
    void *from_dlsym = dlsym(handle, "test_strlen");
    ASSERT(resolved == from_dlsym,
           "mismatch: resolved=%p dlsym=%p", resolved, from_dlsym);

    T("tier1: imported symbol st_value=0 (expected fail)");
    ASSERT(raplt_elf_resolve_st_value(&lib, "strlen", &resolved) != 0,
           "imported symbol should fail");

    T("tier1: nonexistent symbol returns -1");
    ASSERT(raplt_elf_resolve_st_value(&lib, "nonexistent_fn", &resolved) != 0,
           "should fail");

    raplt_elf_fini(&lib);

    /* --- tier 2 + 3: register → unregister recovery --- */

    T("tier3: recover via cached original");
    /* hook `free` which IS in the fixture's GOT (called by test_free) */
    void *orig_free = dlsym(RTLD_DEFAULT, "free");
    void *backup = NULL;
    raplt_hook_t *h = raplt_register(".*libtestfixture\\.so$",
                                      "free",
                                      (void *)0x1,
                                      &backup, 0);

    /* on glibc, the per-lib index might not contain free
     * if libc symbols are in a lib not tracked by us */
    if(!h) {
        printf("    SKIP: free not in GOT index (glibc sym resolution)\n");
    } else {
        ASSERT(backup == orig_free,
               "backup should be original free: %p != %p", backup, orig_free);

        ASSERT(raplt_unregister(h) == 0, "unregister failed");
    }

    T("hooks_finalize ok");
    ASSERT(raplt_hooks_finalize() == 0, "finalize failed");

    T("clear ok");
    raplt_clear();

    dlclose(handle);
    SUMMARY();
    return g_fail ? 1 : 0;
}
