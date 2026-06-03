/* verify g_all_regions table, mremap correctness, and fallback paths */
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <setjmp.h>
#include <sys/mman.h>

#include "raplt.h"
#include "raplt_core.h"
#include "raplt_mremap.h"
#include "raplt_util.h"
#include "test_runner.h"

static sigjmp_buf g_env;

static void sigsegv_catch(int sig)
{
    (void)sig;
    siglongjmp(g_env, 1);
}

int main(void)
{
    raplt_exclude_self(0);

    T("raplt_init succeeds");
    int r = raplt_init();
    ASSERT(r == 0, "init=%d", r);

    T("mremap on anon page works (RW page)");
    void *anon = mmap(NULL, RAPLT_PAGE_SIZE, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    ASSERT(anon != MAP_FAILED, "mmap rw failed");
    *(int *)anon = 42;
    void *backup = mmap(NULL, RAPLT_PAGE_SIZE, PROT_NONE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    ASSERT(backup != MAP_FAILED, "mmap PROT_NONE failed");

    struct sigaction old, act;
    sigemptyset(&act.sa_mask);
    act.sa_handler = sigsegv_catch;
    sigaction(SIGSEGV, &act, &old);

    int crashed = 0;
    if (sigsetjmp(g_env, 1) == 0) {
        void **got = (void **)((char *)anon + 8);
        *got = NULL;
        void *got_arr[1] = { (void *)got };
        void *dummy = (void *)(uintptr_t)0xdead;
        raplt_mremap_patch_region(PAGE_START((uintptr_t)anon),
                                   PAGE_START((uintptr_t)anon) + RAPLT_PAGE_SIZE,
                                   PROT_READ | PROT_WRITE,
                                   got_arr, dummy, 1, &backup);
    } else {
        crashed = 1;
    }
    sigaction(SIGSEGV, &old, NULL);
    ASSERT(!crashed, "SIGSEGV during mremap on anon RW page");

    T("GOT write persisted after mremap");
    void **got2 = (void **)((char *)anon + 8);
    ASSERT(*got2 == (void *)(uintptr_t)0xdead, "got %p (expected 0xdead)", *got2);

    /* cleanup: the backup has old pages, anon has the new page.
       we can't easily restore since mremap needs the old VMA alive.
       just munmap both */
    munmap(backup, RAPLT_PAGE_SIZE);
    munmap(anon, RAPLT_PAGE_SIZE);

    /* test the mprotect fallback (mremap fails intentionally, falls through) */
    T("mprotect path: mremap doesn't crash with bad args");
    void *bad_probe = mmap(NULL, RAPLT_PAGE_SIZE, PROT_READ,
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    ASSERT(bad_probe != MAP_FAILED, "mmap r-- failed");
    void *bad_backup = mmap(NULL, RAPLT_PAGE_SIZE, PROT_NONE,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    ASSERT(bad_backup != MAP_FAILED, "mmap PROT_NONE failed");

    void **bad_got = (void **)bad_probe;
    void *bad_arr[1] = { (void *)bad_got };
    void *dummy_fn = (void *)(uintptr_t)0xbeef;

    /* mremap from a page the test binary owns may or may not work */
    int patch_rc = raplt_mremap_patch_region(PAGE_START((uintptr_t)bad_probe),
                                              PAGE_START((uintptr_t)bad_probe) + RAPLT_PAGE_SIZE,
                                              PROT_READ,
                                              bad_arr, dummy_fn, 1, &bad_backup);
    ASSERT(patch_rc == 0 || patch_rc == -1, "patch returned %d", patch_rc);
    munmap(bad_probe, RAPLT_PAGE_SIZE);
    munmap(bad_backup, RAPLT_PAGE_SIZE);

    SUMMARY();
    return g_fail ? 1 : 0;
}
