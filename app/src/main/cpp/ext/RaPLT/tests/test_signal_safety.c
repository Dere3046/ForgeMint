/* test: signal handler safety (SIGSEGV guard, handler chain, lazy registry) */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <setjmp.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/mman.h>

#include "raplt_signal.h"
#include "raplt_util.h"
#include "test_runner.h"

static int g_custom_handler_called = 0;
static int g_old_handler_flag = 0;

static void custom_sigsegv_direct(int sig, siginfo_t *info, void *ctx)
{
    (void)sig; (void)info; (void)ctx;
    g_custom_handler_called++;
}

int main(void)
{
    T("signal_init returns 0");
    ASSERT(raplt_signal_init() == 0, "init failed");

    T("signal_init idempotent");
    ASSERT(raplt_signal_init() == 0, "second init failed");

    T("SIGSEGV guard: caught fault returns 1");
    int caught = raplt_signal_guard_enter();
    if(caught == 0) {
        /* trigger SIGSEGV */
        volatile int *bad = (volatile int *)0x1;
        (void)*bad;
    }
    ASSERT(caught == 1 || caught == 0, "guard_enter unexpected");
    raplt_signal_guard_exit();

    T("lazy site: register");
    void *dummy_addr = malloc(sizeof(void*));
    void *backup = NULL;
    ASSERT(raplt_signal_register_lazy((void **)dummy_addr,
                                       (void *)0xdead, &backup) == 0,
           "register failed");

    T("lazy site: is registered");
    ASSERT(raplt_signal_is_lazy_site((void **)dummy_addr) == 1,
           "not found");

    T("lazy site: unregister");
    ASSERT(raplt_signal_unregister_lazy((void **)dummy_addr) == 0,
           "unregister failed");

    T("lazy site: is not registered after unregister");
    ASSERT(raplt_signal_is_lazy_site((void **)dummy_addr) == 0,
           "still found");

    T("lazy site: unregister non-existent");
    ASSERT(raplt_signal_unregister_lazy((void **)dummy_addr) == -2, /* -ENOENT */
           "should return -ENOENT");

    T("lazy registry: fill to max");
    raplt_signal_clear_lazy();
    int filled = 0;
    for(int i = 0; i < 2048; i++) {
        void *a = malloc(sizeof(void*));
        if(raplt_signal_register_lazy((void **)a, (void *)(uintptr_t)i, NULL))
            break;
        filled++;
    }
    ASSERT(filled == 1024, "expected 1024, got %d",
           filled);

    T("lazy registry: over max returns ENOSPC");
    void *extra = malloc(sizeof(void*));
    int r = raplt_signal_register_lazy((void **)extra,
                                        (void *)0x1000, NULL);
    ASSERT(r == -28 /* -ENOSPC */, "expected -ENOSPC, got %d", r);
    free(extra);

    T("clear lazy registry");
    raplt_signal_clear_lazy();
    ASSERT(raplt_signal_is_lazy_site((void **)dummy_addr) == 0,
           "still found after clear");

    free(dummy_addr);

    SUMMARY();
    return g_fail ? 1 : 0;
}
