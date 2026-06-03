/* references: xHook (MIT), bhook (MIT) */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <setjmp.h>
#include <pthread.h>
#include <sys/mman.h>

#include "raplt_signal.h"
#include "raplt_util.h"
#include "raplt_log.h"

#define RAPLT_MAX_LAZY_SITES 1024

typedef struct {
    void **got_addr;
    void  *callback;
    void  *original;
    int    active;
} raplt_lazy_site_t;

static struct {
    raplt_lazy_site_t sites[RAPLT_MAX_LAZY_SITES];
    int               count;
    pthread_mutex_t   mutex;

    int                 guard_enable;
    volatile int        guard_flag;
    sigjmp_buf          guard_env;

    struct sigaction    old_sigill;
    struct sigaction    old_sigsegv;
    int                 handlers_installed;
} g_sig = {
    .mutex = PTHREAD_MUTEX_INITIALIZER,
    .count = 0,
    .guard_enable = 1,
    .guard_flag = 0,
    .handlers_installed = 0,
};

#if defined(__arm__)
static inline uintptr_t *get_pc_ptr(void *ucontext)
{
    return (uintptr_t *)&((ucontext_t *)ucontext)->uc_mcontext.arm_pc;
}
#elif defined(__aarch64__)
static inline uintptr_t *get_pc_ptr(void *ucontext)
{
    return (uintptr_t *)&((ucontext_t *)ucontext)->uc_mcontext.pc;
}
#elif defined(__i386__)
static inline uintptr_t *get_pc_ptr(void *ucontext)
{
    return (uintptr_t *)&((ucontext_t *)ucontext)->uc_mcontext.gregs[REG_EIP];
}
#elif defined(__x86_64__)
static inline uintptr_t *get_pc_ptr(void *ucontext)
{
    return (uintptr_t *)&((ucontext_t *)ucontext)->uc_mcontext.gregs[REG_RIP];
}
#endif

static inline uintptr_t get_fault_addr(siginfo_t *info)
{
    return (uintptr_t)info->si_addr;
}

static raplt_lazy_site_t *find_lazy_site(void *addr)
{
    for(int i = 0; i < g_sig.count; i++) {
        if(g_sig.sites[i].active && (void *)g_sig.sites[i].got_addr == addr)
            return &g_sig.sites[i];
    }
    return NULL;
}

void raplt_signal_handler(int sig, siginfo_t *info, void *ucontext)
{
    if(sig == SIGSEGV && g_sig.guard_flag) {
        siglongjmp(g_sig.guard_env, 1);
    }
    uintptr_t fault_addr = get_fault_addr(info);
    uintptr_t *pc = get_pc_ptr(ucontext);
    raplt_lazy_site_t *site = find_lazy_site((void *)fault_addr);

    if(site) {
        LOGI("lazy hook triggered: %p (sig %d)", site->got_addr, sig);
        unsigned int old_prot = 0;
        raplt_get_protect((uintptr_t)site->got_addr, sizeof(void *), NULL, &old_prot);
        raplt_set_protect((uintptr_t)site->got_addr, PROT_READ | PROT_WRITE);
        raplt_write_got(site->got_addr, site->callback);

#if defined(__i386__) || defined(__x86_64__)
        *pc += 2;
#elif defined(__aarch64__) || defined(__arm__)
        *pc += 4;
#endif

        if(!(old_prot & PROT_WRITE))
            raplt_set_protect((uintptr_t)site->got_addr, old_prot);
        raplt_flush_cache((uintptr_t)site->got_addr);
        site->active = 0;
        return;
    }

    struct sigaction *old = (sig == SIGILL) ? &g_sig.old_sigill : &g_sig.old_sigsegv;
    if(old->sa_flags & SA_SIGINFO) {
        if(old->sa_sigaction) old->sa_sigaction(sig, info, ucontext);
    } else if(old->sa_handler && old->sa_handler != SIG_DFL && old->sa_handler != SIG_IGN) {
        old->sa_handler(sig);
    } else {
        signal(sig, SIG_DFL);
        raise(sig);
    }
}

int raplt_signal_init(void)
{
    if(g_sig.handlers_installed) return 0;

    struct sigaction act;
    sigemptyset(&act.sa_mask);
    act.sa_sigaction = raplt_signal_handler;
    act.sa_flags = SA_SIGINFO | SA_RESTART;

    if(sigaction(SIGILL, &act, &g_sig.old_sigill)) return -errno;
    if(sigaction(SIGSEGV, &act, &g_sig.old_sigsegv)) {
        sigaction(SIGILL, &g_sig.old_sigill, NULL);
        return -errno;
    }

    g_sig.handlers_installed = 1;
    return 0;
}

int raplt_signal_register_lazy(void **addr, void *callback, void **backup)
{
    pthread_mutex_lock(&g_sig.mutex);
    if(g_sig.count >= RAPLT_MAX_LAZY_SITES) {
        pthread_mutex_unlock(&g_sig.mutex);
        return -ENOSPC;
    }
    int idx = g_sig.count++;
    g_sig.sites[idx].got_addr = addr;
    g_sig.sites[idx].callback = callback;
    g_sig.sites[idx].original = *addr;
    g_sig.sites[idx].active = 1;
    if(backup) *backup = g_sig.sites[idx].original;
    pthread_mutex_unlock(&g_sig.mutex);
    return 0;
}

int raplt_signal_unregister_lazy(void **addr)
{
    pthread_mutex_lock(&g_sig.mutex);
    for(int i = 0; i < g_sig.count; i++) {
        if(g_sig.sites[i].got_addr == addr && g_sig.sites[i].active) {
            g_sig.sites[i].active = 0;
            pthread_mutex_unlock(&g_sig.mutex);
            return 0;
        }
    }
    pthread_mutex_unlock(&g_sig.mutex);
    return -ENOENT;
}

int raplt_signal_is_lazy_site(void **addr)
{
    pthread_mutex_lock(&g_sig.mutex);
    raplt_lazy_site_t *site = find_lazy_site(addr);
    pthread_mutex_unlock(&g_sig.mutex);
    return (site != NULL) ? 1 : 0;
}

void raplt_signal_clear_lazy(void)
{
    pthread_mutex_lock(&g_sig.mutex);
    memset(g_sig.sites, 0, sizeof(g_sig.sites));
    g_sig.count = 0;
    pthread_mutex_unlock(&g_sig.mutex);
}

int raplt_signal_guard_enter(void)
{
    if(!g_sig.guard_enable) return 0;
    g_sig.guard_flag = 1;
    if(sigsetjmp(g_sig.guard_env, 1) == 0)
        return 0;
    LOGW("SIGSEGV caught in guarded section");
    g_sig.guard_flag = 0;
    return 1;
}

void raplt_signal_guard_exit(void)
{
    g_sig.guard_flag = 0;
}
