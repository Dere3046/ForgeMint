/* references: xHook (MIT), bhook (MIT) */

#ifndef RAPLT_SIGNAL_H
#define RAPLT_SIGNAL_H 1

#include <signal.h>
#include <setjmp.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(__arm__)
#define RAPLT_TRAP_SIZE   4
#elif defined(__aarch64__)
#define RAPLT_TRAP_SIZE   4
#elif defined(__i386__) || defined(__x86_64__)
#define RAPLT_TRAP_SIZE   2
#endif

int raplt_signal_init(void);

void raplt_signal_handler(int sig, siginfo_t *info, void *ucontext);

int raplt_signal_register_lazy(void **addr, void *callback, void **backup);

int raplt_signal_unregister_lazy(void **addr);

int raplt_signal_is_lazy_site(void **addr);

void raplt_signal_clear_lazy(void);

int raplt_signal_guard_enter(void);

void raplt_signal_guard_exit(void);

#ifdef __cplusplus
}
#endif

#endif /* RAPLT_SIGNAL_H */
