/* RaPLT — PLT hook framework for Android
 * references: xHook (MIT), libelfmaster (BSD-2-Clause), bhook (MIT) */

#ifndef RAPLT_H
#define RAPLT_H 1

#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RAPLT_EXPORT __attribute__((visibility("default")))

#define RAPLT_FLAG_NONE        (0)
#define RAPLT_FLAG_LAZY        (1 << 0)
#define RAPLT_FLAG_BATCH       (1 << 1)
#define RAPLT_FLAG_FORCE       (1 << 2)
#define RAPLT_FLAG_SELF        (1 << 3)

typedef void *(*raplt_proxy_t)(void *);

typedef enum {
    RAPLT_TXN_NONE = 0,
    RAPLT_TXN_ACTIVE,
    RAPLT_TXN_COMMITTED,
    RAPLT_TXN_ROLLED_BACK
} raplt_txn_state_t;

typedef struct raplt_hook raplt_hook_t;
typedef struct raplt_txn raplt_txn_t;

/* hook a symbol in libraries matching pathname_regex */
RAPLT_EXPORT raplt_hook_t *
raplt_register(const char *pathname_regex,
               const char *symbol,
               void       *new_func,
               void      **old_func,
               int         flags);

/* hook a symbol only for the caller library (auto-detected) */
RAPLT_EXPORT raplt_hook_t *
raplt_register_caller(const char *symbol,
                      void       *new_func,
                      void      **old_func,
                      int         flags);

/* exclude a library from all future hooks */
RAPLT_EXPORT int
raplt_ignore(const char *pathname_regex);

/* unregister a hook */
RAPLT_EXPORT int
raplt_unregister(raplt_hook_t *hook);

/* commit all pending hooks */
RAPLT_EXPORT int
raplt_commit(void);

/* lazy resolve from signal handler */
RAPLT_EXPORT int
raplt_lazy_resolve(void *got_entry);

/* transactions */
RAPLT_EXPORT raplt_txn_t *
raplt_txn_begin(void);

RAPLT_EXPORT raplt_hook_t *
raplt_txn_register(raplt_txn_t       *txn,
                   const char        *pathname_regex,
                   const char        *symbol,
                   void              *new_func,
                   void             **old_func,
                   int                flags);

RAPLT_EXPORT int
raplt_txn_commit(raplt_txn_t *txn);

RAPLT_EXPORT void
raplt_txn_abort(raplt_txn_t *txn);

/* register callback for new library load events */
typedef void (*raplt_lib_load_callback_t)(const char *pathname, void *userdata);
RAPLT_EXPORT int
raplt_on_library_load(raplt_lib_load_callback_t cb, void *userdata);

/* exclude raplt's own SO from being hooked (default: enabled) */
RAPLT_EXPORT void
raplt_exclude_self(int enable);

/* finalize hooks permanently */
RAPLT_EXPORT int
raplt_hooks_finalize(void);

RAPLT_EXPORT void
raplt_enable_reconstruction(int enable);

RAPLT_EXPORT void
raplt_enable_debug(int enable);

RAPLT_EXPORT void
raplt_enable_sigsegv_protection(int enable);

RAPLT_EXPORT const char *
raplt_version(void);

RAPLT_EXPORT void
raplt_clear(void);

#ifdef __cplusplus
}
#endif

#endif /* RAPLT_H */
