/* references: bhook (MIT) — dlopen interception via PLT hook */

#include <dlfcn.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include "raplt.h"
#include "raplt_log.h"
#include "raplt_core.h"

int g_monitor_active = 0;

typedef void *(*loader_dlopen_t)(const char *, int, const void *);
static loader_dlopen_t orig_loader_dlopen = NULL;

typedef void *(*dlopen_t)(const char *, int);
static dlopen_t orig_dlopen = NULL;

static void *proxy_loader_dlopen(const char *file, int flags, const void *addr)
{
    void *handle = NULL;
    if(orig_loader_dlopen)
        handle = orig_loader_dlopen(file, flags, addr);
    if(handle) {
        LOGI("dlopen: %s", file ? file : "(null)");
        rescan_libraries();
    }
    return handle;
}

static void *proxy_dlopen(const char *file, int flags)
{
    void *handle = NULL;
    if(orig_dlopen)
        handle = orig_dlopen(file, flags);
    if(handle) {
        LOGI("dlopen: %s", file ? file : "(null)");
        rescan_libraries();
    }
    return handle;
}

int raplt_dl_monitor_init(void)
{
    if(g_monitor_active) return 0;

    /* Hook the committed dlopen — wait for raplt_commit() call */
    /* The proxy functions are registered as batch hooks, applied on commit */

    void *sym = dlsym(RTLD_DEFAULT, "__loader_dlopen");
    if(sym) {
        raplt_register(".*libdl\\.so$", "__loader_dlopen",
                        proxy_loader_dlopen,
                        (void **)&orig_loader_dlopen,
                        RAPLT_FLAG_BATCH);
        g_monitor_active = 1;
        LOGI("dl_monitor: registered __loader_dlopen hook");
        return 0;
    }

    sym = dlsym(RTLD_DEFAULT, "android_dlopen_ext");
    if(sym) {
        raplt_register(".*libdl\\.so$", "android_dlopen_ext",
                        (void *)proxy_dlopen,
                        (void **)&orig_dlopen,
                        RAPLT_FLAG_BATCH);
        g_monitor_active = 1;
        LOGI("dl_monitor: registered android_dlopen_ext hook");
        return 0;
    }

    sym = dlsym(RTLD_DEFAULT, "dlopen");
    if(sym) {
        raplt_register(".*libdl\\.so$", "dlopen",
                        (void *)proxy_dlopen,
                        (void **)&orig_dlopen,
                        RAPLT_FLAG_BATCH);
        g_monitor_active = 1;
        LOGI("dl_monitor: registered dlopen hook");
        return 0;
    }

    LOGW("dl_monitor: no dlopen variant found");
    return -1;
}
