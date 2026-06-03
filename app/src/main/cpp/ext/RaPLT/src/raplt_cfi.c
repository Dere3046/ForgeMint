/* references: bhook (MIT) — CFI slowpath disable approach */

#include <stdint.h>
#include <string.h>
#include <dlfcn.h>
#include <sys/mman.h>

#include "raplt_log.h"
#include "raplt_util.h"

void raplt_cfi_disable(void)
{
#if defined(__aarch64__)
    uint32_t ret_inst = 0xd65f03c0;
    void *slowpath = dlsym(RTLD_DEFAULT, "__cfi_slowpath");
    void *slowpath_diag = dlsym(RTLD_DEFAULT, "__cfi_slowpath_diag");

    if(slowpath) {
        uintptr_t page = PAGE_START((uintptr_t)slowpath);
        if(mprotect((void *)page, RAPLT_PAGE_SIZE,
                     PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
            LOGW("cfi: mprotect denied for __cfi_slowpath (mseal?)");
        } else {
            memcpy(slowpath, &ret_inst, sizeof(ret_inst));
            __builtin___clear_cache(slowpath,
                                    (void *)((uintptr_t)slowpath + sizeof(ret_inst)));
            LOGI("cfi: disabled __cfi_slowpath at %p", slowpath);
        }
    }

    if(slowpath_diag) {
        uintptr_t page = PAGE_START((uintptr_t)slowpath_diag);
        if(mprotect((void *)page, RAPLT_PAGE_SIZE,
                     PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
            LOGW("cfi: mprotect denied for __cfi_slowpath_diag (mseal?)");
        } else {
            memcpy(slowpath_diag, &ret_inst, sizeof(ret_inst));
            __builtin___clear_cache(slowpath_diag,
                                    (void *)((uintptr_t)slowpath_diag + sizeof(ret_inst)));
            LOGI("cfi: disabled __cfi_slowpath_diag at %p", slowpath_diag);
        }
    }

#elif defined(__i386__) || defined(__x86_64__)
    uint8_t ret_inst = 0xc3;
    void *slowpath = dlsym(RTLD_DEFAULT, "__cfi_slowpath");
    void *slowpath_diag = dlsym(RTLD_DEFAULT, "__cfi_slowpath_diag");

    if(slowpath) {
        uintptr_t page = PAGE_START((uintptr_t)slowpath);
        mprotect((void *)page, RAPLT_PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC);
        memcpy(slowpath, &ret_inst, sizeof(ret_inst));
        __builtin___clear_cache(slowpath,
                                (void *)((uintptr_t)slowpath + sizeof(ret_inst)));
        LOGI("cfi: disabled __cfi_slowpath");
    }
    if(slowpath_diag) {
        uintptr_t page = PAGE_START((uintptr_t)slowpath_diag);
        mprotect((void *)page, RAPLT_PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC);
        memcpy(slowpath_diag, &ret_inst, sizeof(ret_inst));
        __builtin___clear_cache(slowpath_diag,
                                (void *)((uintptr_t)slowpath_diag + sizeof(ret_inst)));
        LOGI("cfi: disabled __cfi_slowpath_diag");
    }
#else
    LOGI("cfi: slowpath disable not implemented for this arch");
#endif
}
