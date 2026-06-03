/* references: ShadowHook (MIT), Linux mremap(2)
 *
 * mremap-based GOT page patching.
 * Atomically replaces a mapped region with a writable copy via mremap,
 * avoiding mprotect + W^X issues on modern Android.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/syscall.h>

#include "raplt_mremap.h"
#include "raplt_util.h"
#include "raplt_log.h"

#ifndef MREMAP_MAYMOVE
#define MREMAP_MAYMOVE  1
#endif
#ifndef MREMAP_FIXED
#define MREMAP_FIXED    2
#endif
#ifndef MREMAP_DONTUNMAP
#define MREMAP_DONTUNMAP 4
#endif

#ifndef __NR_mremap
#if defined(__aarch64__)
#define __NR_mremap 216
#elif defined(__arm__)
#define __NR_mremap 163
#elif defined(__x86_64__)
#define __NR_mremap 25
#elif defined(__i386__)
#define __NR_mremap 163
#else
#define __NR_mremap -1
#endif
#endif

static void *sys_mremap(void *old_addr, size_t old_len, size_t new_len,
                         int flags, void *new_addr)
{
#if __NR_mremap > 0
    return (void *)syscall(__NR_mremap, old_addr, old_len, new_len,
                           (unsigned long)flags, new_addr);
#else
    (void)old_addr;(void)old_len;(void)new_len;(void)flags;(void)new_addr;
    return MAP_FAILED;
#endif
}

int raplt_mremap_patch_region(uintptr_t start, uintptr_t end,
                               unsigned int orig_perms,
                               void **got_entries, void *new_func,
                               int count, void **backup_out)
{
    void  *orig = (void *)start;
    size_t len  = end - start;
    size_t ps   = RAPLT_PAGE_SIZE;

    void *backup = mmap(NULL, len, PROT_NONE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (backup == MAP_FAILED) return -1;

    void *result = sys_mremap(orig, len, len,
                               MREMAP_FIXED | MREMAP_MAYMOVE | MREMAP_DONTUNMAP,
                               backup);
    if (result == MAP_FAILED || result != backup) {
        result = sys_mremap(orig, len, len,
                             MREMAP_FIXED | MREMAP_MAYMOVE, backup);
        if (result == MAP_FAILED || result != backup) {
            LOGW("mremap failed for %p (mseal?)", orig);
            munmap(backup, len);
            return -1;
        }
    }

    result = mmap(orig, len, PROT_READ | PROT_WRITE | orig_perms,
                  MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS, -1, 0);
    if (result == MAP_FAILED) {
        sys_mremap(backup, len, len,
                    MREMAP_FIXED | MREMAP_MAYMOVE, orig);
        munmap(backup, len);
        return -1;
    }

    for (size_t src = (size_t)backup, dst = start;
         dst < start + len; src += ps, dst += ps)
        memcpy((void *)dst, (void *)src, ps);

    for (int i = 0; i < count; i++)
        *(void **)got_entries[i] = new_func;

    __builtin___clear_cache(orig, (void *)end);

    *backup_out = backup;
    return 0;
}

int raplt_mremap_restore_region(uintptr_t start, uintptr_t end, void *backup)
{
    size_t len = end - start;
    void *result = sys_mremap(backup, len, len,
                               MREMAP_FIXED | MREMAP_MAYMOVE, (void *)start);
    if (result == MAP_FAILED || (uintptr_t)result != start)
        return -1;
    return 0;
}
