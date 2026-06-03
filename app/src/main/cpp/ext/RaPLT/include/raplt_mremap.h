/* references: ShadowHook (MIT), Linux mremap(2) */

#ifndef RAPLT_MREMAP_H
#define RAPLT_MREMAP_H 1

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

int raplt_mremap_patch_region(uintptr_t start, uintptr_t end,
                               unsigned int orig_perms,
                               void **got_entries, void *new_func,
                               int count, void **backup_out);

int raplt_mremap_restore_region(uintptr_t start, uintptr_t end, void *backup);

#ifdef __cplusplus
}
#endif

#endif
