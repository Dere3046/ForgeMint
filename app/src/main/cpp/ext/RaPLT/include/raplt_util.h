/* references: xHook (MIT), bhook (MIT) */

#ifndef RAPLT_UTIL_H
#define RAPLT_UTIL_H 1

#include <stdint.h>
#include <stddef.h>
#include <unistd.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

static inline size_t raplt_page_size(void) {
    static size_t sz = 0;
    if(!sz) sz = (size_t)sysconf(_SC_PAGESIZE);
    return sz;
}
#define RAPLT_PAGE_SIZE  raplt_page_size()
#define RAPLT_PAGE_MASK  (~(RAPLT_PAGE_SIZE - (size_t)1))
#define PAGE_START(addr)  ((uintptr_t)(addr) & RAPLT_PAGE_MASK)
#define PAGE_END(addr)    (PAGE_START((uintptr_t)(addr) + sizeof(uintptr_t) - 1) + RAPLT_PAGE_SIZE)
#define PAGE_COVER(addr)  (PAGE_END(addr) - PAGE_START(addr))

typedef struct {
    char      *pathname;
    uintptr_t  base_addr;
    uintptr_t  end_addr;
    dev_t      dev;
    ino_t      inode;
    int        prot_read;
    int        prot_write;
    int        prot_exec;
    int        is_private;
} raplt_map_entry_t;

int raplt_scan_maps(raplt_map_entry_t **entries, size_t *count);

int raplt_scan_all_maps(raplt_map_entry_t **entries, size_t *count);

void raplt_free_maps(raplt_map_entry_t *entries, size_t count);

int raplt_get_protect(uintptr_t addr, size_t len,
                      const char *pathname, unsigned int *prot);

int raplt_set_protect(uintptr_t addr, unsigned int prot);

void raplt_flush_cache(uintptr_t addr);

static inline void *raplt_read_got(void **addr)
{
    return (void *)__atomic_load_n((uintptr_t *)addr, __ATOMIC_ACQUIRE);
}

static inline void raplt_write_got(void **addr, void *value)
{
    __atomic_store_n((uintptr_t *)addr, (uintptr_t)value, __ATOMIC_RELEASE);
}

static inline int raplt_cas_got(void **addr, void *expected, void *desired)
{
    uintptr_t exp = (uintptr_t)expected;
    return __atomic_compare_exchange_n((uintptr_t *)addr, &exp,
                                       (uintptr_t)desired,
                                       0, __ATOMIC_RELEASE,
                                       __ATOMIC_ACQUIRE) ? 0 : -1;
}

int raplt_backup_page(void *addr, size_t size, void **backup);

int raplt_restore_page(void *addr, size_t size, void *backup);

/* batch mprotect: group addresses by page, call mprotect once per page */
int raplt_batch_set_protect(void **addrs, size_t count, unsigned int prot);

/* batch write: write values to GOT entries grouped under the same page */
void raplt_batch_write_got(void **addrs, void **values, size_t count);

#ifdef __cplusplus
}
#endif

#endif /* RAPLT_UTIL_H */
