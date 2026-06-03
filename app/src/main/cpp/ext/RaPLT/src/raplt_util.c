/* references: xHook (MIT), bhook (MIT) */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <unistd.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/sysmacros.h>

#include "raplt_util.h"

int raplt_get_protect(uintptr_t addr, size_t len,
                      const char *pathname, unsigned int *prot)
{
    uintptr_t  start_addr = addr;
    uintptr_t  end_addr = addr + len;
    FILE      *fp;
    char       line[512];
    uintptr_t  start, end;
    char       perm[5];
    int        load0 = 1;
    int        found_all = 0;

    *prot = 0;

    if(NULL == (fp = fopen("/proc/self/maps", "r")))
        return -errno;

    while(fgets(line, sizeof(line), fp))
    {
        if(NULL != pathname)
            if(NULL == strstr(line, pathname)) continue;

        if(sscanf(line, "%"SCNxPTR"-%"SCNxPTR" %4s ", &start, &end, perm) != 3)
            continue;

        if(perm[3] != 'p') continue;

        if(start_addr >= start && start_addr < end)
        {
            if(load0)
            {
                if(perm[0] == 'r') *prot |= PROT_READ;
                if(perm[1] == 'w') *prot |= PROT_WRITE;
                if(perm[2] == 'x') *prot |= PROT_EXEC;
                load0 = 0;
            }
            else
            {
                if(perm[0] != 'r') *prot &= ~PROT_READ;
                if(perm[1] != 'w') *prot &= ~PROT_WRITE;
                if(perm[2] != 'x') *prot &= ~PROT_EXEC;
            }

            if(end_addr <= end)
            {
                found_all = 1;
                break;
            }
            else
                start_addr = end;
        }
    }

    fclose(fp);
    return found_all ? 0 : -ENOENT;
}

int raplt_set_protect(uintptr_t addr, unsigned int prot)
{
    if(0 != mprotect((void *)PAGE_START(addr), PAGE_COVER(addr), (int)prot))
        return -errno;
    return 0;
}

void raplt_flush_cache(uintptr_t addr)
{
    __builtin___clear_cache((void *)PAGE_START(addr),
                            (void *)PAGE_END(addr));
}

int raplt_scan_maps(raplt_map_entry_t **entries, size_t *count)
{
    char       line[512];
    FILE      *fp;
    uintptr_t  base_addr, end_addr;
    char       perm[5], dev_str[16];
    unsigned long inode_num, offset;
    int        pathname_pos;
    char      *pathname;
    size_t     pathname_len, cap = 128, cnt = 0;
    raplt_map_entry_t *arr;

    if(NULL == (fp = fopen("/proc/self/maps", "r")))
        return -errno;

    arr = malloc(cap * sizeof(raplt_map_entry_t));
    if(!arr) { fclose(fp); return -ENOMEM; }

    while(fgets(line, sizeof(line), fp))
    {
        if(sscanf(line, "%"SCNxPTR"-%"SCNxPTR" %4s %lx %15s %lu%n",
                  &base_addr, &end_addr, perm, &offset, dev_str,
                  &inode_num, &pathname_pos) < 6)
            continue;

        if(perm[3] != 'p') continue;
        if(perm[0] != 'r' || perm[2] != 'x') continue;

        while(pathname_pos < (int)(sizeof(line) - 1) &&
              line[pathname_pos] == ' ')
            pathname_pos++;
        if(pathname_pos >= (int)(sizeof(line) - 1)) continue;
        pathname = line + pathname_pos;
        pathname_len = strlen(pathname);
        if(pathname_len == 0) continue;
        if(pathname[pathname_len - 1] == '\n')
            pathname[pathname_len - 1] = '\0';
        if(pathname[0] == '[') continue;

        dev_t dev = 0;
        char *sep = strchr(dev_str, ':');
        if(sep) {
            *sep = '\0';
            dev = makedev(strtoul(dev_str, NULL, 16),
                         strtoul(sep + 1, NULL, 16));
        }

        if(cnt >= cap) {
            cap *= 2;
            raplt_map_entry_t *tmp = realloc(arr, cap * sizeof(raplt_map_entry_t));
            if(!tmp) { free(arr); fclose(fp); return -ENOMEM; }
            arr = tmp;
        }

        arr[cnt].pathname = strdup(pathname);
        arr[cnt].base_addr = base_addr;
        arr[cnt].end_addr = end_addr;
        arr[cnt].dev = dev;
        arr[cnt].inode = (ino_t)inode_num;
        arr[cnt].prot_read  = (perm[0] == 'r');
        arr[cnt].prot_write = (perm[1] == 'w');
        arr[cnt].prot_exec  = (perm[2] == 'x');
        arr[cnt].is_private = (perm[3] == 'p');
        cnt++;
    }

    fclose(fp);
    *entries = arr;
    *count = cnt;
    return 0;
}

int raplt_scan_all_maps(raplt_map_entry_t **entries, size_t *count)
{
    char       line[512];
    FILE      *fp;
    uintptr_t  base_addr, end_addr;
    char       perm[5], dev_str[16];
    unsigned long inode_num, offset;
    int        pathname_pos;
    char      *pathname;
    size_t     pathname_len, cap = 128, cnt = 0;
    raplt_map_entry_t *arr;

    if(NULL == (fp = fopen("/proc/self/maps", "r")))
        return -errno;

    arr = malloc(cap * sizeof(raplt_map_entry_t));
    if(!arr) { fclose(fp); return -ENOMEM; }

    while(fgets(line, sizeof(line), fp))
    {
        if(sscanf(line, "%"SCNxPTR"-%"SCNxPTR" %4s %lx %15s %lu%n",
                  &base_addr, &end_addr, perm, &offset, dev_str,
                  &inode_num, &pathname_pos) < 6)
            continue;

        if(perm[3] != 'p') continue;
        if(perm[0] != 'r') continue;

        while(pathname_pos < (int)(sizeof(line) - 1) &&
              line[pathname_pos] == ' ')
            pathname_pos++;
        if(pathname_pos >= (int)(sizeof(line) - 1)) continue;
        pathname = line + pathname_pos;
        pathname_len = strlen(pathname);
        if(pathname_len == 0) continue;
        if(pathname[pathname_len - 1] == '\n')
            pathname[pathname_len - 1] = '\0';
        if(pathname[0] == '[') continue;

        dev_t dev = 0;
        char *sep = strchr(dev_str, ':');
        if(sep) {
            *sep = '\0';
            dev = makedev(strtoul(dev_str, NULL, 16),
                         strtoul(sep + 1, NULL, 16));
        }

        if(cnt >= cap) {
            cap *= 2;
            raplt_map_entry_t *tmp = realloc(arr, cap * sizeof(raplt_map_entry_t));
            if(!tmp) { free(arr); fclose(fp); return -ENOMEM; }
            arr = tmp;
        }

        arr[cnt].pathname = strdup(pathname);
        arr[cnt].base_addr = base_addr;
        arr[cnt].end_addr = end_addr;
        arr[cnt].dev = dev;
        arr[cnt].inode = (ino_t)inode_num;
        arr[cnt].prot_read  = (perm[0] == 'r');
        arr[cnt].prot_write = (perm[1] == 'w');
        arr[cnt].prot_exec  = (perm[2] == 'x');
        arr[cnt].is_private = (perm[3] == 'p');
        cnt++;
    }

    fclose(fp);
    *entries = arr;
    *count = cnt;
    return 0;
}

void raplt_free_maps(raplt_map_entry_t *entries, size_t count)
{
    for(size_t i = 0; i < count; i++)
        free(entries[i].pathname);
    free(entries);
}

int raplt_backup_page(void *addr, size_t size, void **backup)
{
    void *bak = mmap(NULL, size, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if(bak == MAP_FAILED)
        return -errno;

    void *res = mremap(addr, size, size,
                       MREMAP_MAYMOVE | MREMAP_FIXED | MREMAP_DONTUNMAP, bak);
    if(res != MAP_FAILED) {
        *backup = bak;
        return 0;
    }

    memcpy(bak, addr, size);

    void *new_page = mmap(addr, size, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if(new_page == MAP_FAILED) {
        munmap(bak, size);
        return -errno;
    }

    memcpy(addr, bak, size);
    *backup = bak;
    return 0;
}

int raplt_restore_page(void *addr, size_t size, void *backup)
{
    void *res = mremap(backup, size, size,
                       MREMAP_MAYMOVE | MREMAP_FIXED, addr);
    if(res != MAP_FAILED)
        return 0;

    if(mprotect(addr, size, PROT_READ | PROT_WRITE))
        return -errno;
    memcpy(addr, backup, size);

    unsigned int prot;
    if(0 == raplt_get_protect((uintptr_t)addr, size, NULL, &prot))
        mprotect(addr, size, (int)prot);

    munmap(backup, size);
    return 0;
}

static int uintptr_cmp(const void *a, const void *b)
{
    uintptr_t aa = *(const uintptr_t *)a;
    uintptr_t bb = *(const uintptr_t *)b;
    return (aa > bb) - (aa < bb);
}

int raplt_batch_set_protect(void **addrs, size_t count, unsigned int prot)
{
    if(count == 0) return 0;

    uintptr_t pages[count];
    size_t page_count = 0;

    for(size_t i = 0; i < count; i++) {
        uintptr_t page = PAGE_START((uintptr_t)addrs[i]);
        int dup = 0;
        for(size_t j = 0; j < page_count; j++)
            if(pages[j] == page) { dup = 1; break; }
        if(!dup) pages[page_count++] = page;
    }

    qsort(pages, page_count, sizeof(uintptr_t), uintptr_cmp);

    for(size_t i = 0; i < page_count; i++) {
        if(mprotect((void *)pages[i], RAPLT_PAGE_SIZE, (int)prot))
            return -errno;
    }
    return 0;
}

void raplt_batch_write_got(void **addrs, void **values, size_t count)
{
    for(size_t i = 0; i < count; i++)
        __atomic_store_n((uintptr_t *)addrs[i], (uintptr_t)values[i], __ATOMIC_RELEASE);
    for(size_t i = 0; i < count; i++)
        __builtin___clear_cache((void *)PAGE_START((uintptr_t)addrs[i]),
                                (void *)PAGE_END((uintptr_t)addrs[i]));
}
