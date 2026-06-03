/* references: xHook (MIT), bhook (MIT), ShadowHook (MIT) */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <regex.h>
#include <dlfcn.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <limits.h>

#include "raplt_elf.h"
#include "raplt_hash.h"
#include "raplt_signal.h"
#include "raplt_util.h"
#include "raplt_log.h"
#include "raplt_core.h"
#include "raplt_cfi.h"
#include "raplt_mremap.h"

static void flog(const char *fmt, ...) { (void)fmt; }

#define RAPLT_RECURSE_STACK_MAX 16
#define RAPLT_MAX_MREMAP_PAGES  256
#define RAPLT_GOT_MAP_SIZE      256

typedef struct {
    struct raplt_registration *reg;
    int                        depth;
} raplt_recurse_frame_t;

typedef struct {
    raplt_recurse_frame_t frames[RAPLT_RECURSE_STACK_MAX];
    int                    count;
} raplt_recurse_stack_t;

typedef struct raplt_registration {
    struct raplt_registration  *next;
    raplt_lib_t                *lib;
    raplt_got_entry_t          *entries;
    size_t                      entry_count;
    char                       *symbol;
    void                       *new_func;
    void                      **old_func;
    int                         flags;
    int                         patched;
} raplt_registration_t;

typedef struct {
    void                  **got_addr;
    raplt_registration_t   *reg;
} raplt_got_map_entry_t;

typedef struct {
    char   *regex_str;
    regex_t regex;
} raplt_ignore_entry_t;

struct raplt_txn {
    raplt_registration_t  *registrations;
    size_t                 count;
    raplt_txn_state_t      state;
};

typedef struct raplt_lib_cb_entry {
    raplt_lib_load_callback_t cb;
    void                      *userdata;
    struct raplt_lib_cb_entry *next;
} raplt_lib_cb_entry_t;

static struct {
    raplt_lib_t          *libs;
    raplt_registration_t *hooks;
    int                   hooks_count;

    raplt_got_map_entry_t got_map[RAPLT_GOT_MAP_SIZE];

    raplt_ignore_entry_t *ignore_list;
    int                   ignore_count;
    int                   ignore_cap;

    raplt_lib_cb_entry_t *load_callbacks;

    pthread_mutex_t       mutex;
    int                   inited;
    int                   exclude_self;
} g_core = {
    .mutex = PTHREAD_MUTEX_INITIALIZER,
    .inited = 0,
    .exclude_self = 1,
};

static struct {
    uintptr_t  start;
    uintptr_t  end;
    void      *backup;
} g_mremap_regions[RAPLT_MAX_MREMAP_PAGES];
static int g_mremap_region_count = 0;

static int find_mremap_region(uintptr_t addr)
{
    for (int i = 0; i < g_mremap_region_count; i++)
        if (addr >= g_mremap_regions[i].start && addr < g_mremap_regions[i].end)
            return i;
    return -1;
}

static void add_mremap_region(uintptr_t start, uintptr_t end, void *backup)
{
    if (g_mremap_region_count < RAPLT_MAX_MREMAP_PAGES) {
        g_mremap_regions[g_mremap_region_count].start  = start;
        g_mremap_regions[g_mremap_region_count].end    = end;
        g_mremap_regions[g_mremap_region_count].backup = backup;
        g_mremap_region_count++;
    }
}

#define RAPLT_MAX_ALL_REGIONS 1024
static struct {
    uintptr_t     start;
    uintptr_t     end;
    unsigned int  perms;
    const char   *pathname;
    dev_t         dev;
    ino_t         inode;
} g_all_regions[RAPLT_MAX_ALL_REGIONS];
static int g_all_region_count = 0;

static int find_region(uintptr_t addr)
{
    for (int i = 0; i < g_all_region_count; i++)
        if (addr >= g_all_regions[i].start && addr < g_all_regions[i].end)
            return i;
    return -1;
}

static pthread_key_t g_recursion_key;
static pthread_once_t g_recursion_key_once = PTHREAD_ONCE_INIT;

static void recursion_key_destroy(void *stack) { free(stack); }
static void recursion_key_init(void) {
    pthread_key_create(&g_recursion_key, recursion_key_destroy);
}

static raplt_recurse_stack_t *get_recurse_stack(void)
{
    pthread_once(&g_recursion_key_once, recursion_key_init);
    raplt_recurse_stack_t *s = pthread_getspecific(g_recursion_key);
    if(!s) {
        s = calloc(1, sizeof(raplt_recurse_stack_t));
        pthread_setspecific(g_recursion_key, s);
    }
    return s;
}

static int is_recursive(raplt_registration_t *reg)
{
    raplt_recurse_stack_t *s = get_recurse_stack();
    for(int i = 0; i < s->count; i++)
        if(s->frames[i].reg == reg) return 1;
    return 0;
}

static void push_recurse(raplt_registration_t *reg)
{
    raplt_recurse_stack_t *s = get_recurse_stack();
    if(s->count < RAPLT_RECURSE_STACK_MAX) {
        s->frames[s->count].reg = reg;
        s->frames[s->count].depth = 0;
        s->count++;
    }
}

static void pop_recurse(raplt_registration_t *reg)
{
    raplt_recurse_stack_t *s = get_recurse_stack();
    for(int i = s->count - 1; i >= 0; i--) {
        if(s->frames[i].reg == reg) { s->count = i; return; }
    }
}

static int is_ignored(const char *pathname)
{
    for(int i = 0; i < g_core.ignore_count; i++)
        if(0 == regexec(&g_core.ignore_list[i].regex, pathname, 0, NULL, 0))
            return 1;
    return 0;
}

static dev_t g_self_dev;
static ino_t g_self_inode;

static int is_self_lib(dev_t dev, ino_t inode)
{
    if(!g_core.exclude_self) return 0;
    if(!g_self_inode) return 0;
    return (dev == g_self_dev && inode == g_self_inode) ? 1 : 0;
}

static int is_self_path(const char *pathname)
{
    if(!pathname) return 0;
    if(!g_core.exclude_self) return 0;
    Dl_info info;
    if(!dladdr((void *)raplt_register, &info)) return 0;
    if(strcmp(info.dli_fname, pathname) == 0) return 1;
    char *abs = realpath(info.dli_fname, NULL);
    if(!abs) return 0;
    int r = strcmp(abs, pathname) == 0;
    free(abs);
    return r;
}

static int detect_caller_lib(char *buf, size_t bufsz)
{
    void *caller = __builtin_return_address(0);
    Dl_info info;
    if(dladdr(caller, &info) && info.dli_fname) {
        strncpy(buf, info.dli_fname, bufsz - 1);
        buf[bufsz - 1] = '\0';
        return 0;
    }
    return -1;
}

static raplt_lib_t *find_lib_for_addr(void **addr)
{
    for(raplt_lib_t *lib = g_core.libs; lib; lib = lib->next)
        if((uintptr_t)addr >= lib->memory_base &&
           (uintptr_t)addr < lib->memory_base + 0x1000000)
            return lib;
    return NULL;
}

static int raplt_patch_got_entry(void **addr, void *value)
{
    int region_idx = find_region((uintptr_t)addr);
    if (region_idx < 0) return -1;

    int idx = find_mremap_region((uintptr_t)addr);
    if (idx >= 0) {
        raplt_write_got(addr, value);
        return 0;
    }
    void *backup_ptr = NULL;
    uintptr_t start  = g_all_regions[region_idx].start;
    uintptr_t end    = g_all_regions[region_idx].end;
    unsigned int perms = g_all_regions[region_idx].perms;

#if !defined(__ANDROID__)
    if (g_all_regions[region_idx].pathname) {
        const char *p = g_all_regions[region_idx].pathname;
        if (strncmp(p, "/usr/", 5) == 0 || strncmp(p, "/lib/", 5) == 0)
            return -1;
    }
#endif

    /* self library: mremap on own pages would deadlock — mprotect instead */
    if (g_all_regions[region_idx].inode &&
        is_self_lib(g_all_regions[region_idx].dev, g_all_regions[region_idx].inode)) {
        if (!(perms & PROT_WRITE)) {
            size_t len = end - start;
            if (mprotect((void *)start, len,
                         PROT_READ | PROT_WRITE | perms))
                return -1;
        }
        raplt_write_got(addr, value);
        return 0;
    }

    void *got_array[1] = { (void *)addr };
    if (raplt_mremap_patch_region(start, end, perms,
                                   got_array, value, 1, &backup_ptr) == 0) {
        add_mremap_region(start, end, backup_ptr);
        return 0;
    }

    if (!(perms & PROT_WRITE)) {
        size_t len = end - start;
        if (mprotect((void *)start, len, PROT_READ | PROT_WRITE | perms) == 0) {
            raplt_write_got(addr, value);
            mprotect((void *)start, len, perms);
            return 0;
        }
        LOGW("mprotect denied for GOT at %p (mseal?)", (void *)start);
    }
    return -1;
}

/* O(1) got_addr -> reg map (open addressing, linear probe) */
static uint32_t got_map_hash(void **addr) {
    return ((uint32_t)(uintptr_t)addr >> 3) % RAPLT_GOT_MAP_SIZE;
}

static void got_map_insert(void **addr, raplt_registration_t *reg)
{
    uint32_t i = got_map_hash(addr);
    for(int n = 0; n < RAPLT_GOT_MAP_SIZE; n++, i = (i + 1) % RAPLT_GOT_MAP_SIZE) {
        if(!g_core.got_map[i].got_addr) {
            g_core.got_map[i].got_addr = addr;
            g_core.got_map[i].reg      = reg;
            return;
        }
    }
}

static raplt_registration_t *got_map_lookup(void **addr)
{
    uint32_t i = got_map_hash(addr);
    for(int n = 0; n < RAPLT_GOT_MAP_SIZE; n++, i = (i + 1) % RAPLT_GOT_MAP_SIZE) {
        if(!g_core.got_map[i].got_addr) return NULL;
        if(g_core.got_map[i].got_addr == addr)
            return g_core.got_map[i].reg;
    }
    return NULL;
}

static void got_map_remove(void **addr)
{
    uint32_t i = got_map_hash(addr);
    for(int n = 0; n < RAPLT_GOT_MAP_SIZE; n++, i = (i + 1) % RAPLT_GOT_MAP_SIZE) {
        if(!g_core.got_map[i].got_addr) return;
        if(g_core.got_map[i].got_addr == addr) {
            g_core.got_map[i].got_addr = NULL;
            g_core.got_map[i].reg = NULL;
            return;
        }
    }
}

static int raplt_core_init_locked(void)
{
    if(g_core.inited) return 0;

    raplt_map_entry_t *maps = NULL;
    size_t map_count = 0;

    if(raplt_scan_maps(&maps, &map_count)) {
        LOGE("failed to scan /proc/self/maps");
        return -1;
    }

    raplt_signal_init();

    {
        Dl_info info;
        if(dladdr((void *)raplt_init, &info) && info.dli_fname) {
            struct stat st;
            if(stat(info.dli_fname, &st) == 0) {
                g_self_dev = st.st_dev;
                g_self_inode = st.st_ino;
            }
        }
    }
    {
        raplt_map_entry_t *all = NULL;
        size_t all_count = 0;
        if (raplt_scan_all_maps(&all, &all_count) == 0) {
            for (size_t i = 0; i < all_count && g_all_region_count < RAPLT_MAX_ALL_REGIONS; i++)
            {
                if (all[i].pathname[0] == '[') continue;
                g_all_regions[g_all_region_count].start = all[i].base_addr;
                g_all_regions[g_all_region_count].end   = all[i].end_addr;
                g_all_regions[g_all_region_count].perms =
                    (all[i].prot_read  ? PROT_READ  : 0) |
                    (all[i].prot_write ? PROT_WRITE : 0) |
                    (all[i].prot_exec  ? PROT_EXEC  : 0);
                g_all_regions[g_all_region_count].pathname = strdup(all[i].pathname);
                g_all_regions[g_all_region_count].dev      = all[i].dev;
                g_all_regions[g_all_region_count].inode    = all[i].inode;
                g_all_region_count++;
            }
            raplt_free_maps(all, all_count);
        }
    }

    for(size_t i = 0; i < map_count; i++) {
        if(is_ignored(maps[i].pathname)) continue;
#if defined(__ANDROID__)
        if(is_self_path(maps[i].pathname)) continue;
#else
        if(is_self_lib(maps[i].dev, maps[i].inode)) continue;
        if(!g_self_inode && is_self_path(maps[i].pathname)) continue;
#endif

        raplt_lib_t *lib = calloc(1, sizeof(raplt_lib_t));
        if(!lib) continue;

        if(raplt_signal_guard_enter()) { free(lib); continue; }

        uintptr_t elf_base = maps[i].base_addr;
        if (raplt_elf_check_header(elf_base) != 0) {
            for (int ri = 0; ri < g_all_region_count; ri++) {
                if (!g_all_regions[ri].pathname ||
                    strcmp(g_all_regions[ri].pathname, maps[i].pathname))
                    continue;
                if (is_self_path(g_all_regions[ri].pathname))
                    continue;
#if !defined(__ANDROID__)
                if (is_self_lib(g_all_regions[ri].dev, g_all_regions[ri].inode))
                    continue;
#endif
                if (raplt_elf_check_header(g_all_regions[ri].start) == 0) {
                    elf_base = g_all_regions[ri].start;
                    break;
                }
            }
            if (elf_base == maps[i].base_addr) {
                raplt_signal_guard_exit(); free(lib); continue;
            }
        }

        int r = raplt_elf_init(lib, elf_base,
                                maps[i].pathname,
                                maps[i].dev, maps[i].inode);
        if(r != 0) { raplt_signal_guard_exit(); free(lib); continue; }

        raplt_signal_guard_exit();

        if(raplt_elf_build_got_index(lib)) {
            raplt_elf_fini(lib); free(lib); continue;
        }

        lib->next = g_core.libs;
        g_core.libs = lib;
    }

    raplt_free_maps(maps, map_count);

    raplt_cfi_disable();

    g_core.inited = 1;
    flog("init done: %zu libs indexed", map_count);
    LOGI("core init: %zu libraries indexed", map_count);
    return 0;
}

static int raplt_patch_registration(raplt_registration_t *reg)
{
    int patched = 0;
    raplt_got_entry_t *entries = reg->entry_count > 0 ? reg->entries : NULL;
    if(!entries) return -1;

    for(size_t i = 0; i < reg->entry_count; i++) {
        void **addr = entries[i].addr;
        void *backup = NULL;

        got_map_insert(addr, reg);

        if(reg->flags & RAPLT_FLAG_LAZY) {
            raplt_signal_register_lazy(addr, reg->new_func, &backup);
            unsigned int old_prot = 0;
            raplt_get_protect((uintptr_t)addr, sizeof(void *), NULL, &old_prot);
            if(!(old_prot & PROT_WRITE))
                raplt_set_protect((uintptr_t)addr, PROT_READ | PROT_WRITE);
            raplt_write_got(addr, reg->new_func);
            if(!(old_prot & PROT_WRITE))
                raplt_set_protect((uintptr_t)addr, old_prot);
            raplt_flush_cache((uintptr_t)addr);
            entries[i].original = backup;
            patched++;
        } else {
            backup = raplt_read_got(addr);
            if (raplt_patch_got_entry(addr, reg->new_func) == 0) {
                entries[i].original = backup;
                patched++;
            }
        }
    }

    reg->patched = patched;
    return (patched > 0) ? 0 : -1;
}

raplt_hook_t *raplt_register(const char *pathname_regex,
                              const char *symbol, void *new_func,
                              void **old_func, int flags)
{
    flog("raplt_register sym=%s", symbol ? symbol : "(null)");
    if(!symbol || !new_func) return NULL;

    pthread_mutex_lock(&g_core.mutex);

    if(!g_core.inited && raplt_core_init_locked()) {
        pthread_mutex_unlock(&g_core.mutex);
        return NULL;
    }

    regex_t regex;
    int use_regex = 0;
    if(pathname_regex) {
        if(regcomp(&regex, pathname_regex, REG_NOSUB) == 0)
            use_regex = 1;
    }

    /* count matches by querying each matching lib */
    size_t match_count = 0;
    raplt_got_entry_t *entries; size_t count;
    for(raplt_lib_t *lib = g_core.libs; lib; lib = lib->next) {
        if(!lib->got_index) continue;
        if(use_regex && regexec(&regex, lib->image_path, 0, NULL, 0))
            continue;
        if(raplt_sym_index_lookup(lib->got_index, symbol, &entries, &count))
            continue;
        match_count += count;
    }

    if(match_count == 0) {
        if(use_regex) regfree(&regex);
        LOGE("symbol not found: %s", symbol);
        pthread_mutex_unlock(&g_core.mutex);
        return NULL;
    }

    raplt_registration_t *reg = calloc(1, sizeof(raplt_registration_t));
    if(!reg) {
        if(use_regex) regfree(&regex);
        pthread_mutex_unlock(&g_core.mutex);
        return NULL;
    }

    reg->symbol   = strdup(symbol);
    reg->new_func = new_func;
    reg->old_func = old_func;
    reg->flags    = flags;
    reg->entries  = malloc(match_count * sizeof(raplt_got_entry_t));
    reg->entry_count = 0;

    for(raplt_lib_t *lib = g_core.libs; lib; lib = lib->next) {
        if(!lib->got_index) continue;
        if(use_regex && regexec(&regex, lib->image_path, 0, NULL, 0))
            continue;
        if(raplt_sym_index_lookup(lib->got_index, symbol, &entries, &count))
            continue;
        for(size_t j = 0; j < count; j++)
            reg->entries[reg->entry_count++] = entries[j];
    }

    if(use_regex) regfree(&regex);

    if(!(flags & RAPLT_FLAG_BATCH)) {
        if (raplt_patch_registration(reg) != 0) {
            LOGI("patch failed for %s", symbol);
            free(reg->symbol);
            free(reg->entries);
            free(reg);
            pthread_mutex_unlock(&g_core.mutex);
            return NULL;
        }
        if (old_func && reg->entry_count > 0)
            *old_func = reg->entries[0].original;
    }

    reg->next = g_core.hooks;
    g_core.hooks = reg;
    g_core.hooks_count++;

    LOGI("register %s -> %p in %zu entries", symbol, new_func, reg->entry_count);
    flog("register ok %s entries=%zu patched=%d", symbol, reg->entry_count, reg->patched);
    pthread_mutex_unlock(&g_core.mutex);

    static volatile int dl_init_done = 0;
    if(!dl_init_done) {
        dl_init_done = 1;
        raplt_dl_monitor_init();
    }

    return (raplt_hook_t *)reg;
}

raplt_hook_t *raplt_register_caller(const char *symbol, void *new_func,
                                     void **old_func, int flags)
{
    char caller_path[PATH_MAX];
    if(detect_caller_lib(caller_path, sizeof(caller_path)))
        return NULL;
    char escaped[PATH_MAX + 16];
    snprintf(escaped, sizeof(escaped), "^%s$", caller_path);
    return raplt_register(escaped, symbol, new_func, old_func, flags);
}

int raplt_ignore(const char *pathname_regex)
{
    if(!pathname_regex) return -EINVAL;

    regex_t regex;
    if(regcomp(&regex, pathname_regex, REG_NOSUB)) return -EINVAL;

    pthread_mutex_lock(&g_core.mutex);

    if(g_core.ignore_count >= g_core.ignore_cap) {
        int new_cap = g_core.ignore_cap ? g_core.ignore_cap * 2 : 8;
        raplt_ignore_entry_t *tmp = realloc(g_core.ignore_list,
                                             new_cap * sizeof(raplt_ignore_entry_t));
        if(!tmp) { regfree(&regex); pthread_mutex_unlock(&g_core.mutex); return -ENOMEM; }
        g_core.ignore_list = tmp;
        g_core.ignore_cap = new_cap;
    }

    g_core.ignore_list[g_core.ignore_count].regex_str = strdup(pathname_regex);
    g_core.ignore_list[g_core.ignore_count].regex = regex;
    g_core.ignore_count++;

    LOGI("ignore: %s", pathname_regex);
    pthread_mutex_unlock(&g_core.mutex);
    return 0;
}

int raplt_unregister(raplt_hook_t *hook)
{
    if(!hook) return -EINVAL;
    pthread_mutex_lock(&g_core.mutex);

    raplt_registration_t *reg = (raplt_registration_t *)hook;
    raplt_registration_t **prev = &g_core.hooks;
    while(*prev) {
        if(*prev == reg) {
            *prev = reg->next;
            for(size_t i = 0; i < reg->entry_count; i++) {
                got_map_remove(reg->entries[i].addr);
                void *got_addr = (void *)reg->entries[i].addr;
                raplt_lib_t *lib = find_lib_for_addr(got_addr);

                /* tier 1: re-resolve from .dynsym st_value */
                void *correct = NULL;
                if(lib && raplt_elf_resolve_st_value(lib, reg->symbol, &correct) == 0) {
                    if (raplt_patch_got_entry(got_addr, correct))
                        LOGW("tier1 restore failed for %s", reg->symbol);
                    continue;
                }

                /* tier 2: read current GOT value */
                void *current = raplt_read_got(got_addr);
                if(current && current != reg->new_func) {
                    continue;
                }

                /* tier 3: cached original fallback */
                if(reg->entries[i].original) {
                    if (raplt_patch_got_entry(got_addr,
                               reg->entries[i].original))
                        LOGW("tier3 restore failed for %s", reg->symbol);
                    continue;
                }

                /* tier 4: cannot recover, keep hook */
                LOGW("cannot restore %s @ %p", reg->symbol, got_addr);
            }
            raplt_signal_unregister_lazy(reg->entries[0].addr);
            free(reg->symbol); free(reg->entries); free(reg);
            g_core.hooks_count--;
            pthread_mutex_unlock(&g_core.mutex);
            return 0;
        }
        prev = &(*prev)->next;
    }

    pthread_mutex_unlock(&g_core.mutex);
    return -ENOENT;
}

int raplt_commit(void)
{
    pthread_mutex_lock(&g_core.mutex);
    int total = 0, success = 0;
    for(raplt_registration_t *reg = g_core.hooks; reg; reg = reg->next) {
        if(reg->patched == 0) {
            if(raplt_patch_registration(reg) == 0) success++;
            total++;
        }
    }
    LOGI("commit: %d/%d hooks", success, total);
    pthread_mutex_unlock(&g_core.mutex);
    return (total == success) ? 0 : -1;
}

int raplt_lazy_resolve(void *got_entry)
{
    raplt_registration_t *reg = got_map_lookup(got_entry);
    if(!reg) return -1;

    raplt_patch_got_entry((void **)got_entry, reg->new_func);
    LOGI("lazy resolve %s @ %p", reg->symbol, got_entry);
    return 0;
}

raplt_txn_t *raplt_txn_begin(void)
{
    raplt_txn_t *txn = calloc(1, sizeof(raplt_txn_t));
    if(txn) txn->state = RAPLT_TXN_ACTIVE;
    return txn;
}

raplt_hook_t *raplt_txn_register(raplt_txn_t *txn,
                                  const char *pathname_regex,
                                  const char *symbol, void *new_func,
                                  void **old_func, int flags)
{
    if(!txn || txn->state != RAPLT_TXN_ACTIVE) return NULL;
    return raplt_register(pathname_regex, symbol, new_func, old_func,
                           flags | RAPLT_FLAG_BATCH);
}

int raplt_txn_commit(raplt_txn_t *txn)
{
    if(!txn || txn->state != RAPLT_TXN_ACTIVE) return -EINVAL;
    pthread_mutex_lock(&g_core.mutex);

    int ok = 1;
    for(raplt_registration_t *reg = g_core.hooks; reg; reg = reg->next) {
        if(reg->patched == 0 && raplt_patch_registration(reg))
            ok = 0;
    }

    txn->state = ok ? RAPLT_TXN_COMMITTED : RAPLT_TXN_ROLLED_BACK;
    LOGI("txn %s", ok ? "committed" : "rolled back");
    pthread_mutex_unlock(&g_core.mutex);
    return ok ? 0 : -1;
}

void raplt_txn_abort(raplt_txn_t *txn)
{
    if(!txn) return;
    txn->state = RAPLT_TXN_ROLLED_BACK;
    free(txn);
}

int raplt_on_library_load(raplt_lib_load_callback_t cb, void *userdata)
{
    if(!cb) return -EINVAL;
    pthread_mutex_lock(&g_core.mutex);

    raplt_lib_cb_entry_t *entry = malloc(sizeof(raplt_lib_cb_entry_t));
    if(!entry) { pthread_mutex_unlock(&g_core.mutex); return -ENOMEM; }
    entry->cb = cb;
    entry->userdata = userdata;
    entry->next = g_core.load_callbacks;
    g_core.load_callbacks = entry;

    pthread_mutex_unlock(&g_core.mutex);
    return 0;
}

static void notify_library_load(const char *pathname)
{
    for(raplt_lib_cb_entry_t *e = g_core.load_callbacks; e; e = e->next)
        e->cb(pathname, e->userdata);
}

void rescan_libraries(void)
{
    if(!g_core.inited) return;

    raplt_map_entry_t *maps = NULL;
    size_t map_count = 0;
    if(raplt_scan_maps(&maps, &map_count)) return;

    for(size_t i = 0; i < map_count; i++) {
        if(is_ignored(maps[i].pathname)) continue;
#if defined(__ANDROID__)
        if(is_self_path(maps[i].pathname)) continue;
#else
        if(is_self_lib(maps[i].dev, maps[i].inode)) continue;
        if(!g_self_inode && is_self_path(maps[i].pathname)) continue;
#endif

        int known = 0;
        for(raplt_lib_t *lib = g_core.libs; lib; lib = lib->next) {
            if(lib->file_inode == maps[i].inode && lib->device == maps[i].dev) {
                known = 1; break;
            }
        }
        if(known) continue;

        raplt_lib_t *lib = calloc(1, sizeof(raplt_lib_t));
        if(!lib) continue;

        if(raplt_signal_guard_enter()) { free(lib); continue; }

        if(raplt_elf_check_header(maps[i].base_addr) != 0) {
            raplt_signal_guard_exit(); free(lib); continue;
        }
        if(raplt_elf_init(lib, maps[i].base_addr, maps[i].pathname,
                           maps[i].dev, maps[i].inode)) {
            raplt_signal_guard_exit(); free(lib); continue;
        }

        raplt_signal_guard_exit();

        if(raplt_elf_build_got_index(lib)) {
            raplt_elf_fini(lib); free(lib); continue;
        }

        lib->next = g_core.libs;
        g_core.libs = lib;

        for(raplt_registration_t *reg = g_core.hooks; reg; reg = reg->next) {
            raplt_got_entry_t *new_entries;
            size_t cnt;
            if(raplt_sym_index_lookup(lib->got_index, reg->symbol, &new_entries, &cnt))
                continue;

            size_t old_n = reg->entry_count;
            raplt_got_entry_t *merged = realloc(reg->entries,
                (old_n + cnt) * sizeof(raplt_got_entry_t));
            if(!merged) continue;
            reg->entries = merged;

            for(size_t j = 0; j < cnt; j++) {
                reg->entries[old_n + j] = new_entries[j];
                got_map_insert(new_entries[j].addr, reg);
                raplt_patch_got_entry(new_entries[j].addr, reg->new_func);
                reg->entry_count++;
            }
        }

        LOGI("new library: %s", maps[i].pathname);
        notify_library_load(maps[i].pathname);
    }

    raplt_free_maps(maps, map_count);
}

void raplt_exclude_self(int enable)
{
    g_core.exclude_self = enable;
}

int raplt_hooks_finalize(void)
{
    pthread_mutex_lock(&g_core.mutex);
    for(raplt_registration_t *reg = g_core.hooks; reg; reg = reg->next)
        for(size_t i = 0; i < reg->entry_count; i++)
            reg->entries[i].original = NULL;
    LOGI("hooks finalized");
    pthread_mutex_unlock(&g_core.mutex);
    return 0;
}

int raplt_init(void)
{
    pthread_mutex_lock(&g_core.mutex);
    int r = raplt_core_init_locked();
    pthread_mutex_unlock(&g_core.mutex);
    return r;
}

void raplt_enable_reconstruction(int enable) { (void)enable; }

void raplt_enable_debug(int enable)      { (void)enable; }

void raplt_enable_sigsegv_protection(int enable) { (void)enable; }

const char *raplt_version(void) { return "RaPLT 1.3.0 (2026)"; }

void raplt_clear(void)
{
    pthread_mutex_lock(&g_core.mutex);

    while(g_core.hooks) {
        raplt_registration_t *reg = g_core.hooks;
        for(size_t i = 0; i < reg->entry_count; i++) {
            got_map_remove(reg->entries[i].addr);
            if(reg->entries[i].original)
                raplt_patch_got_entry(reg->entries[i].addr, reg->entries[i].original);
        }
        g_core.hooks = reg->next;
        free(reg->symbol); free(reg->entries); free(reg);
    }
    g_core.hooks_count = 0;

    raplt_signal_clear_lazy();

    while(g_core.libs) {
        raplt_lib_t *lib = g_core.libs;
        g_core.libs = lib->next;
        raplt_elf_fini(lib); free(lib);
    }

    for(int i = 0; i < g_core.ignore_count; i++) {
        free(g_core.ignore_list[i].regex_str);
        regfree(&g_core.ignore_list[i].regex);
    }
    free(g_core.ignore_list);
    g_core.ignore_list = NULL;
    g_core.ignore_count = 0;
    g_core.ignore_cap = 0;

    while(g_core.load_callbacks) {
        raplt_lib_cb_entry_t *e = g_core.load_callbacks;
        g_core.load_callbacks = e->next;
        free(e);
    }

    memset(g_core.got_map, 0, sizeof(g_core.got_map));
    g_core.inited = 0;
    pthread_mutex_unlock(&g_core.mutex);
    LOGI("core cleared");
}
