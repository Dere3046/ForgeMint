/* references: xHook (MIT), libelfmaster (BSD-2-Clause), bhook (MIT) */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <elf.h>
#include <link.h>

#include "raplt_elf.h"
#include "raplt_hash.h"
#include "raplt_util.h"
#include "raplt_log.h"

typedef struct {
    uint8_t *cursor;
    uint8_t *limit;
} leb128_iter_t;

static void leb128_open(leb128_iter_t *it, ElfW(Addr) base, ElfW(Word) sz)
{
    it->cursor = (uint8_t *)base;
    it->limit  = it->cursor + sz;
}

static int leb128_read(leb128_iter_t *it, size_t *out)
{
    size_t val = 0;
    int shift = 0;
    uint8_t b;
    do {
        if(it->cursor >= it->limit) return -1;
        b = *it->cursor++;
        val |= ((size_t)(b & 0x7f)) << shift;
        shift += 7;
    } while(b & 0x80);
    if(shift < (int)(sizeof(val) * 8) && (b & 0x40))
        val |= -((size_t)1 << shift);
    *out = val;
    return 0;
}

enum {
    ANDROID_GROUP_BY_INFO         = 1,
    ANDROID_GROUP_BY_OFFSET_DELTA = 2,
    ANDROID_GROUP_BY_ADDEND       = 4,
    ANDROID_GROUP_HAS_ADDEND      = 8,
};

typedef struct {
    leb128_iter_t stream;
    size_t        total_relocs;
    size_t        group_size;
    size_t        group_flags;
    size_t        group_delta;
    size_t        processed;
    size_t        group_pos;
    ElfW(Addr)    r_offset;
    size_t        r_info;
    ssize_t       r_addend;
    int           with_addend;
    int           alive;
} packed_reloc_iter_t;

static int packed_reloc_init(packed_reloc_iter_t *it,
                              ElfW(Addr) base, ElfW(Word) sz, int rela)
{
    memset(it, 0, sizeof(*it));
    leb128_open(&it->stream, base, sz);
    it->with_addend = rela;
    it->alive = 1;
    if(leb128_read(&it->stream, &it->total_relocs)) return -1;
    if(leb128_read(&it->stream, &it->r_offset))     return -1;
    return 0;
}

static int packed_reloc_read_group(packed_reloc_iter_t *it)
{
    size_t v;
    if(leb128_read(&it->stream, &it->group_size))  return -1;
    if(leb128_read(&it->stream, &it->group_flags)) return -1;
    if(it->group_flags & ANDROID_GROUP_BY_OFFSET_DELTA)
        if(leb128_read(&it->stream, &it->group_delta)) return -1;
    if(it->group_flags & ANDROID_GROUP_BY_INFO)
        if(leb128_read(&it->stream, &it->r_info)) return -1;
    if((it->group_flags & ANDROID_GROUP_HAS_ADDEND) &&
       (it->group_flags & ANDROID_GROUP_BY_ADDEND)) {
        if(!it->with_addend) return -1;
        if(leb128_read(&it->stream, &v)) return -1;
        it->r_addend += (ssize_t)v;
    } else if(0 == (it->group_flags & ANDROID_GROUP_HAS_ADDEND)) {
        it->r_addend = 0;
    }
    it->group_pos = 0;
    return 0;
}

static int packed_reloc_next(packed_reloc_iter_t *it,
                              ElfW(Addr) *off, size_t *info, ssize_t *addend)
{
    if(!it->alive || it->processed >= it->total_relocs) return 0;
    if(it->group_pos == it->group_size) {
        if(packed_reloc_read_group(it)) { it->alive = 0; return 0; }
    }
    if(it->group_flags & ANDROID_GROUP_BY_OFFSET_DELTA)
        it->r_offset += it->group_delta;
    else {
        size_t v;
        if(leb128_read(&it->stream, &v)) { it->alive = 0; return 0; }
        it->r_offset += v;
    }
    if(0 == (it->group_flags & ANDROID_GROUP_BY_INFO)) {
        size_t v;
        if(leb128_read(&it->stream, &v)) { it->alive = 0; return 0; }
        it->r_info = v;
    }
    if(it->with_addend &&
       (it->group_flags & ANDROID_GROUP_HAS_ADDEND) &&
       (0 == (it->group_flags & ANDROID_GROUP_BY_ADDEND))) {
        size_t v;
        if(leb128_read(&it->stream, &v)) { it->alive = 0; return 0; }
        it->r_addend += (ssize_t)v;
    }
    *off    = it->r_offset;
    *info   = it->r_info;
    *addend = it->r_addend;
    it->processed++;
    it->group_pos++;
    it->alive = (it->processed < it->total_relocs);
    return 1;
}

static uint32_t sysv_elf_hash(const uint8_t *name)
{
    uint32_t h = 0, g;
    while(*name) {
        h = (h << 4) + *name++;
        g = h & 0xf0000000u;
        h ^= g >> 24;
        h &= ~g;
    }
    return h;
}

static uint32_t gnu_djb_hash(const uint8_t *name)
{
    uint32_t h = 5381;
    for(int c; (c = *name); name++)
        h = h * 33 + c;
    return h;
}

static ElfW(Phdr) *find_phdr(ElfW(Phdr) *table, ElfW(Half) n, ElfW(Word) type)
{
    for(ElfW(Half) i = 0; i < n; i++)
        if(table[i].p_type == type) return &table[i];
    return NULL;
}

static ElfW(Phdr) *find_phdr2(ElfW(Phdr) *table, ElfW(Half) n,
                               ElfW(Word) type, ElfW(Off) offset)
{
    for(ElfW(Half) i = 0; i < n; i++)
        if(table[i].p_type == type && table[i].p_offset == offset)
            return &table[i];
    return NULL;
}

int raplt_elf_check_header(uintptr_t addr)
{
    ElfW(Ehdr) *hdr = (ElfW(Ehdr) *)addr;
    if(memcmp(hdr->e_ident, ELFMAG, SELFMAG)) return -1;
#if defined(__LP64__)
    if(ELFCLASS64 != hdr->e_ident[EI_CLASS])  return -1;
#else
    if(ELFCLASS32 != hdr->e_ident[EI_CLASS])  return -1;
#endif
    if(ELFDATA2LSB != hdr->e_ident[EI_DATA])  return -1;
    if(EV_CURRENT != hdr->e_ident[EI_VERSION]) return -1;
    if(ET_EXEC != hdr->e_type && ET_DYN != hdr->e_type) return -1;
#if defined(__arm__)
    if(EM_ARM != hdr->e_machine) return -1;
#elif defined(__aarch64__)
    if(EM_AARCH64 != hdr->e_machine) return -1;
#elif defined(__i386__)
    if(EM_386 != hdr->e_machine) return -1;
#elif defined(__x86_64__)
    if(EM_X86_64 != hdr->e_machine) return -1;
#endif
    return 0;
}

typedef int (*dyn_handler_t)(ElfW(Dyn) *entry, raplt_lib_t *lib);

static uintptr_t resolve_ptr(raplt_lib_t *lib, ElfW(Addr) d_ptr)
{
    if(d_ptr >= lib->memory_base) return d_ptr; /* already absolute (glibc relocated) */
    return lib->load_bias + d_ptr;
}

static int on_strtab(ElfW(Dyn) *e, raplt_lib_t *lib)
{
    lib->string_table = (const char *)resolve_ptr(lib, e->d_un.d_ptr);
    return 0;
}
static int on_symtab(ElfW(Dyn) *e, raplt_lib_t *lib)
{
    lib->symbol_table = (ElfW(Sym) *)resolve_ptr(lib, e->d_un.d_ptr);
    return 0;
}
static int on_pltrel(ElfW(Dyn) *e, raplt_lib_t *lib)
{
    lib->use_rela = (e->d_un.d_val == DT_RELA);
    return 0;
}
static int on_jmprel(ElfW(Dyn) *e, raplt_lib_t *lib)
{
    lib->plt_relocs = resolve_ptr(lib, e->d_un.d_ptr);
    return 0;
}
static int on_pltrelsz(ElfW(Dyn) *e, raplt_lib_t *lib)
{
    lib->plt_relocs_sz = e->d_un.d_val;
    return 0;
}
static int on_rel(ElfW(Dyn) *e, raplt_lib_t *lib)
{
    lib->dyn_relocs = resolve_ptr(lib, e->d_un.d_ptr);
    return 0;
}
static int on_relsz(ElfW(Dyn) *e, raplt_lib_t *lib)
{
    lib->dyn_relocs_sz = e->d_un.d_val;
    return 0;
}
static int on_android_rel(ElfW(Dyn) *e, raplt_lib_t *lib)
{
    lib->android_relocs = resolve_ptr(lib, e->d_un.d_ptr);
    return 0;
}
static int on_android_relsz(ElfW(Dyn) *e, raplt_lib_t *lib)
{
    lib->android_relocs_sz = e->d_un.d_val;
    return 0;
}
static int on_relr(ElfW(Dyn) *e, raplt_lib_t *lib)
{
    lib->relative_relocs = resolve_ptr(lib, e->d_un.d_ptr);
    return 0;
}
static int on_relrsz(ElfW(Dyn) *e, raplt_lib_t *lib)
{
    lib->relative_relocs_sz = e->d_un.d_val;
    return 0;
}
static int on_hash(ElfW(Dyn) *e, raplt_lib_t *lib)
{
    if(lib->use_gnu_hash) return 0;
    uint32_t *raw = (uint32_t *)resolve_ptr(lib, e->d_un.d_ptr);
    lib->hash_bucket_count = raw[0];
    lib->hash_chain_len    = raw[1];
    lib->hash_buckets      = &raw[2];
    lib->hash_chain        = &lib->hash_buckets[lib->hash_bucket_count];
    return 0;
}
static int on_gnu_hash(ElfW(Dyn) *e, raplt_lib_t *lib)
{
    uint32_t *raw = (uint32_t *)resolve_ptr(lib, e->d_un.d_ptr);
    lib->hash_bucket_count = raw[0];
    lib->gnu_sym_base      = raw[1];
    lib->gnu_filter_sz     = raw[2];
    lib->gnu_filter_shift  = raw[3];
    lib->gnu_filter        = (ElfW(Addr) *)&raw[4];
    lib->hash_buckets      = (uint32_t *)&lib->gnu_filter[lib->gnu_filter_sz];
    lib->hash_chain        = &lib->hash_buckets[lib->hash_bucket_count];
    lib->use_gnu_hash      = 1;
    return 0;
}

static const struct {
    ElfW(Sword) tag;
    dyn_handler_t fn;
} dyn_dispatch[] = {
    { DT_STRTAB,       on_strtab       },
    { DT_SYMTAB,       on_symtab       },
    { DT_PLTREL,       on_pltrel       },
    { DT_JMPREL,       on_jmprel       },
    { DT_PLTRELSZ,     on_pltrelsz     },
    { DT_REL,          on_rel          },
    { DT_RELA,         on_rel          },
    { DT_RELSZ,        on_relsz        },
    { DT_RELASZ,       on_relsz        },
    { DT_ANDROID_REL,  on_android_rel  },
    { DT_ANDROID_RELA, on_android_rel  },
    { DT_ANDROID_RELSZ,on_android_relsz},
    { DT_ANDROID_RELASZ,on_android_relsz},
    { DT_RELR,         on_relr         },
    { DT_RELRSZ,       on_relrsz       },
    { DT_HASH,         on_hash         },
    { DT_GNU_HASH,     on_gnu_hash     },
};
static const int dyn_dispatch_n = sizeof(dyn_dispatch) / sizeof(dyn_dispatch[0]);

static void parse_dynamic_segment(raplt_lib_t *lib)
{
    ElfW(Dyn) *cursor   = lib->dynamic;
    ElfW(Dyn) *sentinel = lib->dynamic + (lib->dynamic_sz / sizeof(ElfW(Dyn)));
    for(; cursor < sentinel; cursor++) {
        if(cursor->d_tag == DT_NULL) break;
        for(int i = 0; i < dyn_dispatch_n; i++) {
            if(dyn_dispatch[i].tag == cursor->d_tag) {
                dyn_dispatch[i].fn(cursor, lib);
                break;
            }
        }
    }
    if(lib->android_relocs) {
        const char *magic = (const char *)lib->android_relocs;
        if(lib->android_relocs_sz >= 4 &&
           magic[0]=='A' && magic[1]=='P' &&
           magic[2]=='S' && magic[3]=='2') {
            lib->android_relocs += 4;
            lib->android_relocs_sz -= 4;
        } else {
            lib->android_relocs = 0;
            lib->android_relocs_sz = 0;
        }
    }
}

int raplt_elf_init(raplt_lib_t *lib, uintptr_t addr,
                    const char *path, dev_t dev, ino_t ino)
{
    if(!addr || !path) return -EINVAL;
    memset(lib, 0, sizeof(*lib));

    lib->image_path = strdup(path);
    if(!lib->image_path) return -ENOMEM;
    lib->memory_base  = (ElfW(Addr))addr;
    lib->device       = dev;
    lib->file_inode   = ino;
    lib->elf_header   = (ElfW(Ehdr) *)addr;
    lib->prog_headers = (ElfW(Phdr) *)(addr + lib->elf_header->e_phoff);

    ElfW(Phdr) *p0 = find_phdr2(lib->prog_headers, lib->elf_header->e_phnum,
                                 PT_LOAD, 0);
    if(!p0) { free(lib->image_path); lib->image_path = NULL; return -ENOEXEC; }
    if(lib->memory_base < p0->p_vaddr)
    { free(lib->image_path); lib->image_path = NULL; return -ENOEXEC; }
    lib->load_bias = lib->memory_base - p0->p_vaddr;

    ElfW(Phdr) *dhdr = find_phdr(lib->prog_headers, lib->elf_header->e_phnum,
                                  PT_DYNAMIC);
    if(!dhdr) { free(lib->image_path); lib->image_path = NULL; return -ENOEXEC; }
    lib->dynamic    = (ElfW(Dyn) *)(lib->load_bias + dhdr->p_vaddr);
    lib->dynamic_sz = dhdr->p_memsz;

    parse_dynamic_segment(lib);

    if(lib->string_table && lib->symbol_table) {
        uintptr_t s = (uintptr_t)lib->string_table;
        uintptr_t y = (uintptr_t)lib->symbol_table;
        if(s > y)
            lib->symbol_count = (s - y) / sizeof(ElfW(Sym));
    }

    LOGI("init %s base=%p bias=%p syms=%u %s",
         lib->image_path, (void*)lib->memory_base, (void*)lib->load_bias,
         lib->symbol_count, lib->use_gnu_hash ? "GNU_HASH" : "SYSV_HASH");
    return 0;
}

void raplt_elf_fini(raplt_lib_t *lib)
{
    if(lib->got_index) {
        raplt_sym_index_destroy(lib->got_index);
        free(lib->got_index);
        lib->got_index = NULL;
    }
    free(lib->image_path);
    lib->image_path = NULL;
    memset(lib, 0, sizeof(*lib));
}

static void decode_relr(raplt_lib_t *lib)
{
    if(!lib->relative_relocs || !lib->relative_relocs_sz) return;
    ElfW(Relr) *table = (ElfW(Relr) *)lib->relative_relocs;
    size_t n = lib->relative_relocs_sz / sizeof(ElfW(Relr));
    int total = 0;
    for(size_t i = 0; i < n; i++) {
        ElfW(Relr) word = table[i];
        if((word & 1) == 0) {
            total++;
        } else {
            ElfW(Addr) base = (word & ~(ElfW(Relr))1) +
                              lib->load_bias + RAPLT_WORD_SIZE;
            word >>= 1;
            for(int b = 0; word; b++, word >>= 1)
                if(word & 1) total++;
        }
    }
    LOGI("relr: %s processed %d entries", lib->image_path, total);
}

static int lookup_sysv_hash(raplt_lib_t *lib, const char *name, uint32_t *idx)
{
    uint32_t h = sysv_elf_hash((const uint8_t *)name) % lib->hash_bucket_count;
    for(uint32_t i = lib->hash_buckets[h]; i; i = lib->hash_chain[i]) {
        if(strcmp(name, lib->string_table + lib->symbol_table[i].st_name) == 0) {
            *idx = i;
            return 0;
        }
    }
    return -1;
}

static int lookup_gnu_hash(raplt_lib_t *lib, const char *name, uint32_t *idx)
{
    uint32_t h = gnu_djb_hash((const uint8_t *)name);
    int addr_bits = (int)(sizeof(ElfW(Addr)) * 8);
    size_t w = lib->gnu_filter[(h / (uint32_t)addr_bits) % lib->gnu_filter_sz];
    uint32_t m0 = (uint32_t)1 << (h % (uint32_t)addr_bits);
    uint32_t m1 = (uint32_t)1 << ((h >> lib->gnu_filter_shift) %
                                  (uint32_t)addr_bits);
    if((w & ((size_t)m0 | (size_t)m1)) != ((size_t)m0 | (size_t)m1))
        return -1;
    uint32_t bv = lib->hash_buckets[h % lib->hash_bucket_count];
    if(bv < lib->gnu_sym_base) return -1;
    for(uint32_t i = bv; ; i++) {
        uint32_t cw = lib->hash_chain[i - lib->gnu_sym_base];
        if(((h | 1) == (cw | 1)) &&
           strcmp(name, lib->string_table + lib->symbol_table[i].st_name) == 0) {
            *idx = i;
            return 0;
        }
        if(cw & 1) break;
    }
    return -1;
}

static int resolve_symbol_index(raplt_lib_t *lib, const char *name, uint32_t *idx)
{
    if(lib->use_gnu_hash) return lookup_gnu_hash(lib, name, idx);
    return lookup_sysv_hash(lib, name, idx);
}

static void read_reloc_entry(const void *table, size_t i, int rela,
                              ElfW(Addr) *off, size_t *info, ssize_t *addend)
{
    if(rela) {
        const ElfW(Rela) *r = &((const ElfW(Rela) *)table)[i];
        *off    = r->r_offset;
        *info   = r->r_info;
        *addend = r->r_addend;
    } else {
        const ElfW(Rel) *r = &((const ElfW(Rel) *)table)[i];
        *off    = r->r_offset;
        *info   = r->r_info;
        *addend = 0;
    }
}

static int index_got_entry(raplt_lib_t *lib, ElfW(Addr) r_offset,
                            size_t r_info, int is_jmpslot)
{
    uint32_t sym_idx = RAPLT_R_SYM(r_info);
    uint32_t r_type  = RAPLT_R_TYPE(r_info);
    if(is_jmpslot) {
        if(r_type != RAPLT_R_JUMP_SLOT) return 0;
    } else {
        if(r_type != RAPLT_R_GLOB_DAT && r_type != RAPLT_R_ABS) return 0;
    }
    if(sym_idx >= lib->symbol_count) return 0;
    const char *sym_name = lib->string_table + lib->symbol_table[sym_idx].st_name;
    if(!sym_name || !*sym_name) return 0;
    void **got_addr  = (void **)(lib->load_bias + r_offset);
    void  *orig_val  = *got_addr;
    raplt_got_entry_t entry = {
        .addr      = got_addr,
        .original  = orig_val,
        .symidx    = sym_idx,
        .is_jmpslot= is_jmpslot,
    };
    return raplt_sym_index_insert(lib->got_index, sym_name, &entry);
}

int raplt_elf_build_got_index(raplt_lib_t *lib)
{
    if(!lib->got_index) {
        lib->got_index = calloc(1, sizeof(raplt_sym_index_t));
        if(!lib->got_index) return -ENOMEM;
        raplt_sym_index_init(lib->got_index);
    }
    int rela = lib->use_rela;
    size_t esz;

    if(lib->plt_relocs && lib->plt_relocs_sz) {
        esz = rela ? sizeof(ElfW(Rela)) : sizeof(ElfW(Rel));
        size_t n = lib->plt_relocs_sz / esz;
        for(size_t i = 0; i < n; i++) {
            ElfW(Addr) off; size_t info; ssize_t add;
            read_reloc_entry((const void *)lib->plt_relocs, i, rela,
                             &off, &info, &add);
            index_got_entry(lib, off, info, 1);
        }
    }

    if(lib->dyn_relocs && lib->dyn_relocs_sz) {
        esz = rela ? sizeof(ElfW(Rela)) : sizeof(ElfW(Rel));
        size_t n = lib->dyn_relocs_sz / esz;
        for(size_t i = 0; i < n; i++) {
            ElfW(Addr) off; size_t info; ssize_t add;
            read_reloc_entry((const void *)lib->dyn_relocs, i, rela,
                             &off, &info, &add);
            index_got_entry(lib, off, info, 0);
        }
    }

    if(lib->android_relocs && lib->android_relocs_sz) {
        packed_reloc_iter_t it;
        if(0 == packed_reloc_init(&it, lib->android_relocs,
                                   lib->android_relocs_sz, rela)) {
            ElfW(Addr) off; size_t info; ssize_t add;
            while(packed_reloc_next(&it, &off, &info, &add) > 0)
                index_got_entry(lib, off, info, 0);
        }
    }

    if(lib->relative_relocs && lib->relative_relocs_sz)
        decode_relr(lib);

    LOGI("got-index %s size=%zu", lib->image_path, lib->got_index->entry_count);
    return 0;
}

int raplt_elf_find_got(raplt_lib_t *lib, const char *symbol,
                        raplt_got_callback_t cb, void *ud)
{
    if(!lib->got_index) return -1;
    raplt_got_entry_t *entries = NULL;
    size_t count = 0;
    if(raplt_sym_index_lookup(lib->got_index, symbol, &entries, &count))
        return -1;
    for(size_t i = 0; i < count; i++) {
        int r = cb(lib, &entries[i], ud);
        if(r) return r;
    }
    return 0;
}

int raplt_elf_resolve_st_value(raplt_lib_t *lib,
                                const char  *symbol,
                                void       **out_addr)
{
    if(!lib || !symbol || !out_addr) return -1;
    if(!lib->string_table || !lib->symbol_table) return -1;

    uint32_t idx;
    if(resolve_symbol_index(lib, symbol, &idx)) return -1;

    ElfW(Addr) val = lib->symbol_table[idx].st_value;
    if(val == 0) return -1;

    *out_addr = (void *)(lib->load_bias + val);
    return 0;
}
