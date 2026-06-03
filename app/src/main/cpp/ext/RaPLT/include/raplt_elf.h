/* references: xHook (MIT), libelfmaster (BSD-2-Clause), bhook (MIT) */

#ifndef RAPLT_ELF_H
#define RAPLT_ELF_H 1

#include <stdint.h>
#include <stddef.h>
#include <elf.h>
#include <link.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(__arm__)
#define RAPLT_R_JUMP_SLOT R_ARM_JUMP_SLOT
#define RAPLT_R_GLOB_DAT  R_ARM_GLOB_DAT
#define RAPLT_R_ABS       R_ARM_ABS32
#define RAPLT_R_RELATIVE  R_ARM_RELATIVE
#elif defined(__aarch64__)
#define RAPLT_R_JUMP_SLOT R_AARCH64_JUMP_SLOT
#define RAPLT_R_GLOB_DAT  R_AARCH64_GLOB_DAT
#define RAPLT_R_ABS       R_AARCH64_ABS64
#define RAPLT_R_RELATIVE  R_AARCH64_RELATIVE
#elif defined(__i386__)
#define RAPLT_R_JUMP_SLOT R_386_JMP_SLOT
#define RAPLT_R_GLOB_DAT  R_386_GLOB_DAT
#define RAPLT_R_ABS       R_386_32
#define RAPLT_R_RELATIVE  R_386_RELATIVE
#elif defined(__x86_64__)
#define RAPLT_R_JUMP_SLOT R_X86_64_JUMP_SLOT
#define RAPLT_R_GLOB_DAT  R_X86_64_GLOB_DAT
#define RAPLT_R_ABS       R_X86_64_64
#define RAPLT_R_RELATIVE  R_X86_64_RELATIVE
#endif

#if defined(__LP64__)
#define RAPLT_R_SYM(info)  ELF64_R_SYM(info)
#define RAPLT_R_TYPE(info) ELF64_R_TYPE(info)
#define RAPLT_WORD_SIZE    8
#else
#define RAPLT_R_SYM(info)  ELF32_R_SYM(info)
#define RAPLT_R_TYPE(info) ELF32_R_TYPE(info)
#define RAPLT_WORD_SIZE    4
#endif

typedef struct {
    void     **addr;
    void      *original;
    uint32_t   symidx;
    int        is_jmpslot;
} raplt_got_entry_t;

typedef struct raplt_lib raplt_lib_t;

struct raplt_lib {
    char        *image_path;
    dev_t        device;
    ino_t        file_inode;
    uintptr_t    memory_base;
    uintptr_t    load_bias;

    ElfW(Ehdr)  *elf_header;
    ElfW(Phdr)  *prog_headers;

    ElfW(Dyn)   *dynamic;
    ElfW(Word)   dynamic_sz;

    const char  *string_table;
    ElfW(Sym)   *symbol_table;
    ElfW(Word)   symbol_count;

    ElfW(Addr)   plt_relocs;
    ElfW(Word)   plt_relocs_sz;
    ElfW(Addr)   dyn_relocs;
    ElfW(Word)   dyn_relocs_sz;
    ElfW(Addr)   android_relocs;
    ElfW(Word)   android_relocs_sz;
    ElfW(Addr)   relative_relocs;
    ElfW(Word)   relative_relocs_sz;

    int          use_gnu_hash;
    uint32_t    *hash_buckets;
    uint32_t     hash_bucket_count;
    uint32_t    *hash_chain;
    uint32_t     hash_chain_len;
    uint32_t     gnu_sym_base;
    ElfW(Addr)  *gnu_filter;
    uint32_t     gnu_filter_sz;
    uint32_t     gnu_filter_shift;

    int          use_rela;

    struct raplt_sym_index *got_index;
    raplt_lib_t *next;
};

typedef int (*raplt_got_callback_t)(raplt_lib_t       *lib,
                                     raplt_got_entry_t *entry,
                                     void              *userdata);

int raplt_elf_init(raplt_lib_t *lib,
                   uintptr_t    addr,
                   const char  *path,
                   dev_t        dev,
                   ino_t        ino);

int raplt_elf_build_got_index(raplt_lib_t *lib);

int raplt_elf_find_got(raplt_lib_t         *lib,
                       const char          *symbol,
                       raplt_got_callback_t callback,
                       void                *userdata);

int raplt_elf_reconstruct(raplt_lib_t *lib, const char *pathname);

int raplt_elf_check_header(uintptr_t addr);

void raplt_elf_fini(raplt_lib_t *lib);

int raplt_elf_resolve_st_value(raplt_lib_t *lib,
                                const char  *symbol,
                                void       **out_addr);

#ifdef __cplusplus
}
#endif

#endif /* RAPLT_ELF_H */
