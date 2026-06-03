/* references: libelfmaster (BSD-2-Clause) — section reconstruction approach */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <elf.h>

#include "raplt_recon.h"
#include "raplt_elf.h"
#include "raplt_log.h"

#define SCAN_WINDOW 128

static uintptr_t text_section_base(raplt_lib_t *lib)
{
    for(ElfW(Half) i = 0; i < lib->elf_header->e_phnum; i++) {
        ElfW(Phdr) *p = &lib->prog_headers[i];
        if(p->p_type == PT_LOAD && (p->p_flags & PF_X)) {
            if(lib->load_bias > (uintptr_t)p->p_vaddr)
                return lib->load_bias;
            return 0;
        }
    }
    return lib->memory_base;
}

int raplt_recon_needed(raplt_lib_t *lib)
{
    if(!lib->elf_header) return 0;
    ElfW(Off)  sh_off  = lib->elf_header->e_shoff;
    ElfW(Half) sh_num  = lib->elf_header->e_shnum;
    ElfW(Half) sh_entsz = lib->elf_header->e_shentsize;
    if(sh_off == 0 || sh_num == 0 || sh_entsz == 0) return 1;
    if(lib->elf_header->e_shstrndx >= sh_num ||
       lib->elf_header->e_shstrndx == 0) return 1;
    return 0;
}

uintptr_t raplt_recon_find_plt_addr(raplt_lib_t *lib)
{
    if(!lib->string_table || !lib->symbol_table) return 0;

    ElfW(Dyn) *cur = lib->dynamic;
    ElfW(Dyn) *end = lib->dynamic + (lib->dynamic_sz / sizeof(ElfW(Dyn)));
    ElfW(Addr) pltgot = 0;
    for(; cur < end; cur++) {
        if(cur->d_tag == DT_PLTGOT) {
            pltgot = lib->load_bias + cur->d_un.d_ptr;
            break;
        }
    }

    ElfW(Addr) marker = 0;
    for(cur = lib->dynamic; cur < end; cur++) {
        if(cur->d_tag == DT_INIT) { marker = lib->load_bias + cur->d_un.d_ptr; break; }
    }
    if(!marker) {
        for(cur = lib->dynamic; cur < end; cur++) {
            if(cur->d_tag == DT_FINI) { marker = lib->load_bias + cur->d_un.d_ptr; break; }
        }
    }

#if defined(__x86_64__)
    if(marker) {
        uintptr_t base = text_section_base(lib);
        uintptr_t offset = marker - base;
        uint8_t *scan = (uint8_t *)lib->memory_base + offset;
        for(int i = 0; i < SCAN_WINDOW; i++, scan++) {
            if(*scan != 0xc3) continue;
            uint8_t *next = scan + 1;
            for(int j = 0; j < 32; j++, next++) {
                if(next[0] == 0xff && next[1] == 0x35) {
                    uintptr_t plt = (uintptr_t)(next - (uint8_t *)lib->memory_base)
                                    + lib->memory_base;
                    return plt;
                }
            }
        }
    }
#elif defined(__i386__)
    if(marker) {
        uintptr_t offset = marker - text_section_base(lib);
        uint8_t *scan = (uint8_t *)lib->memory_base + offset;
        for(int i = 0; i < SCAN_WINDOW; i++, scan++) {
            if(scan[0] == 0x5b && scan[1] == 0xc3) {
                return (uintptr_t)(scan + 2 - (uint8_t *)lib->memory_base) + lib->memory_base;
            }
        }
    }
#elif defined(__aarch64__)
    if(pltgot) return pltgot - 0x20;
#endif
    return pltgot;
}

int raplt_recon_rebuild_sections(raplt_lib_t *lib)
{
    if(!lib->dynamic) return -EINVAL;

    if(lib->symbol_count == 0 && lib->string_table && lib->symbol_table) {
        uintptr_t s = (uintptr_t)lib->string_table;
        uintptr_t y = (uintptr_t)lib->symbol_table;
        if(s > y)
            lib->symbol_count = (s - y) / sizeof(ElfW(Sym));
    }

    if(lib->plt_relocs == 0 && lib->plt_relocs_sz == 0) {
        ElfW(Dyn) *cur = lib->dynamic;
        ElfW(Dyn) *end = lib->dynamic + (lib->dynamic_sz / sizeof(ElfW(Dyn)));
        for(; cur < end; cur++) {
            switch(cur->d_tag) {
            case DT_JMPREL:
                lib->plt_relocs = lib->load_bias + cur->d_un.d_ptr;
                break;
            case DT_PLTRELSZ:
                lib->plt_relocs_sz = cur->d_un.d_val;
                break;
            case DT_PLTREL:
                lib->use_rela = (cur->d_un.d_val == DT_RELA);
                break;
            }
        }
    }

    if(!lib->got_index)
        return raplt_elf_build_got_index(lib);

    return 0;
}

int raplt_recon_rebuild_symtab_from_eh_frame(raplt_lib_t *lib)
{
    (void)lib;
    return 0;
}

int raplt_recon_scan_plt_stubs(raplt_lib_t *lib,
                                uintptr_t start, uintptr_t end)
{
    (void)lib; (void)start; (void)end;
    return 0;
}
