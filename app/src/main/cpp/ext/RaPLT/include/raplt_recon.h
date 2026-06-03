/* references: libelfmaster (BSD-2-Clause) — section reconstruction approach */

#ifndef RAPLT_RECON_H
#define RAPLT_RECON_H 1

#include "raplt_elf.h"

#ifdef __cplusplus
extern "C" {
#endif

uintptr_t raplt_recon_find_plt_addr(raplt_lib_t *lib);

int raplt_recon_rebuild_sections(raplt_lib_t *lib);

int raplt_recon_rebuild_symtab_from_eh_frame(raplt_lib_t *lib);

int raplt_recon_scan_plt_stubs(raplt_lib_t *lib,
                                uintptr_t start, uintptr_t end);

int raplt_recon_needed(raplt_lib_t *lib);

#ifdef __cplusplus
}
#endif

#endif /* RAPLT_RECON_H */
