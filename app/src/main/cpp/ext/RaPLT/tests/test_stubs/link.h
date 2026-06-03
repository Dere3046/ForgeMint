#ifndef TEST_LINK_H_STUB
#define TEST_LINK_H_STUB 1

#include <elf.h>

#ifdef __LP64__
#define ElfW(type) Elf64_##type
#else
#define ElfW(type) Elf32_##type
#endif

#ifndef DT_ANDROID_REL
#define DT_ANDROID_REL      0x6000000f
#endif
#ifndef DT_ANDROID_RELA
#define DT_ANDROID_RELA     0x60000010
#endif
#ifndef DT_ANDROID_RELSZ
#define DT_ANDROID_RELSZ    0x6ffffff1
#endif
#ifndef DT_ANDROID_RELASZ
#define DT_ANDROID_RELASZ   0x6ffffff2
#endif
#ifndef DT_RELR
#define DT_RELR             0x6fffff00
#endif
#ifndef DT_RELRSZ
#define DT_RELRSZ           0x6fffff01
#endif

/* ElfW(Relr) is provided by <elf.h> on modern Linux — no custom typedef needed */

struct dl_phdr_info {
    void *dlpi_addr;
    const char *dlpi_name;
    const void *dlpi_phdr;
    unsigned short dlpi_phnum;
};
int dl_iterate_phdr(int (*c)(struct dl_phdr_info *, size_t, void *), void *);

#endif
