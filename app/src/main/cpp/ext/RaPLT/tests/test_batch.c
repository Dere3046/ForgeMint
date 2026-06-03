/* test: batch mprotect page merging */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

#include "raplt_util.h"
#include "test_runner.h"

int main(void)
{
    size_t ps = raplt_page_size();

    T("page_size > 0");
    ASSERT(ps >= 4096, "got %zu", ps);

    T("single page batch protect");
    void *mem = mmap(NULL, ps * 2, PROT_READ,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    ASSERT(mem != MAP_FAILED, "mmap failed");

    void *addrs[2];
    addrs[0] = mem;
    addrs[1] = (char *)mem + 8; /* same page */

    int r = raplt_batch_set_protect(addrs, 2, PROT_READ | PROT_WRITE);
    ASSERT(r == 0, "batch_set_protect failed");
    /* verify writable */
    *(volatile char *)mem = 42;

    T("cross-page batch protect");
    void *addrs2[2];
    addrs2[0] = mem;
    addrs2[1] = (char *)mem + ps;

    r = raplt_batch_set_protect(addrs2, 2, PROT_READ | PROT_WRITE);
    ASSERT(r == 0, "cross-page batch failed");
    *(volatile char *)((char *)mem + ps) = 99;

    T("batch write GOT");
    void *values[2] = { (void *)0xabcdef01, (void *)0x98765432 };
    raplt_batch_write_got(addrs2, values, 2);
    ASSERT(*(uintptr_t *)mem == 0xabcdef01,
           "wrong value at addr0: %lx", *(unsigned long *)mem);
    ASSERT(*(uintptr_t *)((char *)mem + ps) == 0x98765432,
           "wrong value at addr1: %lx", *(unsigned long *)((char *)mem + ps));

    munmap(mem, ps * 2);

    T("empty batch protect");
    r = raplt_batch_set_protect(NULL, 0, PROT_READ);
    ASSERT(r == 0, "should return 0 for empty");

    T("PAGE_START macro correct");
    uintptr_t aligned = PAGE_START((uintptr_t)0x1234);
    ASSERT(aligned == 0x1000, "got %lx", (unsigned long)aligned);

    T("PAGE_END macro correct");
    uintptr_t end_addr = PAGE_END((uintptr_t)(0x1234 + sizeof(void *) - 1));
    ASSERT(end_addr == 0x2000, "got %lx", (unsigned long)end_addr);

    SUMMARY();
    return g_fail ? 1 : 0;
}
