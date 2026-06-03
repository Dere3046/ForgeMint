/* test: SLEB128 decoder for Android packed relocations */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "test_runner.h"

/* copy the leb128 decoder directly for standalone testing */
typedef struct {
    uint8_t *cursor;
    uint8_t *limit;
} leb_t;

static void leb_open(leb_t *it, uint8_t *buf, size_t sz)
{
    it->cursor = buf;
    it->limit  = buf + sz;
}

static int leb_read(leb_t *it, size_t *out)
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

int main(void)
{
    leb_t it;
    size_t v;

    T("decode 0x00");
    uint8_t d0[] = { 0x00 };
    leb_open(&it, d0, 1);
    ASSERT(leb_read(&it, &v) == 0 && v == 0, "got %zu", v);

    T("decode 0x7f = -1 (SLEB128 sign-extend)");
    uint8_t d1[] = { 0x7f };
    leb_open(&it, d1, 1);
    ASSERT(leb_read(&it, &v) == 0 && (ssize_t)v == -1,
           "got %zd", (ssize_t)v);

    T("decode 0x80 0x01 = 128");
    uint8_t d2[] = { 0x80, 0x01 };
    leb_open(&it, d2, 2);
    ASSERT(leb_read(&it, &v) == 0 && v == 128, "got %zu", v);

    T("decode 0xff 0x7f = -1 (SLEB128 signed)");
    uint8_t d3[] = { 0xff, 0x7f };
    leb_open(&it, d3, 2);
    ASSERT(leb_read(&it, &v) == 0 && (ssize_t)v == -1,
           "got %zd", (ssize_t)v);

    T("decode 0xc0 0x00 = 64");
    uint8_t d4[] = { 0xc0, 0x00 };
    leb_open(&it, d4, 2);
    ASSERT(leb_read(&it, &v) == 0 && v == 64, "got %zu", v);

    T("buffer underflow returns -1");
    uint8_t d5[] = { 0x80 };
    leb_open(&it, d5, 1);
    ASSERT(leb_read(&it, &v) == -1, "should fail");

    T("empty buffer returns -1");
    leb_open(&it, NULL, 0);
    ASSERT(leb_read(&it, &v) == -1, "should fail");

    /* Android APS2 packed reloc header simulation */
    T("APS2 group header decode");
    uint8_t aps2[] = {
        0x03,             /* relocation_count = 3 */
        0x10,             /* r_offset = 16 */
        0x02,             /* group_size = 2 */
        0x03,             /* group_flags = GROUP_BY_INFO | GROUP_BY_OFFSET_DELTA */
        0x08,             /* group_delta = 8 */
    };
    leb_open(&it, aps2, sizeof(aps2));

    size_t reloc_count, r_offset;
    size_t group_size, group_flags, group_delta;

    ASSERT(leb_read(&it, &reloc_count) == 0 && reloc_count == 3,
           "reloc_count should be 3, got %zu", reloc_count);
    ASSERT(leb_read(&it, &r_offset) == 0 && r_offset == 16,
           "r_offset should be 16, got %zu", r_offset);
    ASSERT(leb_read(&it, &group_size) == 0 && group_size == 2,
           "group_size should be 2, got %zu", group_size);
    ASSERT(leb_read(&it, &group_flags) == 0 && group_flags == 3,
           "group_flags should be 3, got %zu", group_flags);
    ASSERT(leb_read(&it, &group_delta) == 0 && group_delta == 8,
           "group_delta should be 8, got %zu", group_delta);

    SUMMARY();
    return g_fail ? 1 : 0;
}
