/* test: core API logic */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "raplt.h"
#include "test_runner.h"

int main(void)
{
    T("raplt_register NULL pathname rejected");
    ASSERT(raplt_register(NULL, "malloc", (void *)0x1000, NULL, 0) == NULL,
           "should be NULL");

    T("raplt_register NULL symbol rejected");
    ASSERT(raplt_register(".*", NULL, (void *)0x1000, NULL, 0) == NULL,
           "should be NULL");

    T("raplt_register NULL new_func rejected");
    ASSERT(raplt_register(".*", "malloc", NULL, NULL, 0) == NULL,
           "should be NULL");

    T("raplt_ignore valid regex");
    ASSERT(raplt_ignore(".*/libc\\.so$") == 0,
           "ignore failed");

    T("raplt_ignore NULL rejected");
    ASSERT(raplt_ignore(NULL) == -22, /* -EINVAL */
           "should return -EINVAL");

    T("raplt_unregister NULL rejected");
    ASSERT(raplt_unregister(NULL) == -22,
           "should return -EINVAL");

    T("raplt_hooks_finalize");
    int r = raplt_hooks_finalize();
    ASSERT(r == 0, "returned %d", r);

    T("raplt_txn_begin returns non-NULL");
    raplt_txn_t *txn = raplt_txn_begin();
    ASSERT(txn != NULL, "txn is NULL");

    T("raplt_txn_abort");
    raplt_txn_abort(txn);
    /* no crash = ok */
    OK();

    T("raplt_txn_commit invalid txn");
    ASSERT(raplt_txn_commit(NULL) == -22,
           "should return -EINVAL");

    T("raplt_txn_register invalid txn");
    ASSERT(raplt_txn_register(NULL, ".*", "x", (void *)0x1000, NULL, 0) == NULL,
           "should be NULL");

    T("raplt_exclude_self callable");
    raplt_exclude_self(0);
    raplt_exclude_self(1);
    OK();

    T("raplt_version returns string");
    ASSERT(raplt_version() != NULL, "NULL");
    ASSERT(strlen(raplt_version()) > 0, "empty string");

    T("raplt_enable_debug callable");
    raplt_enable_debug(0);
    raplt_enable_debug(1);
    OK();

    T("raplt_enable_sigsegv_protection callable");
    raplt_enable_sigsegv_protection(0);
    raplt_enable_sigsegv_protection(1);
    OK();

    T("raplt_clear callable");
    raplt_clear();
    OK();

    SUMMARY();
    return g_fail ? 1 : 0;
}
