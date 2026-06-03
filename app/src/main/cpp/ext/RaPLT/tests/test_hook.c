/* end-to-end PLT hook test using a separate caller .so */
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>

#include "raplt.h"
#include "raplt_core.h"
#include "test_runner.h"

static int my_add(int a, int b) { return a + b + 1000; }
static int my_sub(int a, int b) { return b - a; }

int main(void)
{
    void *handle = dlopen("./libtestfixture.so", RTLD_NOW);
    if (!handle) { printf("SKIP: libtestfixture not found\n"); SUMMARY(); return 77; }

    void *caller = dlopen("./libtest_hook_caller.so", RTLD_NOW);
    if (!caller) { printf("SKIP: libtest_hook_caller not found\n"); dlclose(handle); SUMMARY(); return 77; }

    typedef int (*add_t)(int, int);
    typedef int (*sub_t)(int, int);
    add_t add = (add_t)dlsym(caller, "test_call_add");
    sub_t sub = (sub_t)dlsym(caller, "test_call_sub");
    if (!add || !sub) {
        printf("SKIP: caller symbols missing\n");
        dlclose(caller); dlclose(handle); SUMMARY(); return 77;
    }

    T("before hook: test_call_add(1,2) == 3");
    ASSERT(add(1, 2) == 3, "got %d", add(1, 2));

    T("before hook: test_call_sub(4,2) == 2");
    ASSERT(sub(4, 2) == 2, "got %d", sub(4, 2));

    T("raplt_init returns 0");
    ASSERT(raplt_init() == 0, "init failed");

    T("register hook on fixture_add via caller library");
    raplt_hook_t *hk = raplt_register("test_hook_caller", "fixture_add", my_add, NULL, 0);
    ASSERT(hk != NULL, "register returned NULL");

    T("hooked call: test_call_add(1,2) == 1003");
    ASSERT(add(1, 2) == 1003, "got %d", add(1, 2));

    T("unhooked call: test_call_sub(4,2) unchanged == 2");
    ASSERT(sub(4, 2) == 2, "got %d", sub(4, 2));

    T("unregister");
    ASSERT(raplt_unregister(hk) == 0, "unregister failed");

    T("restored: test_call_add(1,2) == 3");
    ASSERT(add(1, 2) == 3, "got %d", add(1, 2));

    /* multi-hook */
    T("register hooks on fixture_add and fixture_sub");
    raplt_hook_t *hk_a = raplt_register("test_hook_caller", "fixture_add", my_add, NULL, 0);
    raplt_hook_t *hk_s = raplt_register("test_hook_caller", "fixture_sub", my_sub, NULL, 0);
    ASSERT(hk_a != NULL && hk_s != NULL, "register failed a=%p s=%p", (void *)hk_a, (void *)hk_s);

    T("hooked test_call_add(1,2) == 1003");
    ASSERT(add(1, 2) == 1003, "got %d", add(1, 2));

    T("hooked test_call_sub(4,2) == -2 (reversed)");
    ASSERT(sub(4, 2) == -2, "got %d", sub(4, 2));

    T("unregister both");
    ASSERT(raplt_unregister(hk_a) == 0, "unregister add failed");
    ASSERT(raplt_unregister(hk_s) == 0, "unregister sub failed");

    T("restored test_call_add(1,2) == 3");
    ASSERT(add(1, 2) == 3, "got %d", add(1, 2));

    T("restored test_call_sub(4,2) == 2");
    ASSERT(sub(4, 2) == 2, "got %d", sub(4, 2));

    dlclose(caller); dlclose(handle);
    SUMMARY();
    return g_fail ? 1 : 0;
}
