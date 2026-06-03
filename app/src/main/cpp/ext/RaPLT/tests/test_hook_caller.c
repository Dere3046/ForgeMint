/* a separate shared library that imports fixture_add/fixture_sub.
 * compiled as a .so so its GOT can be hooked by raplt_register. */
#include <stdio.h>

extern int fixture_add(int, int);
extern int fixture_sub(int, int);

int test_call_add(int a, int b) { return fixture_add(a, b); }
int test_call_sub(int a, int b) { return fixture_sub(a, b); }
