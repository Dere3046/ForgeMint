#ifndef TEST_RUNNER_H
#define TEST_RUNNER_H 1

#include <stdio.h>
#include <stdlib.h>

static int g_pass = 0, g_fail = 0;

#define T(name)  printf("  %-55s ", name)
#define OK()     do { printf("OK\n"); g_pass++; } while(0)
#define FAIL(fmt, ...) do { printf("FAIL " fmt "\n", ##__VA_ARGS__); g_fail++; } while(0)
#define ASSERT(cond, ...) do { if(cond) OK(); else FAIL(__VA_ARGS__); } while(0)
#define SUMMARY() printf("\n%d passed  %d failed  %d total\n", g_pass, g_fail, g_pass+g_fail)

#endif
