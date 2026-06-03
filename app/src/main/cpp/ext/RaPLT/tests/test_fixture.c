/* test fixture library - target for hook tests
 * compile: gcc -shared -fPIC -fvisibility=default -o libtestfixture.so test_fixture.c */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <pthread.h>

static volatile int g_malloc_count = 0;

__attribute__((visibility("default")))
size_t test_strlen(const char *s)
{
    return strlen(s);
}

__attribute__((visibility("default")))
void *test_malloc(size_t sz)
{
    g_malloc_count++;
    return malloc(sz);
}

__attribute__((visibility("default")))
void test_free(void *p)
{
    free(p);
}

__attribute__((visibility("default")))
ssize_t test_write(int fd, const void *buf, size_t n)
{
    return write(fd, buf, n);
}

__attribute__((visibility("default")))
int test_get_malloc_count(void)
{
    return g_malloc_count;
}

__attribute__((visibility("default")))
void *test_pthread_create(pthread_t *t, const void *a,
                           void *(*fn)(void *), void *arg)
{
    (void)a;
    return (void *)(uintptr_t)pthread_create(t, NULL, fn, arg);
}

__attribute__((visibility("default")))
int fixture_add(int a, int b)
{
    return a + b;
}

__attribute__((visibility("default")))
int fixture_sub(int a, int b)
{
    return a - b;
}
