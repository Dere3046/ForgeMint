#ifndef ANDROID_LOG_H_STUB
#define ANDROID_LOG_H_STUB 1

#include <stdio.h>

typedef enum {
    ANDROID_LOG_VERBOSE = 2,
    ANDROID_LOG_DEBUG   = 3,
    ANDROID_LOG_INFO    = 4,
    ANDROID_LOG_WARN    = 5,
    ANDROID_LOG_ERROR   = 6,
} android_LogPriority;

#define __android_log_print(prio, tag, ...) \
    printf("[%s] ", tag); printf(__VA_ARGS__); printf("\n")

#endif
