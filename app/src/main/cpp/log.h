#ifndef FM_LOG_H
#define FM_LOG_H

#include <fcntl.h>
#include <unistd.h>

#ifdef __ANDROID__
#include <android/log.h>
#define LOG(fmt, ...) do { \
    __android_log_print(ANDROID_LOG_INFO, "ForgeMint", fmt, ##__VA_ARGS__); \
} while(0)
#define LOGD(fmt, ...) do { \
    __android_log_print(ANDROID_LOG_DEBUG, "ForgeMint", fmt, ##__VA_ARGS__); \
} while(0)
#else
#include <stdio.h>
#define LOG(fmt, ...)  fprintf(stderr, "ForgeMint [I] " fmt "\n", ##__VA_ARGS__)
#define LOGD(fmt, ...) fprintf(stderr, "ForgeMint [D] " fmt "\n", ##__VA_ARGS__)
#endif

#endif
