/* references: xHook (MIT) */

#ifndef RAPLT_LOG_H
#define RAPLT_LOG_H 1

#include <android/log.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef RAPLT_LOG_TAG
#define RAPLT_LOG_TAG "RaPLT"
#endif

#define LOGV(...) __android_log_print(ANDROID_LOG_VERBOSE, RAPLT_LOG_TAG, __VA_ARGS__)
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG,   RAPLT_LOG_TAG, __VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,    RAPLT_LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN,    RAPLT_LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR,   RAPLT_LOG_TAG, __VA_ARGS__)

#ifdef __cplusplus
}
#endif

#endif /* RAPLT_LOG_H */
