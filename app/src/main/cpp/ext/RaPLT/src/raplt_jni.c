/* references: xHook (MIT) */

#include <jni.h>
#include <string.h>

#include "raplt.h"
#include "raplt_log.h"

#define RAPLT_JNI_VERSION JNI_VERSION_1_6

JNIEXPORT jstring JNICALL
Java_raplt_RaPLT_nativeGetVersion(JNIEnv *env, jclass clazz)
{
    (void)clazz;
    return (*env)->NewStringUTF(env, raplt_version());
}

JNIEXPORT jlong JNICALL
Java_raplt_RaPLT_nativeRegisterHook(JNIEnv *env, jclass clazz,
                                     jstring pathname_regex,
                                     jstring symbol,
                                     jlong new_func_ptr,
                                     jint flags)
{
    (void)clazz;
    const char *pathname = (*env)->GetStringUTFChars(env, pathname_regex, NULL);
    const char *sym = (*env)->GetStringUTFChars(env, symbol, NULL);

    raplt_hook_t *hook = raplt_register(pathname, sym,
                                         (void *)(uintptr_t)new_func_ptr,
                                         NULL, (int)flags);

    (*env)->ReleaseStringUTFChars(env, pathname_regex, pathname);
    (*env)->ReleaseStringUTFChars(env, symbol, sym);

    return (jlong)(uintptr_t)hook;
}

JNIEXPORT jboolean JNICALL
Java_raplt_RaPLT_nativeCommit(JNIEnv *env, jclass clazz)
{
    (void)clazz;
    return (raplt_commit() == 0) ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT void JNICALL
Java_raplt_RaPLT_nativeEnableDebug(JNIEnv *env, jclass clazz, jboolean enable)
{
    (void)env; (void)clazz;
    raplt_enable_debug(enable);
}

/*
 * JNI entry point for native library loading.
 * Users should call raplt_register / raplt_commit from their code.
 * This is a convenience for simple cases.
 */
JNIEXPORT jint JNI_OnLoad(JavaVM *vm, void *reserved)
{
    (void)vm; (void)reserved;
    LOGI("RaPLT loaded: %s", raplt_version());
    return RAPLT_JNI_VERSION;
}
