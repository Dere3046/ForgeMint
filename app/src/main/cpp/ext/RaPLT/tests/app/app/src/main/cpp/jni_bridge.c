#include <jni.h>
#include <android/log.h>
#include "raplt.h"
#include "raplt_core.h"

#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, "RaPLT", __VA_ARGS__)

extern int calc_add(int, int);
extern int calc_sub(int, int);
extern int calc_mul(int, int);
extern int calc_div(int, int);

static raplt_hook_t *hk_add, *hk_sub, *hk_mul, *hk_div;
static const char *R = ".*base\\.apk.*";

static int my_add(int a, int b) {
    LOGI("calc_add(%d,%d) → HOOKED = %d", a, b, a + b + 1000);
    return a + b + 1000;
}
static int my_sub(int a, int b) {
    LOGI("calc_sub(%d,%d) → HOOKED = %d", a, b, b - a);
    return b - a;
}
static int my_mul(int a, int b) {
    LOGI("calc_mul(%d,%d) → HOOKED = %d", a, b, a * b + a);
    return a * b + a;
}
static int my_div(int a, int b) {
    LOGI("calc_div(%d,%d) → HOOKED = %d", a, b, a * b);
    return a * b;
}

JNIEXPORT jint JNICALL
Java_com_raplt_test_MainActivity_nativeAdd(JNIEnv *e, jobject o, jint a, jint b) {
    (void)e; (void)o; return calc_add(a, b);
}
JNIEXPORT jint JNICALL
Java_com_raplt_test_MainActivity_nativeSub(JNIEnv *e, jobject o, jint a, jint b) {
    (void)e; (void)o; return calc_sub(a, b);
}
JNIEXPORT jint JNICALL
Java_com_raplt_test_MainActivity_nativeMul(JNIEnv *e, jobject o, jint a, jint b) {
    (void)e; (void)o; return calc_mul(a, b);
}
JNIEXPORT jint JNICALL
Java_com_raplt_test_MainActivity_nativeDiv(JNIEnv *e, jobject o, jint a, jint b) {
    (void)e; (void)o; return calc_div(a, b);
}


JNIEXPORT jint JNICALL
Java_com_raplt_test_MainActivity_nativeHookAdd(JNIEnv *e, jobject o) {
    (void)e; (void)o;
    if(!hk_add) hk_add = raplt_register(R, "calc_add", my_add, NULL, 0);
    return hk_add ? 1 : 0;
}
JNIEXPORT jint JNICALL
Java_com_raplt_test_MainActivity_nativeHookSub(JNIEnv *e, jobject o) {
    (void)e; (void)o;
    if(!hk_sub) hk_sub = raplt_register(R, "calc_sub", my_sub, NULL, 0);
    return hk_sub ? 1 : 0;
}
JNIEXPORT jint JNICALL
Java_com_raplt_test_MainActivity_nativeHookMul(JNIEnv *e, jobject o) {
    (void)e; (void)o;
    if(!hk_mul) hk_mul = raplt_register(R, "calc_mul", my_mul, NULL, 0);
    return hk_mul ? 1 : 0;
}
JNIEXPORT jint JNICALL
Java_com_raplt_test_MainActivity_nativeHookDiv(JNIEnv *e, jobject o) {
    (void)e; (void)o;
    if(!hk_div) hk_div = raplt_register(R, "calc_div", my_div, NULL, 0);
    return hk_div ? 1 : 0;
}

JNIEXPORT jint JNICALL
Java_com_raplt_test_MainActivity_nativeUnhookAdd(JNIEnv *e, jobject o) {
    (void)e; (void)o;
    if(hk_add) { raplt_unregister(hk_add); hk_add = NULL; }
    return 0;
}
JNIEXPORT jint JNICALL
Java_com_raplt_test_MainActivity_nativeUnhookSub(JNIEnv *e, jobject o) {
    (void)e; (void)o;
    if(hk_sub) { raplt_unregister(hk_sub); hk_sub = NULL; }
    return 0;
}
JNIEXPORT jint JNICALL
Java_com_raplt_test_MainActivity_nativeUnhookMul(JNIEnv *e, jobject o) {
    (void)e; (void)o;
    if(hk_mul) { raplt_unregister(hk_mul); hk_mul = NULL; }
    return 0;
}
JNIEXPORT jint JNICALL
Java_com_raplt_test_MainActivity_nativeUnhookDiv(JNIEnv *e, jobject o) {
    (void)e; (void)o;
    if(hk_div) { raplt_unregister(hk_div); hk_div = NULL; }
    return 0;
}
JNIEXPORT jint JNICALL
Java_com_raplt_test_MainActivity_nativeUnhookAll(JNIEnv *e, jobject o) {
    (void)e; (void)o;
    if(hk_add) { raplt_unregister(hk_add); hk_add = NULL; }
    if(hk_sub) { raplt_unregister(hk_sub); hk_sub = NULL; }
    if(hk_mul) { raplt_unregister(hk_mul); hk_mul = NULL; }
    if(hk_div) { raplt_unregister(hk_div); hk_div = NULL; }
    return 0;
}
JNIEXPORT jint JNICALL
Java_com_raplt_test_MainActivity_nativeVersion(JNIEnv *e, jobject o) {
    (void)o; return (*e)->NewStringUTF(e, raplt_version());
}

/* RaPLTApp init — runs in Application.attachBaseContext, before Activity */
JNIEXPORT void JNICALL
Java_com_raplt_test_RaPLTApp_nativeInit(JNIEnv *e, jobject o) {
    (void)e; (void)o;
    LOGI("init=%d", raplt_init());
}
