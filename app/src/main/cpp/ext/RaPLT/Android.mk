LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE     := raplt
LOCAL_SRC_FILES  := \
    raplt_core.c \
    raplt_elf.c \
    raplt_hash.c \
    raplt_signal.c \
    raplt_util.c \
    raplt_recon.c \
    raplt_dlopen.c \
    raplt_cfi.c \
    raplt_jni.c
LOCAL_C_INCLUDES := $(LOCAL_PATH)/../include
LOCAL_CFLAGS     := -Wall -Wextra -Werror -fvisibility=hidden -std=gnu11
LOCAL_LDLIBS     := -llog
include $(BUILD_SHARED_LIBRARY)
