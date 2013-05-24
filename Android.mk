LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)

LOCAL_SRC_FILES := hexdumpmem.c

LOCAL_MODULE := hexdumpmem
LOCAL_FORCE_STATIC_EXECUTABLE := true
LOCAL_STATIC_LIBRARIES := libc libcutils

include $(BUILD_EXECUTABLE)
