#ifndef LOGGING_H
#define LOGGING_H

#include <errno.h>
#include <string.h>

#include <android/log.h>

#include "misc.h"

#ifndef LOG_TAG
  #define LOG_TAG "zygisk-core"
#endif

/*
 * Match VexZygisk logging policy:
 * release builds are completely silent; debug builds retain every level.
 * PLOGE records the failed operation together with errno and its description.
 */
#ifdef NDEBUG
  #define LOGD(...)
  #define LOGV(...)
  #define LOGI(...)
  #define LOGW(...)
  #define LOGE(...)
  #define LOGF(...)
  #define PLOGE(fmt, args...)
#else
  #define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
  #define LOGV(...) __android_log_print(ANDROID_LOG_VERBOSE, LOG_TAG, __VA_ARGS__)
  #define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
  #define LOGW(...) __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)
  #define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
  #define LOGF(...) __android_log_print(ANDROID_LOG_FATAL, LOG_TAG, __VA_ARGS__)
  #define PLOGE(fmt, args...) LOGE(fmt " failed with %d: %s", ##args, errno, strerror(errno))
#endif

#endif /* LOGGING_H */
