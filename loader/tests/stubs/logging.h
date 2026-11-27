#ifndef TEST_LOGGING_H
#define TEST_LOGGING_H
#include <elf.h>
#define ELF_ST_TYPE(info) ELF64_ST_TYPE(info)
#define LOGE(...) ((void)0)
#define LOGW(...) ((void)0)
#define LOGI(...) ((void)0)
#define LOGD(...) ((void)0)
#define LOGV(...) ((void)0)
#define LOGF(...) ((void)0)
#define PLOGE(...) ((void)0)
#endif
