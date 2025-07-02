#ifndef DSLS_OS_ICONV_H
#define DSLS_OS_ICONV_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// 类型定义
typedef void* iconv_t;

// 公共函数
iconv_t iconv_open(const char* tocode, const char* fromcode);
size_t iconv(iconv_t cd, char** inbuf, size_t *inbytesleft,
             char** outbuf, size_t *outbytesleft);
int iconv_close(iconv_t cd);

#ifdef _WIN32
#else
#define ICONV_CONS T
#endif

// 常用编码类型定义
#define UTF8_ENCODING    "UTF-8"
#define UTF16LE_ENCODING "UTF-16LE"
#define ASCII_ENCODING   "ASCII"

#ifdef __cplusplus
}
#endif

#endif // DSLS_OS_ICONV_H