#ifndef STDARG_H
#define STDARG_H

#if defined(__GNUC__) || defined(__clang__)
typedef __builtin_va_list va_list;
#define va_start(ap, last)   __builtin_va_start(ap, last)
#define va_end(ap)           __builtin_va_end(ap)
#define va_arg(ap, type)     __builtin_va_arg(ap, type)
#define va_copy(dest, src)   __builtin_va_copy(dest, src)
#elif defined(_MSC_VER)
typedef va_list va_list;
#define va_start(ap, last)   va_start(ap, last)
#define va_end(ap)           va_end(ap)
#define va_arg(ap, type)     va_arg(ap, type)
#define va_copy(dest, src)   va_copy(dest, src)
#else
#include <stdarg.h>
#endif

#endif // STDARG_H