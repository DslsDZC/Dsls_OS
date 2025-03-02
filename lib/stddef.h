#ifndef _STDDEF_H
#define _STDDEF_H

typedef __SIZE_TYPE__    size_t;
typedef __PTRDIFF_TYPE__ ptrdiff_t;

#ifdef __cplusplus
#define NULL             nullptr
#else
#define NULL             ((void*)0)
#endif

#ifdef __cplusplus
typedef unsigned long   size_t;
#define NULL nullptr
#endif

#ifdef __GNUC__
#define offsetof(type, member)  __builtin_offsetof(type, member)
#else
#define offsetof(type, member)  ((size_t)&((type*)0)->member)
#endif

#if __STDC_VERSION__ >= 201112L
typedef long double      max_align_t;
#endif

#endif
