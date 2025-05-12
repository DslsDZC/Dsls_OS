#ifndef _STDINT_H
#define _STDINT_H

typedef signed char        int8_t;
typedef short              int16_t;
typedef int                int32_t;
typedef long long          int64_t;
typedef unsigned char      uint8_t;
typedef unsigned short     uint16_t;
typedef unsigned int       uint32_t;
typedef unsigned long long uint64_t;

typedef int8_t   int_least8_t;
typedef uint8_t  uint_least8_t;
typedef int16_t  int_least16_t;
typedef uint16_t uint_least16_t;
typedef int32_t  int_least32_t;
typedef uint32_t uint_least32_t;
typedef int64_t  int_least64_t;
typedef uint64_t uint_least64_t;

typedef int8_t   int_fast8_t;
typedef uint8_t  uint_fast8_t;
typedef int      int_fast16_t;
typedef unsigned uint_fast16_t;
typedef int      int_fast32_t;
typedef unsigned uint_fast32_t;
typedef long     int_fast64_t;
typedef unsigned long uint_fast64_t;

typedef int64_t  intmax_t;
typedef uint64_t uintmax_t;

typedef long      intptr_t;
typedef unsigned long uintptr_t;


#define INT8_MIN    (-0x7F-1)
#define INT16_MIN   (-0x7FFF-1)
#define INT32_MIN   (-0x7FFFFFFF-1)
#define INT64_MIN   (-0x7FFFFFFFFFFFFFFFLL-1)

#define INT8_MAX    0x7F
#define INT16_MAX   0x7FFF
#define INT32_MAX   0x7FFFFFFF
#define INT64_MAX   0x7FFFFFFFFFFFFFFFLL

#define UINT8_MAX   0xFF
#define UINT16_MAX  0xFFFF
#define UINT32_MAX  0xFFFFFFFFU
#define UINT64_MAX  0xFFFFFFFFFFFFFFFFULL

#define INTPTR_MIN  INT64_MIN
#define INTPTR_MAX  INT64_MAX
#define UINTPTR_MAX UINT64_MAX

#define INTMAX_MIN  INT64_MIN
#define INTMAX_MAX  INT64_MAX
#define UINTMAX_MAX UINT64_MAX

#define INT8_C(x)   (x)
#define UINT8_C(x)  (x)
#define INT16_C(x)  (x)
#define UINT16_C(x) (x)
#define INT32_C(x)  (x)
#define UINT32_C(x) (x ## U)
#define INT64_C(x)  (x ## LL)
#define UINT64_C(x) (x ## ULL)


// 添加链表节点结构体定义
struct list_head {
    struct list_head *prev;
    struct list_head *next;
};

struct timer_list {
    struct list_head entry;         // 定时器链表节点
    unsigned long expires;          // 到期时间（jiffies为单位）
    void (*function)(unsigned long);// 回调函数指针
    unsigned long data;             // 传递给回调函数的数据
    unsigned int flags;             // 状态标志位
    struct tvec_base *base;         // 所属定时器基准
    int slack;                      // 时间容忍度（纳秒级）
#ifdef CONFIG_LOCKDEP
    struct lockdep_map lockdep_map; // 锁依赖映射
#endif
#if defined(CONFIG_SMP) && defined(CONFIG_NO_HZ_COMMON)
    unsigned long timer_start_pid;  // 启动定时器的进程ID
    char timer_start_comm[16];      // 启动定时器的进程名
#endif
};

#endif