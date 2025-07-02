#ifndef INTRIN_H
#define INTRIN_H

#include <stdint.h>

// 内存屏障
#define _ReadBarrier() __asm__ __volatile__ ("" : : : "memory")
#define _WriteBarrier() __asm__ __volatile__ ("" : : : "memory")

// 原子交换
static inline char _InterlockedExchange8(volatile char* target, char value) {
    char result;
    __asm__ __volatile__ (
        "xchgb %b0, %1"
        : "=q" (result), "+m" (*target)
        : "0" (value)
        : "memory"
    );
    return result;
}

// PAUSE 指令
static inline void _mm_pause(void) {
    __asm__ __volatile__ ("pause");
}

// CPUID 指令
static inline void __cpuid(int regs[4], int leaf) {
    __asm__ __volatile__ (
        "cpuid"
        : "=a" (regs[0]), "=b" (regs[1]), "=c" (regs[2]), "=d" (regs[3])
        : "a" (leaf)
    );
}

#endif // INTRIN_H