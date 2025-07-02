#ifndef CPUID_H
#define CPUID_H

#include <stdint.h>
// 定义 CPUID 指令的叶子值
#define CPUID_LEAF_VENDOR_ID 0x0
#define CPUID_LEAF_FEATURES 0x1
#define CPUID_LEAF_CACHE_INFO 0x2
#define CPUID_LEAF_EXTENDED_FEATURES 0x7
// 定义 CPUID 指令的子叶值
#define CPUID_SUBLEAF_EXTENDED_FEATURES 0x0
// 定义 CPUID 指令的寄存器索引
#define CPUID_EAX 0
#define CPUID_EBX 1
#define CPUID_ECX 2
#define CPUID_EDX 3
// 定义 CPUID 指令的返回值结构
typedef struct {
    uint32_t eax; // EAX 寄存器
    uint32_t ebx; // EBX 寄存器
    uint32_t ecx; // ECX 寄存器
    uint32_t edx; // EDX 寄存器
} cpuid_result_t;
// 定义 CPUID 指令的函数
static inline cpuid_result_t cpuid(uint32_t leaf, uint32_t subleaf) {
    cpuid_result_t result;
    __asm__ __volatile__ (
        "cpuid"
        : "=a"(result.eax), "=b"(result.ebx), "=c"(result.ecx), "=d"(result.edx)
        : "a"(leaf), "c"(subleaf)
    );
    return result;
}

#endif // CPUID_H