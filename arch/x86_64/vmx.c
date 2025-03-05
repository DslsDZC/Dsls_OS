#include <stdint.h>
#include "slab.h"
#include "vmx.h"

static uint8_t* vmxon_region;  // VMXON 区域指针
static uint8_t* vmcs_region;   // VMCS 区域指针

// 检查 CPU 是否支持 VT-x
int vmx_support() {
    uint32_t eax, ecx;
    __asm__ volatile("cpuid" 
        : "=a"(eax), "=c"(ecx) 
        : "a"(1), "c"(0));
    return (ecx & (1 << 5)) != 0; // 检查 ECX 的位5
}

// 分配对齐的物理内存
static void* alloc_phys_aligned(uint32_t size) {
    // 假设 alloc_phys_page() 分配物理页
    uint8_t* mem = alloc_phys_page();
    if ((uint64_t)mem % 4096 != 0) {
        panic("VMX requires 4KB-aligned memory");
    }
    return mem;
}

// 初始化 VMXON 区域
static int vmx_init_vmxon() {
    uint64_t vmx_basic;
    __asm__ volatile("rdmsr" : "=A"(vmx_basic) : "c"(IA32_VMX_BASIC_MSR));

    uint32_t vmxon_size = (vmx_basic & 0x1FFF) + 1; // 获取 VMXON 区域大小
    vmxon_region = alloc_phys_aligned(vmxon_size);
    
    // 写入修订标识符
    uint32_t revision_id = vmx_basic & 0xFFFFFFFF;
    *(uint32_t*)vmxon_region = revision_id;

    // 执行 VMXON
    uint8_t error;
    __asm__ volatile(
        "vmxon %[vmxon_region]\n\t"
        "setna %[error]"
        : [error]"=r"(error)
        : [vmxon_region]"m"(vmxon_region)
        : "cc", "memory"
    );
    return error ? VMX_ERROR_FAILED_VMXON : VMX_ERROR_SUCCESS;
}

// 初始化 VMCS
static int vmx_init_vmcs() {
    vmcs_region = alloc_phys_aligned(4096); // VMCS 大小为 4KB
    
    // 清理 VMCS
    __asm__ volatile("vmclear %0" : : "m"(vmcs_region));
    
    // 加载 VMCS
    uint8_t error;
    __asm__ volatile(
        "vmptrld %[vmcs_region]\n\t"
        "setna %[error]"
        : [error]"=r"(error)
        : [vmcs_region]"m"(vmcs_region)
        : "cc", "memory"
    );
    if (error) return VMX_ERROR_FAILED_VMPTRLD;

    // 配置 VMCS 主机状态
    __asm__ volatile(
        "mov %%cs, %0\n\t"
        "mov %%ss, %1\n\t"
        "mov %%ds, %2\n\t"
        "mov %%es, %3\n\t"
        "mov %%fs, %4\n\t"
        "mov %%gs, %5\n\t"
        "mov %%tr, %6\n\t"
        : 
        : "m"(VMCS_HOST_CS_SELECTOR),
          "m"(VMCS_HOST_SS_SELECTOR),
          "m"(VMCS_HOST_DS_SELECTOR),
          "m"(VMCS_HOST_ES_SELECTOR),
          "m"(VMCS_HOST_FS_SELECTOR),
          "m"(VMCS_HOST_GS_SELECTOR),
          "m"(VMCS_HOST_TR_SELECTOR)
    );

    // 设置客户机 RIP
    uint64_t guest_rip = 0x0000; // 客户机入口地址
    __asm__ volatile("vmwrite %0, %1" 
        :: "r"(guest_rip), "i"(VMCS_GUEST_RIP));

    return VMX_ERROR_SUCCESS;
}

// 启用 VMX 操作
int vmx_enable() {
    if (!vmx_support()) {
        return -1; // 不支持 VT-x
    }

    // 设置 CR4.VMXE
    uint64_t cr4;
    __asm__ volatile("mov %%cr4, %0" : "=r"(cr4));
    cr4 |= (1 << 13); // CR4.VMXE = 1
    __asm__ volatile("mov %0, %%cr4" :: "r"(cr4));

    // 配置 VMXON 区域
    int err = vmx_init_vmxon();
    if (err != VMX_ERROR_SUCCESS) {
        return err;
    }

    // 初始化 VMCS
    return vmx_init_vmcs();
}

// 启动虚拟机
void vmx_launch_vm() {
    __asm__ volatile(
        "vmlaunch\n\t"
        "jmp 1f\n\t"   // 正常退出
        "1:\n\t"
    );
}

// VMX 退出处理函数
__attribute__((naked)) void vmx_exit_handler() {
    __asm__ volatile(
        "pusha\n\t"
        // 处理退出原因
        "popa\n\t"
        "vmresume\n\t"
    );
}