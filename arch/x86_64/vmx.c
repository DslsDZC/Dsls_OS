#include <stdint.h>
#include "slab.c"   // 假设存在物理内存分配函数

// VMX 相关 MSR 寄存器
#define IA32_VMX_BASIC_MSR         0x480
#define IA32_VMX_CR0_FIXED0_MSR    0x486
#define IA32_VMX_CR0_FIXED1_MSR    0x487
#define IA32_VMX_CR4_FIXED0_MSR    0x488
#define IA32_VMX_CR4_FIXED1_MSR    0x489
#define IA32_VMX_VMCS_ENABLE_MSR   0x48A

/* 
 * ==============================================
 * VMCS 字段定义 (Intel SDM Vol.3, Chapter 24)
 * ==============================================
 */

/*--------------------------
  控制类字段（Control Fields） 
 --------------------------*/
#define VMCS_CTRL_PIN_BASED            0x4000  // 基于引脚的执行控制
#define VMCS_CTRL_CPU_BASED            0x4002  // 基于处理器的执行控制
#define VMCS_CTRL_EXCEPTION_BITMAP     0x4004  // 异常位图
#define VMCS_CTRL_IO_BITMAP_A          0x4006  // I/O位图地址A
#define VMCS_CTRL_IO_BITMAP_B          0x4008  // I/O位图地址B
#define VMCS_CTRL_MSR_BITMAP           0x400A  // MSR位图地址
#define VMCS_CTRL_TSC_OFFSET           0x4010  // TSC偏移量
#define VMCS_CTRL_CR0_GUEST_HOST_MASK  0x6000  // CR0 Guest/Host 掩码
#define VMCS_CTRL_CR4_GUEST_HOST_MASK  0x6002  // CR4 Guest/Host 掩码
#define VMCS_CTRL_CR3_TARGET_COUNT     0x600A  // CR3目标数量

/*--------------------------
  主机状态字段（Host-State Fields） 
 --------------------------*/
#define VMCS_HOST_CR0                  0x0C00  // 主机CR0
#define VMCS_HOST_CR3                  0x0C02  // 主机CR3
#define VMCS_HOST_CR4                  0x0C04  // 主机CR4
#define VMCS_HOST_ES_SELECTOR          0x0C06  // 主机ES选择子
#define VMCS_HOST_CS_SELECTOR          0x0C08  // 主机CS选择子
#define VMCS_HOST_SS_SELECTOR          0x0C0A  // 主机SS选择子
#define VMCS_HOST_DS_SELECTOR          0x0C0C  // 主机DS选择子
#define VMCS_HOST_FS_SELECTOR          0x0C0E  // 主机FS选择子
#define VMCS_HOST_GS_SELECTOR          0x0C10  // 主机GS选择子
#define VMCS_HOST_TR_SELECTOR          0x0C12  // 主机TR选择子
#define VMCS_HOST_GDTR_BASE            0x0C16  // 主机GDTR基地址
#define VMCS_HOST_IDTR_BASE            0x0C18  // 主机IDTR基地址
#define VMCS_HOST_RSP                  0x0C1C  // 主机RSP
#define VMCS_HOST_RIP                  0x0C1E  // 主机RIP

/*--------------------------
  客户机状态字段（Guest-State Fields） 
 --------------------------*/
#define VMCS_GUEST_CR0                 0x6800  // 客户机CR0
#define VMCS_GUEST_CR3                 0x6802  // 客户机CR3
#define VMCS_GUEST_CR4                 0x6804  // 客户机CR4
#define VMCS_GUEST_ES_SELECTOR         0x6806  // 客户机ES选择子
#define VMCS_GUEST_CS_SELECTOR         0x6808  // 客户机CS选择子
#define VMCS_GUEST_SS_SELECTOR         0x680A  // 客户机SS选择子
#define VMCS_GUEST_DS_SELECTOR         0x680C  // 客户机DS选择子
#define VMCS_GUEST_FS_SELECTOR         0x680E  // 客户机FS选择子
#define VMCS_GUEST_GS_SELECTOR         0x6810  // 客户机GS选择子
#define VMCS_GUEST_TR_SELECTOR         0x6812  // 客户机TR选择子
#define VMCS_GUEST_GDTR_BASE           0x6816  // 客户机GDTR基地址
#define VMCS_GUEST_IDTR_BASE           0x6818  // 客户机IDTR基地址
#define VMCS_GUEST_RSP                 0x681C  // 客户机RSP
#define VMCS_GUEST_RIP                 0x681E  // 客户机RIP
#define VMCS_GUEST_RFLAGS              0x6820  // 客户机RFLAGS
#define VMCS_GUEST_PENDING_DEBUG_EXC   0x6822  // 待处理调试异常

/*--------------------------
  VM-Exit 信息字段（VM-Exit Information Fields）
 --------------------------*/
#define VMCS_EXIT_REASON               0x4400  // 退出原因
#define VMCS_EXIT_INTERRUPTION_INFO    0x4402  // 中断信息
#define VMCS_EXIT_INTERRUPTION_ERRCODE 0x4404  // 中断错误码
#define VMCS_EXIT_IDT_VECTORING_INFO   0x4406  // IDT矢量化信息
#define VMCS_EXIT_IDT_VECTORING_ERR    0x4408  // IDT矢量化错误码
#define VMCS_EXIT_INSTRUCTION_LEN      0x440C  // 指令长度
#define VMCS_EXIT_QUALIFICATION        0x440E  // 退出限定符

/*--------------------------
  VM-Entry 控制字段（VM-Entry Control Fields）
 --------------------------*/
#define VMCS_ENTRY_CONTROL             0x4012  // VM入口控制
#define VMCS_ENTRY_INTERRUPTION_INFO   0x4014  // 入口中断信息
#define VMCS_ENTRY_EXCEPTION_ERRCODE   0x4016  // 入口异常错误码
#define VMCS_ENTRY_INSTRUCTION_LEN     0x4018  // 入口指令长度

/*--------------------------
  其他关键字段
 --------------------------*/
#define VMCS_LINK_POINTER              0x0000  // VMCS链接指针
#define VMCS_GUEST_ACTIVITY_STATE      0x6824  // 客户机活动状态
#define VMCS_GUEST_INTERRUPTIBILITY    0x6826  // 客户机可中断状态
#define VMCS_PREEMPTION_TIMER_VALUE    0x482E  // 抢占计时器值

// VMX 指令错误码
#define VMX_ERROR_SUCCESS          0
#define VMX_ERROR_FAILED_VMXON     1
#define VMX_ERROR_FAILED_VMPTRLD   2

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