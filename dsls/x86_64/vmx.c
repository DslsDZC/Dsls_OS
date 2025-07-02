#include <stdint.h>
#include <stdbool.h>
#include <slab.h>
#include <vmx.h>
#include <panic.h>
#include <cpuid.h>
#include <msr.h>

// ========================
// 辅助函数
// ========================

// 分配对齐的物理内存页
static void* vmx_alloc_phys_page(void) {
    void* page = alloc_phys_page();
    if ((uintptr_t)page % 4096 != 0) {
        panic("VMX: Physical memory not 4K aligned");
    }
    return page;
}

// 读取控制寄存器
static uint64_t read_cr0(void) {
    uint64_t cr0;
    __asm__ __volatile__("mov %%cr0, %0" : "=r"(cr0));
    return cr0;
}

static uint64_t read_cr3(void) {
    uint64_t cr3;
    __asm__ __volatile__("mov %%cr3, %0" : "=r"(cr3));
    return cr3;
}

static uint64_t read_cr4(void) {
    uint64_t cr4;
    __asm__ __volatile__("mov %%cr4, %0" : "=r"(cr4));
    return cr4;
}

// 写入控制寄存器
static void write_cr0(uint64_t cr0) {
    __asm__ __volatile__("mov %0, %%cr0" : : "r"(cr0));
}

static void write_cr3(uint64_t cr3) {
    __asm__ __volatile__("mov %0, %%cr3" : : "r"(cr3));
}

static void write_cr4(uint64_t cr4) {
    __asm__ __volatile__("mov %0, %%cr4" : : "r"(cr4));
}

// ========================
// 基本 VMX 操作
// ========================

// 读取 VMX 修订标识符
uint32_t vmx_read_revision_id(void) {
    uint32_t lo, hi;
    rdmsr(IA32_VMX_BASIC_MSR, &lo, &hi);
    return lo & 0x7FFFFFFF;  // 返回低31位
}

// 检查 CPU 是否支持 VMX
bool vmx_support(void) {
    uint32_t eax, ebx, ecx, edx;
    cpuid(1, &eax, &ebx, &ecx, &edx);
    return (ecx & (1 << 5)) != 0;  // 检查 VMX 位
}

// 启用 VMX 支持
int vmx_enable(void) {
    if (!vmx_support()) {
        return VMX_ERROR_FAILED_VMXON;
    }
    
    // 设置 CR4.VMXE = 1
    uint64_t cr4 = read_cr4();
    cr4 |= CR4_VMXE;
    write_cr4(cr4);
    
    return VMX_ERROR_SUCCESS;
}

// 禁用 VMX 支持
void vmx_disable(void) {
    // 设置 CR4.VMXE = 0
    uint64_t cr4 = read_cr4();
    cr4 &= ~CR4_VMXE;
    write_cr4(cr4);
}

// 执行 VMXON 指令
int vmx_on(uint8_t* region) {
    vmxon_region = region;
    *(uint32_t*)vmxon_region = vmx_read_revision_id();
    
    uint8_t status;
    __asm__ __volatile__(
        "vmxon %1\n\t"
        "setb %0"
        : "=r"(status)
        : "m"(vmxon_region)
        : "cc", "memory"
    );
    
    return status ? VMX_ERROR_FAILED_VMXON : VMX_ERROR_SUCCESS;
}

// 执行 VMXOFF 指令
int vmx_off(void) {
    uint8_t status;
    __asm__ __volatile__(
        "vmxoff\n\t"
        "setb %0"
        : "=r"(status)
        : 
        : "cc", "memory"
    );
    
    return status ? VMX_ERROR_FAILED_VMXOFF : VMX_ERROR_SUCCESS;
}

// ========================
// VMCS 管理
// ========================

// 执行 VMCLEAR 指令
int vmx_clear(uint8_t* region) {
    uint8_t status;
    __asm__ __volatile__(
        "vmclear %1\n\t"
        "setb %0"
        : "=r"(status)
        : "m"(region)
        : "cc", "memory"
    );
    
    return status ? VMX_ERROR_FAILED_VMCLEAR : VMX_ERROR_SUCCESS;
}

// 执行 VMPTRLD 指令
int vmx_ptrld(uint8_t* region) {
    vmcs_region = region;
    uint8_t status;
    __asm__ __volatile__(
        "vmptrld %1\n\t"
        "setb %0"
        : "=r"(status)
        : "m"(vmcs_region)
        : "cc", "memory"
    );
    
    return status ? VMX_ERROR_FAILED_VMPTRLD : VMX_ERROR_SUCCESS;
}

// 执行 VMREAD 指令
int vmx_read(uint32_t field, uint64_t* value) {
    uint8_t status;
    __asm__ __volatile__(
        "vmread %2, %1\n\t"
        "setb %0"
        : "=r"(status), "=r"(*value)
        : "r"(field)
        : "cc", "memory"
    );
    
    return status ? VMX_ERROR_INVALID_VMCS : VMX_ERROR_SUCCESS;
}

// 执行 VMWRITE 指令
int vmx_write(uint32_t field, uint64_t value) {
    uint8_t status;
    __asm__ __volatile__(
        "vmwrite %2, %1\n\t"
        "setb %0"
        : "=r"(status)
        : "r"(value), "r"(field)
        : "cc", "memory"
    );
    
    return status ? VMX_ERROR_INVALID_VMCS : VMX_ERROR_SUCCESS;
}

// ========================
// 虚拟机操作
// ========================

// 执行 VMLAUNCH 指令
int vmx_launch(void) {
    uint8_t status;
    __asm__ __volatile__(
        "vmlaunch\n\t"
        "setb %0"
        : "=r"(status)
        : 
        : "cc", "memory"
    );
    
    return status ? VMX_ERROR_FAILED_VMLAUNCH : VMX_ERROR_SUCCESS;
}

// 执行 VMRESUME 指令
int vmx_resume(void) {
    uint8_t status;
    __asm__ __volatile__(
        "vmresume\n\t"
        "setb %0"
        : "=r"(status)
        : 
        : "cc", "memory"
    );
    
    return status ? VMX_ERROR_FAILED_VMRESUME : VMX_ERROR_SUCCESS;
}

// 执行 VMCALL 指令
int vmx_call(uint32_t function, uint64_t arg1, uint64_t arg2, uint64_t arg3) {
    uint8_t status;
    __asm__ __volatile__(
        "mov %1, %%rax\n\t"
        "mov %2, %%rbx\n\t"
        "mov %3, %%rcx\n\t"
        "mov %4, %%rdx\n\t"
        "vmcall\n\t"
        "setb %0"
        : "=r"(status)
        : "r"(function), "r"(arg1), "r"(arg2), "r"(arg3)
        : "rax", "rbx", "rcx", "rdx", "cc", "memory"
    );
    
    return status ? VMX_ERROR_FAILED_VMCALL : VMX_ERROR_SUCCESS;
}

// ========================
// 状态设置
// ========================

// 设置主机状态
void vmx_setup_host_state(void) {
    vmx_write(VMCS_HOST_CR0, read_cr0());
    vmx_write(VMCS_HOST_CR3, read_cr3());
    vmx_write(VMCS_HOST_CR4, read_cr4());
    
    // 获取段选择器值
    uint16_t cs, ss, ds, es, fs, gs, tr;
    __asm__ __volatile__(
        "mov %%cs, %0\n\t"
        "mov %%ss, %1\n\t"
        "mov %%ds, %2\n\t"
        "mov %%es, %3\n\t"
        "mov %%fs, %4\n\t"
        "mov %%gs, %5\n\t"
        "mov %%tr, %6\n\t"
        : "=r"(cs), "=r"(ss), "=r"(ds), "=r"(es), "=r"(fs), "=r"(gs), "=r"(tr)
    );
    
    vmx_write(VMCS_HOST_CS_SELECTOR, cs);
    vmx_write(VMCS_HOST_SS_SELECTOR, ss);
    vmx_write(VMCS_HOST_DS_SELECTOR, ds);
    vmx_write(VMCS_HOST_ES_SELECTOR, es);
    vmx_write(VMCS_HOST_FS_SELECTOR, fs);
    vmx_write(VMCS_HOST_GS_SELECTOR, gs);
    vmx_write(VMCS_HOST_TR_SELECTOR, tr);
    
    // 获取描述符表基址
    uint64_t gdtr_base, idtr_base;
    __asm__ __volatile__(
        "sgdt %0\n\t"
        "sidt %1\n\t"
        : "=m"(gdtr_base), "=m"(idtr_base)
    );
    
    vmx_write(VMCS_HOST_GDTR_BASE, gdtr_base);
    vmx_write(VMCS_HOST_IDTR_BASE, idtr_base);
    
    // 设置主机栈指针和指令指针
    uint64_t rsp;
    __asm__ __volatile__("mov %%rsp, %0" : "=r"(rsp));
    vmx_write(VMCS_HOST_RSP, rsp);
    vmx_write(VMCS_HOST_RIP, (uint64_t)vmx_exit_handler);
}

// 设置客户机状态
void vmx_setup_guest_state(uintptr_t rip, uintptr_t rsp) {
    vmx_write(VMCS_GUEST_CR0, read_cr0());
    vmx_write(VMCS_GUEST_CR3, read_cr3());
    vmx_write(VMCS_GUEST_CR4, read_cr4());
    
    // 获取段选择器值
    uint16_t cs, ss, ds, es, fs, gs, tr;
    __asm__ __volatile__(
        "mov %%cs, %0\n\t"
        "mov %%ss, %1\n\t"
        "mov %%ds, %2\n\t"
        "mov %%es, %3\n\t"
        "mov %%fs, %4\n\t"
        "mov %%gs, %5\n\t"
        "mov %%tr, %6\n\t"
        : "=r"(cs), "=r"(ss), "=r"(ds), "=r"(es), "=r"(fs), "=r"(gs), "=r"(tr)
    );
    
    vmx_write(VMCS_GUEST_CS_SELECTOR, cs);
    vmx_write(VMCS_GUEST_SS_SELECTOR, ss);
    vmx_write(VMCS_GUEST_DS_SELECTOR, ds);
    vmx_write(VMCS_GUEST_ES_SELECTOR, es);
    vmx_write(VMCS_GUEST_FS_SELECTOR, fs);
    vmx_write(VMCS_GUEST_GS_SELECTOR, gs);
    vmx_write(VMCS_GUEST_TR_SELECTOR, tr);
    
    // 获取描述符表基址
    uint64_t gdtr_base, idtr_base;
    __asm__ __volatile__(
        "sgdt %0\n\t"
        "sidt %1\n\t"
        : "=m"(gdtr_base), "=m"(idtr_base)
    );
    
    vmx_write(VMCS_GUEST_GDTR_BASE, gdtr_base);
    vmx_write(VMCS_GUEST_IDTR_BASE, idtr_base);
    
    // 设置客户机栈指针和指令指针
    vmx_write(VMCS_GUEST_RSP, rsp);
    vmx_write(VMCS_GUEST_RIP, rip);
    vmx_write(VMCS_GUEST_RFLAGS, 0x2);  // 设置标志位
}

// 设置控制字段
void vmx_setup_control_fields(void) {
    // 读取真实控制值
    rdmsr(IA32_VMX_TRUE_PINBASED_CTLS_MSR, &vmx_true_pinbased_ctls_msr, NULL);
    rdmsr(IA32_VMX_TRUE_PROCBASED_CTLS_MSR, &vmx_true_procbased_ctls_msr, NULL);
    rdmsr(IA32_VMX_TRUE_EXIT_CTLS_MSR, &vmx_true_exit_ctls_msr, NULL);
    rdmsr(IA32_VMX_TRUE_ENTRY_CTLS_MSR, &vmx_true_entry_ctls_msr, NULL);
    
    // 设置控制字段
    vmx_write(VMCS_CTRL_PIN_BASED, vmx_true_pinbased_ctls_msr);
    vmx_write(VMCS_CTRL_CPU_BASED, vmx_true_procbased_ctls_msr);
    vmx_write(VMCS_CTRL_VMEXIT_CONTROLS, vmx_true_exit_ctls_msr);
    vmx_write(VMCS_CTRL_VMENTRY_CONTROLS, vmx_true_entry_ctls_msr);
    
    // 设置其他控制字段
    vmx_write(VMCS_CTRL_EXCEPTION_BITMAP, 0xFFFFFFFF); // 捕获所有异常
    vmx_write(VMCS_CTRL_CR0_GUEST_HOST_MASK, 0);
    vmx_write(VMCS_CTRL_CR4_GUEST_HOST_MASK, 0);
}

// ========================
// 高级功能
// ========================

// 启用 EPT
int vmx_enable_ept(uint64_t eptp) {
    if (!(vmx_ept_vpid_cap_msr & VMX_EPT_CAP)) {
        return VMX_ERROR_EPT_VIOLATION;
    }
    
    // 设置 EPT 指针
    vmx_write(VMCS_CTRL_EPT_POINTER, eptp);
    
    // 启用二级地址转换
    uint64_t procbased_ctls = vmx_true_procbased_ctls_msr;
    procbased_ctls |= VMX_PROCBASED_CTLS_SECONDARY_CONTROLS;
    vmx_write(VMCS_CTRL_CPU_BASED, procbased_ctls);
    
    // 设置二级控制
    uint64_t secondary_ctls = 0;
    vmx_read(VMCS_CTRL_CPU_BASED2, &secondary_ctls);
    secondary_ctls |= VMX_PROCBASED_CTLS2_ENABLE_EPT;
    vmx_write(VMCS_CTRL_CPU_BASED2, secondary_ctls);
    
    return VMX_ERROR_SUCCESS;
}

// 禁用 EPT
int vmx_disable_ept(void) {
    // 禁用二级地址转换
    uint64_t procbased_ctls = vmx_true_procbased_ctls_msr;
    procbased_ctls &= ~VMX_PROCBASED_CTLS_SECONDARY_CONTROLS;
    vmx_write(VMCS_CTRL_CPU_BASED, procbased_ctls);
    
    return VMX_ERROR_SUCCESS;
}

// 启用 VPID
int vmx_enable_vpid(uint16_t vpid) {
    if (!(vmx_ept_vpid_cap_msr & VMX_VPID_CAP)) {
        return VMX_ERROR_VPID_INVALID;
    }
    
    // 设置 VPID
    vmx_write(VMCS_CTRL_VPID, vpid);
    
    // 启用 VPID
    uint64_t procbased_ctls = vmx_true_procbased_ctls_msr;
    procbased_ctls |= VMX_PROCBASED_CTLS_SECONDARY_CONTROLS;
    vmx_write(VMCS_CTRL_CPU_BASED, procbased_ctls);
    
    // 设置二级控制
    uint64_t secondary_ctls = 0;
    vmx_read(VMCS_CTRL_CPU_BASED2, &secondary_ctls);
    secondary_ctls |= VMX_PROCBASED_CTLS2_ENABLE_VPID;
    vmx_write(VMCS_CTRL_CPU_BASED2, secondary_ctls);
    
    return VMX_ERROR_SUCCESS;
}

// 禁用 VPID
int vmx_disable_vpid(void) {
    // 禁用二级地址转换
    uint64_t procbased_ctls = vmx_true_procbased_ctls_msr;
    procbased_ctls &= ~VMX_PROCBASED_CTLS_SECONDARY_CONTROLS;
    vmx_write(VMCS_CTRL_CPU_BASED, procbased_ctls);
    
    return VMX_ERROR_SUCCESS;
}

// ========================
// 退出处理
// ========================

// VM-exit 处理程序
__attribute__((naked)) void vmx_exit_handler(void) {
    __asm__ __volatile__(
        // 保存所有通用寄存器
        "push rax\n\t"
        "push rbx\n\t"
        "push rcx\n\t"
        "push rdx\n\t"
        "push rsi\n\t"
        "push rdi\n\t"
        "push rbp\n\t"
        "push r8\n\t"
        "push r9\n\t"
        "push r10\n\t"
        "push r11\n\t"
        "push r12\n\t"
        "push r13\n\t"
        "push r14\n\t"
        "push r15\n\t"
        
        // 调用 C 处理函数
        "call vmx_handle_exit\n\t"
        
        // 恢复所有通用寄存器
        "pop r15\n\t"
        "pop r14\n\t"
        "pop r13\n\t"
        "pop r12\n\t"
        "pop r11\n\t"
        "pop r10\n\t"
        "pop r9\n\t"
        "pop r8\n\t"
        "pop rbp\n\t"
        "pop rdi\n\t"
        "pop rsi\n\t"
        "pop rdx\n\t"
        "pop rcx\n\t"
        "pop rbx\n\t"
        "pop rax\n\t"
        
        // 返回到客户机
        "vmresume\n\t"
        
        // 安全防护：不应该执行到这里
        "ud2\n\t"
    );
}

// VM-exit 处理函数
void vmx_handle_exit(void) {
    uint64_t exit_reason;
    vmx_read(VMCS_EXIT_REASON, &exit_reason);
    exit_reason &= 0xFFFF;  // 提取退出原因
    
    uint64_t exit_qualification = 0;
    vmx_read(VMCS_EXIT_QUALIFICATION, &exit_qualification);
    
    switch (exit_reason) {
        case EXIT_REASON_EXCEPTION_NMI:
            // 处理异常或NMI
            break;
            
        case EXIT_REASON_EXTERNAL_INTERRUPT:
            // 处理外部中断
            break;
            
        case EXIT_REASON_TRIPLE_FAULT:
            panic("VMX: Triple fault occurred");
            break;
            
        case EXIT_REASON_INIT_SIGNAL:
            // 处理INIT信号
            break;
            
        case EXIT_REASON_STARTUP_IPI:
            // 处理启动IPI
            break;
            
        case EXIT_REASON_IO_SMI:
            // 处理I/O SMI
            break;
            
        case EXIT_REASON_OTHER_SMI:
            // 处理其他SMI
            break;
            
        case EXIT_REASON_INTERRUPT_WINDOW:
            // 处理中断窗口
            break;
            
        case EXIT_REASON_NMI_WINDOW:
            // 处理NMI窗口
            break;
            
        case EXIT_REASON_TASK_SWITCH:
            // 处理任务切换
            break;
            
        case EXIT_REASON_CPUID:
            // 处理CPUID指令
            break;
            
        case EXIT_REASON_GETSEC:
            // 处理GETSEC指令
            break;
            
        case EXIT_REASON_HLT:
            // 处理HLT指令
            break;
            
        // 添加更多退出原因处理...
            
        default:
            panic("VMX: Unhandled exit reason: %llu", exit_reason);
    }
}

// ========================
// 信息获取
// ========================

// 读取固定控制寄存器值
void vmx_read_fixed_cr_values(void) {
    rdmsr(IA32_VMX_CR0_FIXED0_MSR, &vmx_cr0_fixed0, NULL);
    rdmsr(IA32_VMX_CR0_FIXED1_MSR, &vmx_cr0_fixed1, NULL);
    rdmsr(IA32_VMX_CR4_FIXED0_MSR, &vmx_cr4_fixed0, NULL);
    rdmsr(IA32_VMX_CR4_FIXED1_MSR, &vmx_cr4_fixed1, NULL);
}

// 读取 VMX 能力信息
void vmx_read_capabilities(void) {
    rdmsr(IA32_VMX_BASIC_MSR, &vmx_basic_msr, NULL);
    rdmsr(IA32_VMX_TRUE_PINBASED_CTLS_MSR, &vmx_true_pinbased_ctls_msr, NULL);
    rdmsr(IA32_VMX_TRUE_PROCBASED_CTLS_MSR, &vmx_true_procbased_ctls_msr, NULL);
    rdmsr(IA32_VMX_TRUE_EXIT_CTLS_MSR, &vmx_true_exit_ctls_msr, NULL);
    rdmsr(IA32_VMX_TRUE_ENTRY_CTLS_MSR, &vmx_true_entry_ctls_msr, NULL);
    rdmsr(IA32_VMX_MISC_MSR, &vmx_misc_msr, NULL);
    rdmsr(IA32_VMX_EPT_VPID_CAP_MSR, &vmx_ept_vpid_cap_msr, NULL);
}

// ========================
// 实用函数
// ========================

// 无效化 VPID
int vmx_invalidate_vpid(uint16_t vpid, uint64_t address) {
    if (!(vmx_ept_vpid_cap_msr & VMX_VPID_CAP)) {
        return VMX_ERROR_VPID_INVALID;
    }
    
    uint8_t status;
    __asm__ __volatile__(
        "invvpid %2, %1\n\t"
        "setb %0"
        : "=r"(status)
        : "r"((struct { uint16_t vpid; uint64_t addr; }){vpid, address}), "m"(address)
        : "cc", "memory"
    );
    
    return status ? VMX_ERROR_VPID_INVALID : VMX_ERROR_SUCCESS;
}

// 无效化 EPT
int vmx_invalidate_ept(uint64_t eptp, uint64_t address) {
    if (!(vmx_ept_vpid_cap_msr & VMX_EPT_CAP)) {
        return VMX_ERROR_EPT_VIOLATION;
    }
    
    uint8_t status;
    __asm__ __volatile__(
        "invept %2, %1\n\t"
        "setb %0"
        : "=r"(status)
        : "r"((struct { uint64_t eptp; uint64_t addr; }){eptp, address}), "m"(address)
        : "cc", "memory"
    );
    
    return status ? VMX_ERROR_EPT_VIOLATION : VMX_ERROR_SUCCESS;
}
