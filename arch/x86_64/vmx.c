#include <stdint.h>
#include <slab.h>
#include <vmx.h>

enum vmx_error {
    VMX_ERROR_SUCCESS,
    VMX_ERROR_FAILED_VMXON,
    VMX_ERROR_FAILED_VMPTRLD
};

static uint32_t read_revision_id() {
    uint64_t vmx_basic;
    __asm__ volatile("rdmsr" : "=A"(vmx_basic) : "c"(IA32_VMX_BASIC_MSR));
    return vmx_basic & 0xFFFFFFFF;
}

static void* alloc_aligned_phys_mem() {
    uint8_t* mem = alloc_phys_page();
    if ((uint64_t)mem % 4096) panic("Alignment failure");
    return mem;
}

int vmx_support() {
    uint32_t ecx;
    __asm__ volatile("cpuid" : "=c"(ecx) : "a"(1) : "ebx","edx");
    return (ecx & 0x60) == 0x60;
}

static int execute_vmxon(uint8_t** region) {
    const uint32_t size = (read_revision_id() & 0x1FFF) + 1;
    *region = alloc_aligned_phys_mem();
    *(uint32_t*)*region = read_revision_id();

    bool status;
    __asm__ volatile(
        "vmxon %1\n\t"
        "setna %0"
        : "=r"(status) : "m"(*region) : "cc", "memory"
    );
    return status ? VMX_ERROR_FAILED_VMXON : VMX_ERROR_SUCCESS;
}

static int setup_vmcs() {
    vmcs_region = alloc_aligned_phys_mem();
    
    __asm__ volatile("vmclear %0" : : "m"(vmcs_region));
    
    bool status;
    __asm__ volatile(
        "vmptrld %1\n\t"
        "setna %0"
        : "=r"(status) : "m"(vmcs_region) : "cc", "memory"
    );
    if (status) return VMX_ERROR_FAILED_VMPTRLD;

    __asm__ volatile(
        "vmwrite %0, %1\n\t"
        "mov %%cs, %2\n\t"
        "mov %%ss, %3\n\t"
        "mov %%tr, %4"
        :: "r"(0x0000ULL), "i"(VMCS_GUEST_RIP),
           "m"(VMCS_HOST_CS_SELECTOR),
           "m"(VMCS_HOST_SS_SELECTOR),
           "m"(VMCS_HOST_TR_SELECTOR)
    );

    return VMX_ERROR_SUCCESS;
}

int vmx_enable() {
    if (!vmx_support()) return -1;

    __asm__ volatile("mov %%cr4, %0" : "=r"(uint64_t cr4));
    __asm__ volatile("mov %0, %%cr4" :: "r"(cr4 | (1 << 13)));

    return execute_vmxon(&vmxon_region) ?: setup_vmcs();
}

__attribute__((naked)) void vmx_exit_handler() {
    __asm__ volatile(
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
        "vmresume\n\t"
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
        "ret\n\t"
    );
}

void vmx_launch_vm() {
    __asm__ volatile("vmlaunch\n\t");
}
