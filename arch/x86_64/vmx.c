#include <stdint.h>
#include "slab.h"
#include "vmx.h"

#define IA32_VMX_BASIC_MSR 0x480
#define VMCS_HOST_CS_SELECTOR 0x08
#define VMCS_HOST_SS_SELECTOR 0x10
#define VMCS_HOST_DS_SELECTOR 0x10
#define VMCS_HOST_ES_SELECTOR 0x10
#define VMCS_HOST_FS_SELECTOR 0x10
#define VMCS_HOST_GS_SELECTOR 0x10
#define VMCS_HOST_TR_SELECTOR 0x28
#define VMCS_GUEST_RIP 0x681E

enum vmx_error {
    VMX_ERROR_SUCCESS,
    VMX_ERROR_FAILED_VMXON,
    VMX_ERROR_FAILED_VMPTRLD
};

static uint8_t* vmxon_region;
static uint8_t* vmcs_region;

static uint32_t read_revision_id() {
    uint64_t vmx_basic;
    __asm__ volatile("rdmsr" : "=A"(vmx_basic) : "c"(IA32_VMX_BASIC_MSR));
    return vmx_basic & 0xFFFFFFFF;
}

static void* alloc_aligned_phys_mem(uint32_t size) {
    uint8_t* mem = alloc_phys_page();
    if ((uint64_t)mem % 4096 != 0) panic("Alignment failure");
    return mem;
}

int vmx_support() {
    uint32_t ecx;
    __asm__ volatile("cpuid" : "=c"(ecx) : "a"(1) : "ebx","edx");
    return (ecx & (1 << 5)) && (ecx & (1 << 6));
}

static int execute_vmx_operation(uint8_t** region, uint32_t size) {
    *region = alloc_aligned_phys_mem(size);
    *(uint32_t*)*region = read_revision_id();
    
    uint8_t status;
    __asm__ volatile(
        "vmxon %[region]\n\t"
        "setna %[status]"
        : [status]"=r"(status)
        : [region]"m"(*region)
        : "cc", "memory"
    );
    return status ? VMX_ERROR_FAILED_VMXON : VMX_ERROR_SUCCESS;
}

static int setup_vmcs_region() {
    vmcs_region = alloc_aligned_phys_mem(4096);
    
    __asm__ volatile("vmclear %0" : : "m"(vmcs_region));
    
    uint8_t status;
    __asm__ volatile(
        "vmptrld %[region]\n\t"
        "setna %[status]"
        : [status]"=r"(status)
        : [region]"m"(vmcs_region)
        : "cc", "memory"
    );
    if (status) return VMX_ERROR_FAILED_VMPTRLD;

    __asm__ volatile(
        "mov %%cs, %0\n\t"
        "mov %%ss, %1\n\t"
        "mov %%ds, %2\n\t"
        "mov %%es, %3\n\t"
        "mov %%fs, %4\n\t"
        "mov %%gs, %5\n\t"
        "mov %%tr, %6"
        :: "m"(VMCS_HOST_CS_SELECTOR),
           "m"(VMCS_HOST_SS_SELECTOR),
           "m"(VMCS_HOST_DS_SELECTOR),
           "m"(VMCS_HOST_ES_SELECTOR),
           "m"(VMCS_HOST_FS_SELECTOR),
           "m"(VMCS_HOST_GS_SELECTOR),
           "m"(VMCS_HOST_TR_SELECTOR)
    );

    __asm__ volatile("vmwrite %0, %1" :: "r"(0x0000ULL), "i"(VMCS_GUEST_RIP));
    return VMX_ERROR_SUCCESS;
}

int vmx_enable() {
    if (!vmx_support()) return -1;

    uint64_t cr4;
    __asm__ volatile("mov %%cr4, %0" : "=r"(cr4));
    __asm__ volatile("mov %0, %%cr4" :: "r"(cr4 | (1 << 13)));

    int status = execute_vmx_operation(&vmxon_region, 
        (read_revision_id() & 0x1FFF) + 1);
    return status == VMX_ERROR_SUCCESS ? setup_vmcs_region() : status;
}

__attribute__((naked)) void vmx_exit_handler() {
    __asm__ volatile(
        "sub rsp, 120\n\t"
        "mov [rsp+0x00], rax\n\t"
        "mov [rsp+0x08], rbx\n\t"
        "mov [rsp+0x10], rcx\n\t"
        "mov [rsp+0x18], rdx\n\t"
        "mov [rsp+0x20], rsi\n\t"
        "mov [rsp+0x28], rdi\n\t"
        "mov [rsp+0x30], rbp\n\t"
        "mov [rsp+0x38], r8\n\t"
        "mov [rsp+0x40], r9\n\t"
        "mov [rsp+0x48], r10\n\t"
        "mov [rsp+0x50], r11\n\t"
        "mov [rsp+0x58], r12\n\t"
        "mov [rsp+0x60], r13\n\t"
        "mov [rsp+0x68], r14\n\t"
        "mov [rsp+0x70], r15\n\t"
        "vmresume\n\t"
        "add rsp, 120\n\t"
        "ret\n\t"
    );
}

void vmx_launch_vm() {
    __asm__ volatile(
        "vmlaunch\n\t"
        "jmp 1f\n\t"
        "1: nop\n\t"
    );
}
