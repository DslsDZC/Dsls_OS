#include <stddef.h>
#ifndef _VMX
#define _VMX

// ========================
// VMX 相关 MSR 寄存器定义
// ========================
#define IA32_VMX_BASIC_MSR             0x480
#define IA32_VMX_PINBASED_CTLS_MSR     0x481
#define IA32_VMX_PROCBASED_CTLS_MSR    0x482
#define IA32_VMX_EXIT_CTLS_MSR         0x483
#define IA32_VMX_ENTRY_CTLS_MSR        0x484
#define IA32_VMX_MISC_MSR              0x485
#define IA32_VMX_CR0_FIXED0_MSR        0x486
#define IA32_VMX_CR0_FIXED1_MSR        0x487
#define IA32_VMX_CR4_FIXED0_MSR        0x488
#define IA32_VMX_CR4_FIXED1_MSR        0x489
#define IA32_VMX_VMCS_ENABLE_MSR       0x48A
#define IA32_VMX_EPTP_LIST_ADDRESS_MSR 0x48B
#define IA32_VMX_EPT_VPID_CAP_MSR      0x48C
#define IA32_VMX_TRUE_PINBASED_CTLS_MSR 0x48D
#define IA32_VMX_TRUE_PROCBASED_CTLS_MSR 0x48E
#define IA32_VMX_TRUE_EXIT_CTLS_MSR    0x48F
#define IA32_VMX_TRUE_ENTRY_CTLS_MSR   0x490
#define IA32_VMX_VMFUNC_MSR            0x491
#define IA32_VMX_MISC2_MSR             0x492

// ========================
// VMCS 控制字段
// ========================
#define VMCS_CTRL_PIN_BASED            0x4000
#define VMCS_CTRL_CPU_BASED            0x4002
#define VMCS_CTRL_EXCEPTION_BITMAP     0x4004
#define VMCS_CTRL_IO_BITMAP_A          0x4006
#define VMCS_CTRL_IO_BITMAP_B          0x4008
#define VMCS_CTRL_MSR_BITMAP           0x400A
#define VMCS_CTRL_TSC_OFFSET           0x4010
#define VMCS_CTRL_CR0_GUEST_HOST_MASK  0x6000
#define VMCS_CTRL_CR4_GUEST_HOST_MASK  0x6002
#define VMCS_CTRL_CR3_TARGET_COUNT     0x600A
#define VMCS_CTRL_VMEXIT_CONTROLS      0x4400
#define VMCS_CTRL_VMENTRY_CONTROLS     0x4402
#define VMCS_CTRL_EXCEPTION_ERROR_CODE 0x4404
#define VMCS_CTRL_ENTRY_MSR_LOAD_COUNT 0x4406
#define VMCS_CTRL_EXIT_MSR_STORE_COUNT 0x4408
#define VMCS_CTRL_EXIT_MSR_LOAD_COUNT  0x440A
#define VMCS_CTRL_ENTRY_MSR_LOAD_ADDR  0x440C
#define VMCS_CTRL_EXIT_MSR_STORE_ADDR  0x440E
#define VMCS_CTRL_EXIT_MSR_LOAD_ADDR   0x4410
#define VMCS_CTRL_ENTRY_INTERRUPTION_INFO 0x4012
#define VMCS_CTRL_ENTRY_EXCEPTION_ERRCODE 0x4014
#define VMCS_CTRL_ENTRY_INSTRUCTION_LEN 0x4016
#define VMCS_CTRL_ENTRY_MSR_LOAD_ADDR  0x4018
#define VMCS_CTRL_ENTRY_MSR_STORE_ADDR 0x401A
#define VMCS_CTRL_ENTRY_MSR_LOAD_COUNT 0x401C
#define VMCS_CTRL_ENTRY_MSR_STORE_COUNT 0x401E

// ========================
// VMCS 主机状态字段
// ========================
#define VMCS_HOST_CR0                  0x0C00
#define VMCS_HOST_CR3                  0x0C02
#define VMCS_HOST_CR4                  0x0C04
#define VMCS_HOST_ES_SELECTOR          0x0C06
#define VMCS_HOST_CS_SELECTOR          0x0C08
#define VMCS_HOST_SS_SELECTOR          0x0C0A
#define VMCS_HOST_DS_SELECTOR          0x0C0C
#define VMCS_HOST_FS_SELECTOR          0x0C0E
#define VMCS_HOST_GS_SELECTOR          0x0C10
#define VMCS_HOST_TR_SELECTOR          0x0C12
#define VMCS_HOST_GDTR_BASE            0x0C16
#define VMCS_HOST_IDTR_BASE            0x0C18
#define VMCS_HOST_RSP                  0x0C1C
#define VMCS_HOST_RIP                  0x0C1E

// ========================
// VMCS 客户机状态字段
// ========================
#define VMCS_GUEST_CR0                 0x6800
#define VMCS_GUEST_CR3                 0x6802
#define VMCS_GUEST_CR4                 0x6804
#define VMCS_GUEST_ES_SELECTOR         0x6806
#define VMCS_GUEST_CS_SELECTOR         0x6808
#define VMCS_GUEST_SS_SELECTOR         0x680A
#define VMCS_GUEST_DS_SELECTOR         0x680C
#define VMCS_GUEST_FS_SELECTOR         0x680E
#define VMCS_GUEST_GS_SELECTOR         0x6810
#define VMCS_GUEST_TR_SELECTOR         0x6812
#define VMCS_GUEST_GDTR_BASE           0x6816
#define VMCS_GUEST_IDTR_BASE           0x6818
#define VMCS_GUEST_RSP                 0x681C
#define VMCS_GUEST_RIP                 0x681E
#define VMCS_GUEST_RFLAGS              0x6820
#define VMCS_GUEST_PENDING_DEBUG_EXC   0x6822
#define VMCS_GUEST_ACTIVITY_STATE      0x6824
#define VMCS_GUEST_INTERRUPTIBILITY    0x6826
#define VMCS_GUEST_SYSENTER_CS         0x6828
#define VMCS_GUEST_SYSENTER_ESP        0x682A
#define VMCS_GUEST_SYSENTER_EIP        0x682C
#define VMCS_GUEST_DEBUGCTL            0x682E
#define VMCS_GUEST_PAT                 0x6830
#define VMCS_GUEST_EFER                0x6832
#define VMCS_GUEST_PERF_GLOBAL_CTRL    0x6834
#define VMCS_GUEST_PDPTE0              0x6836
#define VMCS_GUEST_PDPTE1              0x6838
#define VMCS_GUEST_PDPTE2              0x683A
#define VMCS_GUEST_PDPTE3              0x683C 

// ========================
// VMCS 退出信息字段
// ========================
#define VMCS_EXIT_REASON               0x4400
#define VMCS_EXIT_INTERRUPTION_INFO    0x4402
#define VMCS_EXIT_INTERRUPTION_ERRCODE 0x4404
#define VMCS_EXIT_IDT_VECTORING_INFO   0x4406
#define VMCS_EXIT_IDT_VECTORING_ERR    0x4408
#define VMCS_EXIT_INSTRUCTION_LEN      0x440C
#define VMCS_EXIT_QUALIFICATION        0x440E
#define VMCS_EXIT_MSR_STORE_COUNT      0x4410
#define VMCS_EXIT_MSR_STORE_ADDR       0x4412
#define VMCS_EXIT_MSR_LOAD_COUNT       0x4414
#define VMCS_EXIT_MSR_LOAD_ADDR        0x4416

// ========================
// VMCS 入口信息字段
// ========================
#define VMCS_ENTRY_CONTROL             0x4012
#define VMCS_ENTRY_INTERRUPTION_INFO   0x4014
#define VMCS_ENTRY_EXCEPTION_ERRCODE   0x4016
#define VMCS_ENTRY_INSTRUCTION_LEN     0x4018
#define VMCS_ENTRY_MSR_LOAD_COUNT      0x401A
#define VMCS_ENTRY_MSR_LOAD_ADDR       0x401C
#define VMCS_ENTRY_MSR_STORE_ADDR      0x401E

// ========================
// VMCS 物理地址字段
// ========================
#define VMCS_GUEST_PHYSICAL_ADDR       0x680A
#define VMCS_HOST_PHYSICAL_ADDR        0x0C1A

// ========================
// VMCS MTRR 信息字段
// ========================
#define VMCS_MTRR_PHYS_BASE0           0x2000
#define VMCS_MTRR_PHYS_MASK0           0x2002
#define VMCS_MTRR_PHYS_BASE1           0x2004
#define VMCS_MTRR_PHYS_MASK1           0x2006
#define VMCS_MTRR_PHYS_BASE2           0x2008
#define VMCS_MTRR_PHYS_MASK2           0x200A
#define VMCS_MTRR_PHYS_BASE3           0x200C
#define VMCS_MTRR_PHYS_MASK3           0x200E
#define VMCS_MTRR_PHYS_BASE4           0x2010   
#define VMCS_MTRR_PHYS_MASK4           0x2012
#define VMCS_MTRR_PHYS_BASE5           0x2014
#define VMCS_MTRR_PHYS_MASK5           0x2016
#define VMCS_MTRR_PHYS_BASE6           0x2018
#define VMCS_MTRR_PHYS_MASK6           0x201A
#define VMCS_MTRR_PHYS_BASE7           0x201C
#define VMCS_MTRR_PHYS_MASK7           0x201E

// ========================
// VMCS MSR 信息字段
// ========================
#define VMCS_MSR_BITMAP                0x0002
#define VMCS_MSR_LOAD_ADDR             0x0004       
#define VMCS_MSR_STORE_ADDR            0x0006

// ========================
// VMCS 其他字段
// ========================
#define VMCS_LINK_POINTER              0x0000
#define VMCS_PREEMPTION_TIMER_VALUE    0x482E

// ========================
// VMX 错误代码
// ========================
#define VMX_ERROR_SUCCESS          0
#define VMX_ERROR_FAILED_VMXON     1
#define VMX_ERROR_FAILED_VMPTRLD   2
#define VMX_ERROR_FAILED_VMCLEAR   3
#define VMX_ERROR_FAILED_VMLAUNCH  4
#define VMX_ERROR_FAILED_VMRESUME  5        
#define VMX_ERROR_FAILED_VMCALL    6
#define VMX_ERROR_FAILED_VMXOFF    7
#define VMX_ERROR_INVALID_VMCS     8
#define VMX_ERROR_EPT_VIOLATION    9
#define VMX_ERROR_VPID_INVALID     10

// ========================
// VMX 区域指针
// ========================
extern uint8_t* vmxon_region;
extern uint8_t* vmcs_region;

// ========================
// VMX 控制寄存器值
// ========================
extern uint64_t vmx_cr0_fixed0;
extern uint64_t vmx_cr0_fixed1; 
extern uint64_t vmx_cr4_fixed0;
extern uint64_t vmx_cr4_fixed1;

// ========================
// VMX 支持标志
// ========================
extern uint64_t vmx_basic_msr;
extern uint64_t vmx_pinbased_ctls_msr;
extern uint64_t vmx_procbased_ctls_msr;
extern uint64_t vmx_exit_ctls_msr;
extern uint64_t vmx_entry_ctls_msr;
extern uint64_t vmx_misc_msr;
extern uint64_t vmx_ept_vpid_cap_msr;
extern uint64_t vmx_true_pinbased_ctls_msr;
extern uint64_t vmx_true_procbased_ctls_msr;
extern uint64_t vmx_true_exit_ctls_msr;
extern uint64_t vmx_true_entry_ctls_msr;

// ========================
// VMX EPT 支持标志
// ========================
extern uint64_t vmx_ept_cap_msr;
extern uint64_t vmx_vpid_cap_msr;

// ========================
// VMX EPTP 列表地址
// ========================
extern uint64_t vmx_eptp_list_address_msr;

// ========================
// VMX VMFUNC 支持标志
// ========================
extern uint64_t vmx_vmfunc_msr;

// ========================
// VMX MISC2 支持标志
// ========================
extern uint64_t vmx_misc2_msr;

// ========================
// VMX 物理地址
// ========================
extern uint64_t vmx_guest_physical_addr;
extern uint64_t vmx_host_physical_addr;

// ========================
// VMX MTRR 信息
// ========================
extern uint64_t vmx_mtrr_phys_base0;
extern uint64_t vmx_mtrr_phys_mask0;
extern uint64_t vmx_mtrr_phys_base1;    
extern uint64_t vmx_mtrr_phys_mask1;
extern uint64_t vmx_mtrr_phys_base2;
extern uint64_t vmx_mtrr_phys_mask2;
extern uint64_t vmx_mtrr_phys_base3;
extern uint64_t vmx_mtrr_phys_mask3;
extern uint64_t vmx_mtrr_phys_base4;
extern uint64_t vmx_mtrr_phys_mask4;
extern uint64_t vmx_mtrr_phys_base5;
extern uint64_t vmx_mtrr_phys_mask5;    
extern uint64_t vmx_mtrr_phys_base6;
extern uint64_t vmx_mtrr_phys_mask6;
extern uint64_t vmx_mtrr_phys_base7;
extern uint64_t vmx_mtrr_phys_mask7;

// ========================
// VMX MSR 信息
// ========================
extern uint64_t vmx_msr_bitmap;
extern uint64_t vmx_msr_load_addr;
extern uint64_t vmx_msr_store_addr;

// ========================
// 函数声明
// ========================

// 基本 VMX 操作
uint32_t vmx_read_revision_id(void);
bool vmx_support(void);
int vmx_enable(void);
void vmx_disable(void);
int vmx_on(uint8_t* region);
int vmx_off(void);

// VMCS 管理
int vmx_clear(uint8_t* region);
int vmx_ptrld(uint8_t* region);
int vmx_read(uint32_t field, uint64_t* value);
int vmx_write(uint32_t field, uint64_t value);

// 虚拟机操作
int vmx_launch(void);
int vmx_resume(void);
int vmx_call(uint32_t function, uint64_t arg1, uint64_t arg2, uint64_t arg3);

// 状态设置
void vmx_setup_host_state(void);
void vmx_setup_guest_state(uintptr_t rip, uintptr_t rsp);
void vmx_setup_control_fields(void);

// 高级功能
int vmx_enable_ept(uint64_t eptp);
int vmx_disable_ept(void);
int vmx_enable_vpid(uint16_t vpid);
int vmx_disable_vpid(void);

// 退出处理
void vmx_exit_handler(void);
void vmx_handle_exit(void);

// 信息获取
void vmx_read_fixed_cr_values(void);
void vmx_read_capabilities(void);

// 实用函数
uint64_t vmx_get_eptp(void);
uint16_t vmx_get_vpid(void);
int vmx_invalidate_vpid(uint16_t vpid, uint64_t address);
int vmx_invalidate_ept(uint64_t eptp, uint64_t address);


// VMX 区域指针
uint8_t* vmxon_region = NULL;
uint8_t* vmcs_region = NULL;

// VMX 控制寄存器值
uint64_t vmx_cr0_fixed0 = 0;
uint64_t vmx_cr0_fixed1 = 0;
uint64_t vmx_cr4_fixed0 = 0;
uint64_t vmx_cr4_fixed1 = 0;

// VMX 能力标志
uint64_t vmx_basic_msr = 0;
uint64_t vmx_pinbased_ctls_msr = 0;
uint64_t vmx_procbased_ctls_msr = 0;
uint64_t vmx_exit_ctls_msr = 0;
uint64_t vmx_entry_ctls_msr = 0;
uint64_t vmx_misc_msr = 0;
uint64_t vmx_ept_vpid_cap_msr = 0;
uint64_t vmx_true_pinbased_ctls_msr = 0;
uint64_t vmx_true_procbased_ctls_msr = 0;
uint64_t vmx_true_exit_ctls_msr = 0;
uint64_t vmx_true_entry_ctls_msr = 0;

// VMX EPT/VPID 能力
uint64_t vmx_ept_cap_msr = 0;
uint64_t vmx_vpid_cap_msr = 0;

// VMX EPTP 列表地址
uint64_t vmx_eptp_list_address_msr = 0;

// VMX VMFUNC 能力
uint64_t vmx_vmfunc_msr = 0;

// VMX MISC2 能力
uint64_t vmx_misc2_msr = 0;

// VMX 物理地址
uint64_t vmx_guest_physical_addr = 0;
uint64_t vmx_host_physical_addr = 0;

// VMX MTRR 信息
uint64_t vmx_mtrr_phys_base0 = 0;
uint64_t vmx_mtrr_phys_mask0 = 0;
// ... 其他 MTRR 变量类似

// VMX MSR 信息
uint64_t vmx_msr_bitmap = 0;
uint64_t vmx_msr_load_addr = 0;
uint64_t vmx_msr_store_addr = 0;

#define VMX_VPID_CAP (1ULL << 32)
#define VMX_EPT_CAP (1ULL << 33)
#define VMX_EPTP_LIST_ADDRESS_MSR (1ULL << 34)
#define VMX_VMFUNC_MSR (1ULL << 35)
#define VMX_MISC2_MSR (1ULL << 36)
#define VMX_EPTP_LIST_ADDRESS_MSR (1ULL << 37)
#define VMCS_CTRL_EPT_POINTER 0x201A
#define VMCS_CTRL_VPID 0x201C
#define VMX_EPTP_LIST_ADDRESS_MSR (1ULL << 38)
#define VMX_VMCS_ENABLE_MSR (1ULL << 39)
#endif
