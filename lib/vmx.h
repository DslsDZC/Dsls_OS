#ifndef _VMX
#define _VMX
#define IA32_VMX_BASIC_MSR         0x480
#define IA32_VMX_CR0_FIXED0_MSR    0x486
#define IA32_VMX_CR0_FIXED1_MSR    0x487
#define IA32_VMX_CR4_FIXED0_MSR    0x488
#define IA32_VMX_CR4_FIXED1_MSR    0x489
#define IA32_VMX_VMCS_ENABLE_MSR   0x48A

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

#define VMCS_EXIT_REASON               0x4400  // 退出原因
#define VMCS_EXIT_INTERRUPTION_INFO    0x4402  // 中断信息
#define VMCS_EXIT_INTERRUPTION_ERRCODE 0x4404  // 中断错误码
#define VMCS_EXIT_IDT_VECTORING_INFO   0x4406  // IDT矢量化信息
#define VMCS_EXIT_IDT_VECTORING_ERR    0x4408  // IDT矢量化错误码
#define VMCS_EXIT_INSTRUCTION_LEN      0x440C  // 指令长度
#define VMCS_EXIT_QUALIFICATION        0x440E  // 退出限定符

#define VMCS_ENTRY_CONTROL             0x4012  // VM入口控制
#define VMCS_ENTRY_INTERRUPTION_INFO   0x4014  // 入口中断信息
#define VMCS_ENTRY_EXCEPTION_ERRCODE   0x4016  // 入口异常错误码
#define VMCS_ENTRY_INSTRUCTION_LEN     0x4018  // 入口指令长度

#define VMCS_LINK_POINTER              0x0000  // VMCS链接指针
#define VMCS_GUEST_ACTIVITY_STATE      0x6824  // 客户机活动状态
#define VMCS_GUEST_INTERRUPTIBILITY    0x6826  // 客户机可中断状态
#define VMCS_PREEMPTION_TIMER_VALUE    0x482E  // 抢占计时器值

#define VMX_ERROR_SUCCESS          0
#define VMX_ERROR_FAILED_VMXON     1
#define VMX_ERROR_FAILED_VMPTRLD   2

static uint8_t* vmxon_region;
static uint8_t* vmcs_region;

#endif