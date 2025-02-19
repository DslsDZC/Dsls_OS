#include <stdint.h>
#include "pci.c"  // 假设已实现 PCI 枚举功能
#include "slab.c"   // 假设已实现物理内存分配
#include "io.h"   // 内存映射 I/O 函数

// AHCI 寄存器定义
#define AHCI_CAP        0x00    // HBA 能力
#define AHCI_GHC        0x04    // 全局主机控制
#define AHCI_IS         0x08    // 中断状态
#define AHCI_PI         0x0C    // 端口实现位图
#define AHCI_VS         0x10    // 版本号
#define AHCI_CAP_NP     (1 << 0)  // 支持 Native Command Queue

// 端口寄存器偏移量（每个端口 0x80 字节）
#define PORT_CLB        0x00    // Command List Base
#define PORT_CLBU       0x04    // Command List Base Upper
#define PORT_FB         0x08    // FIS Base
#define PORT_FBU        0x0C    // FIS Base Upper
#define PORT_IS         0x10    // 中断状态
#define PORT_IE         0x14    // 中断使能
#define PORT_CMD        0x18    // 命令控制
#define PORT_SCTL       0x24    // SATA 控制
#define PORT_SERR       0x30    // SATA 错误
#define PORT_SIG        0x24    // 设备签名

// 命令状态
#define AHCI_CMD_START  (1 << 0)
#define AHCI_CMD_FIS_RX (1 << 4)

// FIS 类型
#define FIS_TYPE_REG_H2D    0x27    // Host to Device Register
#define FIS_TYPE_REG_D2H    0x34    // Device to Host Register
#define FIS_TYPE_DMA_ACT    0x39    // DMA Activate
#define FIS_TYPE_DMA_SETUP  0x41    // DMA Setup

// AHCI 数据结构
struct hba_port {
    // 0x00 - Command List Base Address
    uint32_t clb;           // 命令列表基地址低32位
    uint32_t clbu;          // 命令列表基地址高32位

    // 0x08 - FIS Base Address
    uint32_t fb;            // FIS基地址低32位
    uint32_t fbu;           // FIS基地址高32位

    // 0x10 - Interrupt Status
    volatile uint32_t is;    // 中断状态 (RO)
    
    // 0x14 - Interrupt Enable
    uint32_t ie;            // 中断使能 (RW)
    
    // 0x18 - Command and Status
    volatile uint32_t cmd;   // 命令控制 (RW)
    
    // 0x1C - Reserved
    uint32_t reserved0;
    
    // 0x20 - Task File Data
    volatile uint32_t tfd;   // 任务文件数据 (RO)
    
    // 0x24 - Signature
    volatile uint32_t sig;   // 设备签名 (RO)
    
    // 0x28 - SATA Status
    volatile uint32_t ssts;  // SATA状态 (RO)
    
    // 0x2C - SATA Control
    uint32_t sctl;          // SATA控制 (RW)
    
    // 0x30 - SATA Error
    volatile uint32_t serr;  // SATA错误 (RW1C)
    
    // 0x34 - SATA Active
    volatile uint32_t sact;  // SATA活动状态 (RO)
    
    // 0x38 - Command Issue
    volatile uint32_t ci;    // 命令发布 (RW)
    
    // 0x3C - SATA Notification
    uint32_t sntf;          // SATA通知 (RW)
    
    // 0x40 - FIS-Based Switching Control
    uint32_t fbs;           // FIS切换控制 (RW)
    
    // 0x44 - Device Sleep
    uint32_t devslp;        // 设备睡眠控制 (RW)
    
    // 0x48-0x7F - Reserved
    uint8_t reserved1[0x80 - 0x48];
} __attribute__((packed));

struct hba_memory {
    uint32_t cap;           // HBA 能力
    uint32_t ghc;           // 全局主机控制
    uint32_t is;            // 中断状态
    uint32_t pi;            // 端口实现位图
    uint32_t vs;            // 版本号
    uint8_t  reserved[0xA0 - 0x10];
    struct hba_port ports[32];  // 最多支持32个端口
};

// AHCI 命令列表项（Command Table）
struct ahci_command_header {
    uint16_t options;       // 命令选项
    uint16_t prdtl;         // PRD 条目数
    uint32_t transferred;   // 传输字节数
    uint32_t cmd_table_addr;// Command Table 物理地址
    uint32_t cmd_table_addr_high;
    uint32_t reserved[4];
};

// PRD（Physical Region Descriptor）条目
struct ahci_prd {
    uint32_t data_base;     // 数据物理地址低32位
    uint32_t data_base_high;// 数据物理地址高32位
    uint32_t reserved;
    uint32_t data_byte_count; // 数据字节数（最高位为中断标志）
};

// FIS结构（Host to Device）
struct fis_reg_h2d {
    uint8_t type;           // FIS_TYPE_REG_H2D
    uint8_t pm_port:4;      // Port Multiplier
    uint8_t rsv0:3;
    uint8_t c:1;            // 1 = Command, 0 = Control
    uint8_t command;        // ATA 命令
    uint8_t feature_low;
    uint8_t lba0;           // LBA 低字节
    uint8_t lba1;
    uint8_t lba2;
    uint8_t device;
    uint8_t lba3;
    uint8_t lba4;
    uint8_t lba5;
    uint8_t feature_high;
    uint16_t count;
    uint8_t icc;
    uint8_t control;
    uint32_t rsv1;
};

static struct hba_memory* hba = NULL;

// 初始化 AHCI 端口
static int ahci_port_init(struct hba_port* port) {
    // 停止命令引擎
    port->cmd &= ~AHCI_CMD_START;
    while (port->cmd & AHCI_CMD_FIS_RX);

    // 分配命令列表和 FIS 区域（物理内存）
    uint8_t* cl_base = alloc_phys_pages(1);  // 分配1页（4KB）
    uint8_t* fis_base = alloc_phys_pages(1);
    
    // 设置命令列表基址
    port->clb = (uint32_t)(uintptr_t)cl_base;
    port->clbu = (uint32_t)((uintptr_t)cl_base >> 32);
    
    // 设置 FIS 基址
    port->fb = (uint32_t)(uintptr_t)fis_base;
    port->fbu = (uint32_t)((uintptr_t)fis_base >> 32);

    // 启动命令引擎
    port->cmd |= AHCI_CMD_START | AHCI_CMD_FIS_RX;
    return 0;
}

// 发送 ATA 命令
int ahci_read_sector(struct hba_port* port, uint64_t lba, void* buffer) {
    // 分配命令表和 PRD（物理内存）
    struct ahci_command_header* cmd_header = alloc_phys_pages(1);
    struct fis_reg_h2d* fis = (struct fis_reg_h2d*)cmd_header;

    // 配置 FIS
    fis->type = FIS_TYPE_REG_H2D;
    fis->c = 1;            // Command FIS
    fis->command = 0x25;   // READ DMA EXT 命令
    fis->lba0 = lba & 0xFF;
    fis->lba1 = (lba >> 8) & 0xFF;
    fis->lba2 = (lba >> 16) & 0xFF;
    fis->device = 0x40;    // LBA模式
    fis->lba3 = (lba >> 24) & 0xFF;
    fis->lba4 = (lba >> 32) & 0xFF;
    fis->lba5 = (lba >> 40) & 0xFF;
    fis->count = 1;        // 读取1个扇区

    // 配置 PRD
    struct ahci_prd* prd = (struct ahci_prd*)(cmd_header + 1);
    prd->data_base = (uint32_t)(uintptr_t)buffer;
    prd->data_base_high = (uint32_t)((uintptr_t)buffer >> 32);
    prd->data_byte_count = 512 - 1;  // 512字节（扇区大小）

    // 发送命令
    volatile uint32_t* cmd_slot = (uint32_t*)port->clb;
    *cmd_slot = (uint32_t)(uintptr_t)cmd_header;

    // 等待命令完成
    while (port->is == 0);
    port->is = ~0;  // 清除中断状态

    return 0;
}

// 初始化 AHCI 控制器
void ahci_init(struct pci_device* dev) {
    // 获取 BAR5（AHCI 内存空间）
    uint32_t bar5 = dev->bars[5];
    if ((bar5 & 1) == 0) {
        // 内存映射 I/O
        hba = (struct hba_memory*)(bar5 & ~0xF);
    } else {
        panic("AHCI uses I/O space, not supported");
    }

    // 启用 AHCI 模式
    hba->ghc |= (1 << 31);  // AE (AHCI Enable)

    // 初始化所有实现的端口
    uint32_t ports = hba->pi;
    for (int i = 0; i < 32; i++) {
        if (ports & (1 << i)) {
            ahci_port_init(&hba->ports[i]);
        }
    }

    printf("AHCI initialized with %d ports\n", __builtin_popcount(ports));
}