// AHCI 寄存器偏移定义
#define AHCI_CAP 0x00        // HBA 能力寄存器（Host Bus Adapter Capabilities）
#define AHCI_GHC 0x04        // 全局主机控制寄存器（Global Host Control）
#define AHCI_IS 0x08         // 中断状态寄存器（Interrupt Status）
#define AHCI_PI 0x0C         // 端口实现位图寄存器（Ports Implemented）
#define AHCI_VS 0x10         // 版本号寄存器（Version）
#define AHCI_CAP_NP (1 << 0) // 支持 Native Command Queue 的能力标志

// 端口寄存器偏移定义
#define PORT_CLB 0x00  // 命令列表基地址低32位（Command List Base Address Low）
#define PORT_CLBU 0x04 // 命令列表基地址高32位（Command List Base Address High）
#define PORT_FB 0x08   // FIS 基地址低32位（FIS Base Address Low）
#define PORT_FBU 0x0C  // FIS 基地址高32位（FIS Base Address High）
#define PORT_IS 0x10   // 中断状态寄存器（Interrupt Status）
#define PORT_IE 0x14   // 中断使能寄存器（Interrupt Enable）
#define PORT_CMD 0x18  // 命令控制寄存器（Command and Status）
#define PORT_SCTL 0x24 // SATA 控制寄存器（SATA Control）
#define PORT_SERR 0x30 // SATA 错误寄存器（SATA Error）
#define PORT_SIG 0x24  // 设备签名寄存器（Device Signature）

// 命令控制寄存器的位定义
#define AHCI_CMD_START (1 << 0)  // 启动命令引擎（Start Command Engine）
#define AHCI_CMD_FIS_RX (1 << 4) // 启用 FIS 接收（Enable FIS Receive）

// FIS 类型定义
#define FIS_TYPE_REG_H2D 0x27   // 主机到设备寄存器 FIS（Host to Device Register FIS）
#define FIS_TYPE_REG_D2H 0x34   // 设备到主机寄存器 FIS（Device to Host Register FIS）
#define FIS_TYPE_DMA_ACT 0x39   // DMA 激活 FIS（DMA Activate FIS）
#define FIS_TYPE_DMA_SETUP 0x41 // DMA 设置 FIS（DMA Setup FIS）


// HBA 内存结构体
struct hba_memory
{
    uint32_t cap;                  // HBA 能力寄存器（Host Bus Adapter Capabilities）
    uint32_t ghc;                  // 全局主机控制寄存器（Global Host Control）
    uint32_t is;                   // 中断状态寄存器（Interrupt Status）
    uint32_t pi;                   // 端口实现位图寄存器（Ports Implemented）
    uint32_t vs;                   // 版本号寄存器（Version）
    uint8_t reserved[0xA0 - 0x10]; // 保留区域
    struct hba_port ports[32];     // 最多支持32个端口
};

// AHCI 命令列表项结构体
struct ahci_command_header
{
    uint16_t options;             // 命令选项（Command Options）
    uint16_t prdtl;               // PRD 条目数（Physical Region Descriptor Table Length）
    uint32_t transferred;         // 已传输字节数（Bytes Transferred）
    uint32_t cmd_table_addr;      // 命令表物理地址低32位（Command Table Physical Address Low）
    uint32_t cmd_table_addr_high; // 命令表物理地址高32位（Command Table Physical Address High）
    uint32_t reserved[4];         // 保留区域
};

// PRD（Physical Region Descriptor）条目结构体
struct ahci_prd
{
    uint32_t data_base;       // 数据物理地址低32位（Data Base Address Low）
    uint32_t data_base_high;  // 数据物理地址高32位（Data Base Address High）
    uint32_t reserved;        // 保留区域
    uint32_t data_byte_count; // 数据字节数（最高位为中断标志，Data Byte Count）
};

// FIS 结构体（Host to Device）
struct fis_reg_h2d
{
    uint8_t type;         // FIS 类型（FIS_TYPE_REG_H2D）
    uint8_t pm_port : 4;  // 端口倍增器端口号（Port Multiplier Port Number）
    uint8_t rsv0 : 3;     // 保留位
    uint8_t c : 1;        // 命令/控制标志（1 = Command, 0 = Control）
    uint8_t command;      // ATA 命令（ATA Command）
    uint8_t feature_low;  // 功能字段低位（Feature Low）
    uint8_t lba0;         // LBA 地址低位（LBA Low Byte）
    uint8_t lba1;         // LBA 地址中低位（LBA Mid Byte）
    uint8_t lba2;         // LBA 地址中高位（LBA High Byte）
    uint8_t device;       // 设备字段（Device）
    uint8_t lba3;         // LBA 地址高位（LBA High Byte）
    uint8_t lba4;         // LBA 地址扩展低位（LBA Extended Low Byte）
    uint8_t lba5;         // LBA 地址扩展高位（LBA Extended High Byte）
    uint8_t feature_high; // 功能字段高位（Feature High）
    uint16_t count;       // 扇区计数（Sector Count）
    uint8_t icc;          // 接口通信控制（Interface Communication Control）
    uint8_t control;      // 控制字段（Control）
    uint32_t rsv1;        // 保留字段
};

// 全局变量声明
static struct hba_memory *hba = NULL;

#ifndef HBA_PORT_DEFINED
#define HBA_PORT_DEFINED
struct hba_port
{
    uint32_t clb;
    uint32_t clbu;
    uint32_t fb;
    uint32_t fbu;
    uint32_t is;
    uint32_t ie;
    uint32_t cmd;
    uint32_t reserved0;
    uint32_t tfd;
    uint32_t sig;
    uint32_t ssts;
    uint32_t sctl;
    uint32_t serr;
    uint32_t sact;
    uint32_t ci;
    uint32_t sntf;
    uint32_t fbs;
    uint32_t devslp;
    uint8_t reserved1[0x70 - 0x48];
    uint32_t vendor[4];
};
#endif

static int ahci_port_init(hba_port *port);
