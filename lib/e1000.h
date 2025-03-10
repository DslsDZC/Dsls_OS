/* 
 * Intel 82540EM 千兆网卡寄存器定义及驱动实现
 * 文件：e1000.h
 */

// 设备标识
#define E1000_VENDOR_ID   0x8086     // Intel厂商ID
#define E1000_DEVICE_ID   0x100E     // 82540EM 设备ID

// 寄存器偏移量（单位：字节）
#define E1000_CTRL        0x0000     // 设备控制寄存器
#define E1000_STATUS      0x0008     // 设备状态寄存器
#define E1000_RX_BASE     0x2800     // 接收描述符基址寄存器起始
#define E1000_TX_BASE     0x3800     // 发送描述符基址寄存器起始

// 接收相关寄存器
#define E1000_RCTL        0x0100     // 接收控制寄存器
#define E1000_RDBAL       0x2800     // 接收描述符低地址寄存器
#define E1000_RDBAH       0x2804     // 接收描述符高地址寄存器
#define E1000_RDLEN       0x2808     // 接收描述符环长度寄存器
#define E1000_RDH         0x2810     // 接收头指针寄存器
#define E1000_RDT         0x2818     // 接收尾指针寄存器

// 发送相关寄存器
#define E1000_TCTL        0x0400     // 发送控制寄存器
#define E1000_TDBAL       0x3800     // 发送描述符低地址寄存器
#define E1000_TDBAH       0x3804     // 发送描述符高地址寄存器
#define E1000_TDLEN       0x3808     // 发送描述符环长度寄存器
#define E1000_TDH         0x3810     // 发送头指针寄存器
#define E1000_TDT         0x3818     // 发送尾指针寄存器

// 接收控制标志位
#define RCTL_EN           (1 << 1)   // 接收使能
#define RCTL_SBP          (1 << 2)   // 存储坏包
#define RCTL_UPE          (1 << 3)   // 单播接收使能
#define RCTL_LPE          (1 << 5)   // 长包接收使能（支持超过1518字节）
#define RCTL_BAM          (1 << 15)  // 广播接收使能

// 发送控制标志位
#define TCTL_EN           (1 << 1)   // 发送使能
#define TCTL_PSP          (1 << 3)   // 填充短包（填充至最小以太帧长度）

// 描述符状态标志
#define DESC_OWN          (1 << 0)   // 描述符所有权（1=硬件，0=软件）
#define DESC_EOP          (1 << 1)   // 数据包结束标志

#pragma pack(push, 1)  // 取消结构体对齐，确保内存布局准确

/**
 * 接收描述符结构体
 * 每个描述符对应一个接收缓冲区
 */
struct e1000_rx_desc {
    uint64_t addr;       // 数据缓冲区物理地址（必须页对齐）
    uint16_t length;     // 接收数据长度
    uint16_t checksum;   // 校验和值
    uint8_t status;      // 状态标志（DESC_OWN等）
    uint8_t errors;      // 错误指示位
    uint16_t special;    // 特殊字段（保留）
};

/**
 * 发送描述符结构体
 * 每个描述符对应一个发送缓冲区
 */
struct e1000_tx_desc {
    uint64_t addr;       // 数据缓冲区物理地址（必须页对齐）
    uint16_t length;     // 发送数据长度
    uint8_t cso;         // 校验和偏移量
    uint8_t cmd;         // 命令标志（DESC_EOP等）
    uint8_t status;      // 状态标志
    uint8_t css;         // 校验和起始位置
    uint16_t special;    // 特殊字段（保留）
};

#pragma pack(pop)

/**
 * 网卡设备结构体
 * 管理网卡硬件资源和描述符环
 */
struct e1000_device {
    uint32_t* regs;                // 内存映射寄存器基址
    struct e1000_rx_desc* rx_ring; // 接收描述符环（环形缓冲区）
    struct e1000_tx_desc* tx_ring; // 发送描述符环（环形缓冲区）
    uint16_t rx_idx;               // 当前接收描述符索引
    uint16_t tx_idx;               // 当前发送描述符索引
};

static struct e1000_device nic;    // 全局网卡设备实例

/**
 * 初始化接收环
 * 分配描述符内存，配置硬件寄存器，预分配接收缓冲区
 */
static void e1000_init_rx() {
    // 分配物理连续的接收描述符环（256个描述符，4096字节）
    nic.rx_ring = alloc_phys_pages(1);
    memset(nic.rx_ring, 0, 4096);

    // 配置接收描述符寄存器
    nic.regs[E1000_RDBAL/4] = (uint32_t)(uintptr_t)nic.rx_ring;  // 低32位地址
    nic.regs[E1000_RDBAH/4] = 0;               // 高32位地址（32位系统设为0）
    nic.regs[E1000_RDLEN/4] = 4096;            // 描述符环总长度
    nic.regs[E1000_RDH/4] = 0;                 // 头指针初始位置
    nic.regs[E1000_RDT/4] = 15;                // 尾指针初始位置（预分配16个缓冲区）

    // 预分配接收缓冲区（每个缓冲区1页=4096字节）
    for (int i = 0; i < 16; i++) {
        nic.rx_ring[i].addr = (uint64_t)alloc_phys_pages(1);
        nic.rx_ring[i].status = DESC_OWN;  // 将缓冲区所有权交给硬件
    }

    // 启用接收功能：使能接收 | 接收广播 | 允许长包
    nic.regs[E1000_RCTL/4] = RCTL_EN | RCTL_BAM | RCTL_LPE;
}

/**
 * 初始化发送环
 * 分配描述符内存，配置硬件寄存器
 */
static void e1000_init_tx() {
    // 分配物理连续的发送描述符环
    nic.tx_ring = alloc_phys_pages(1);
    memset(nic.tx_ring, 0, 4096);

    // 配置发送描述符寄存器
    nic.regs[E1000_TDBAL/4] = (uint32_t)(uintptr_t)nic.tx_ring;
    nic.regs[E1000_TDBAH/4] = 0;
    nic.regs[E1000_TDLEN/4] = 4096;
    nic.regs[E1000_TDH/4] = 0;
    nic.regs[E1000_TDT/4] = 0;  // 初始时发送环为空

    // 启用发送功能：使能发送 | 自动填充短包
    nic.regs[E1000_TCTL/4] = TCTL_EN | TCTL_PSP;
}