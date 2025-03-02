#include <stdint.h>
#include "pci.h"
#include "slab.c"
#include "io.h"

#define E1000_VENDOR_ID   0x8086
#define E1000_DEVICE_ID   0x100E  // 82540EM

#define E1000_CTRL        0x0000  // 设备控制
#define E1000_STATUS      0x0008  // 设备状态
#define E1000_RX_BASE     0x2800  // 接收描述符基址
#define E1000_TX_BASE     0x3800  // 发送描述符基址
#define E1000_RCTL        0x0100  // 接收控制
#define E1000_TCTL        0x0400  // 发送控制
#define E1000_RDBAL       0x2800  // 接收描述符低地址
#define E1000_RDBAH       0x2804  // 接收描述符高地址
#define E1000_RDLEN       0x2808  // 接收描述符长度
#define E1000_RDH         0x2810  // 接收头指针
#define E1000_RDT         0x2818  // 接收尾指针
#define E1000_TDBAL       0x3800  // 发送描述符低地址
#define E1000_TDBAH       0x3804  // 发送描述符高地址
#define E1000_TDLEN       0x3808  // 发送描述符长度
#define E1000_TDH         0x3810  // 发送头指针
#define E1000_TDT         0x3818  // 发送尾指针

#define RCTL_EN           (1 << 1)    // 接收使能
#define RCTL_SBP          (1 << 2)    // 接收所有流量
#define RCTL_UPE          (1 << 3)    // 单播接收使能
#define RCTL_LPE          (1 << 5)    // 长包接收
#define RCTL_BAM          (1 << 15)   // 广播接收

#define TCTL_EN           (1 << 1)    // 发送使能
#define TCTL_PSP          (1 << 3)    // 填充短包

#define DESC_OWN          (1 << 0)    // 描述符由硬件拥有
#define DESC_EOP          (1 << 1)    // 数据包结束

struct e1000_rx_desc {
    uint64_t addr;       // 数据缓冲区物理地址
    uint16_t length;     // 数据长度
    uint16_t checksum;   // 校验和
    uint8_t status;      // 状态标志
    uint8_t errors;      // 错误标志
    uint16_t special;
} __attribute__((packed));

struct e1000_tx_desc {
    uint64_t addr;       // 数据缓冲区物理地址
    uint16_t length;     // 数据长度
    uint8_t cso;         // CSO偏移
    uint8_t cmd;         // 命令标志
    uint8_t status;      // 状态标志
    uint8_t css;         // 校验和起始
    uint16_t special;
} __attribute__((packed));

struct e1000_device {
    uint32_t* regs;      // 内存映射寄存器基址
    struct e1000_rx_desc* rx_ring; // 接收描述符环
    struct e1000_tx_desc* tx_ring; // 发送描述符环
    uint16_t rx_idx;     // 当前接收索引
    uint16_t tx_idx;     // 当前发送索引
};

static struct e1000_device nic;

static void e1000_init_rx() {
    // 分配对齐的接收描述符环（物理内存）
    nic.rx_ring = alloc_phys_pages(1); // 分配1页（256个描述符）
    memset(nic.rx_ring, 0, 4096);

    // 配置接收描述符基址
    nic.regs[E1000_RDBAL/4] = (uint32_t)(uintptr_t)nic.rx_ring;
    nic.regs[E1000_RDBAH/4] = 0;
    nic.regs[E1000_RDLEN/4] = 4096;
    nic.regs[E1000_RDH/4] = 0;
    nic.regs[E1000_RDT/4] = 15; // 预分配16个缓冲区

    // 为每个描述符分配接收缓冲区
    for (int i = 0; i < 16; i++) {
        nic.rx_ring[i].addr = (uint64_t)alloc_phys_pages(1);
        nic.rx_ring[i].status = DESC_OWN;
    }

    // 启用接收
    nic.regs[E1000_RCTL/4] = RCTL_EN | RCTL_BAM | RCTL_LPE;
}

// 初始化发送环
static void e1000_init_tx() {
    nic.tx_ring = alloc_phys_pages(1); // 分配1页（256个描述符）
    memset(nic.tx_ring, 0, 4096);

    nic.regs[E1000_TDBAL/4] = (uint32_t)(uintptr_t)nic.tx_ring;
    nic.regs[E1000_TDBAH/4] = 0;
    nic.regs[E1000_TDLEN/4] = 4096;
    nic.regs[E1000_TDH/4] = 0;
    nic.regs[E1000_TDT/4] = 0;

    nic.regs[E1000_TCTL/4] = TCTL_EN | TCTL_PSP;
}

// 初始化网卡
void e1000_init(struct pci_device* dev) {
    // 映射寄存器空间
    nic.regs = (uint32_t*)(dev->bars[0] & ~0xF);

    // 重置网卡
    nic.regs[E1000_CTRL/4] |= (1 << 26);
    while (nic.regs[E1000_CTRL/4] & (1 << 26));

    // 初始化收发环
    e1000_init_rx();
    e1000_init_tx();
}

// 发送数据包
void e1000_send_packet(void* data, uint16_t len) {
    uint16_t idx = nic.tx_idx;
    nic.tx_ring[idx].addr = (uint64_t)virt_to_phys(data);
    nic.tx_ring[idx].length = len;
    nic.tx_ring[idx].cmd = DESC_EOP | DESC_OWN;

    nic.regs[E1000_TDT/4] = (idx + 1) % 256;
    nic.tx_idx = (idx + 1) % 256;
}

struct nic_ops {
    void (*init)(struct pci_device*);
    void (*send)(void*, uint16_t);
};

static const struct nic_ops e1000_ops = {
    .init = e1000_init,
    .send = e1000_send_packet
};

#ifdef SUPPORT_E1001
#define E1001_DEVICE_ID   0x100F

static void e1001_init(struct pci_device* dev) {
    // 实现不同的初始化流程
}

static void e1001_send_packet(void* data, uint16_t len) {
    // 实现不同的发送逻辑
}

static const struct nic_ops e1001_ops = {
    .init = e1001_init,
    .send = e1001_send_packet
};
#endif

// 驱动注册表
static struct {
    uint16_t vendor;
    uint16_t device;
    const struct nic_ops* ops;
} nic_drivers[] = {
    {E1000_VENDOR_ID, E1000_DEVICE_ID, &e1000_ops},
    #ifdef SUPPORT_E1001
    {E1000_VENDOR_ID, E1001_DEVICE_ID, &e1001_ops},
    #endif
};

// 初始化网络子系统
void net_init() {
    struct pci_device* dev = find_pci_device(E1000_VENDOR_ID, E1000_DEVICE_ID);
    if (dev) {
        nic_drivers[0].ops->init(dev);
    }
}