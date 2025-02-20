#include <stdint.h>
#include "io.h"
#include "printf.h"

#define PCI_MAX_BUS     256
#define PCI_MAX_DEVICE  32
#define PCI_MAX_FUNC    8

// PCI 配置空间头类型
#define PCI_HEADER_TYPE_DEVICE  0x00
#define PCI_HEADER_TYPE_BRIDGE  0x01

// PCI 设备信息结构
struct pci_device {
    uint8_t bus;
    uint8_t device;
    uint8_t function;
    uint16_t vendor_id;
    uint16_t device_id;
    uint8_t class_code;
    uint8_t subclass;
    uint8_t prog_if;
    uint8_t header_type;
    uint32_t bars[6];  // Base Address Registers
    struct pci_device* next;
};

static struct pci_device* pci_devices = NULL;

// 生成 PCI 配置空间地址
static uint32_t pci_config_address(uint8_t bus, uint8_t device, 
                                  uint8_t function, uint8_t offset) {
    return (1 << 31)              // 启用配置空间访问
         | (bus << 16)            // 总线号
         | (device << 11)         // 设备号
         | (function << 8)        // 功能号
         | (offset & 0xFC);       // 寄存器偏移（4字节对齐）
}

// 读取 PCI 配置空间 32 位寄存器
static uint32_t pci_read_config32(uint8_t bus, uint8_t device, 
                                uint8_t function, uint8_t offset) {
    outl(0xCF8, pci_config_address(bus, device, function, offset));
    return inl(0xCFC);
}

// 写入 PCI 配置空间 32 位寄存器
static void pci_write_config32(uint8_t bus, uint8_t device,
                              uint8_t function, uint8_t offset, uint32_t value) {
    outl(0xCF8, pci_config_address(bus, device, function, offset));
    outl(0xCFC, value);
}

// 读取 PCI 设备信息
static void pci_read_device_info(struct pci_device* dev) {
    uint32_t reg = pci_read_config32(dev->bus, dev->device, dev->function, 0x00);
    dev->vendor_id = reg & 0xFFFF;
    dev->device_id = (reg >> 16) & 0xFFFF;

    reg = pci_read_config32(dev->bus, dev->device, dev->function, 0x08);
    dev->revision_id = reg & 0xFF;
    dev->prog_if = (reg >> 8) & 0xFF;
    dev->subclass = (reg >> 16) & 0xFF;
    dev->class_code = (reg >> 24) & 0xFF;

    reg = pci_read_config32(dev->bus, dev->device, dev->function, 0x0C);
    dev->header_type = (reg >> 16) & 0xFF;

    // 读取 BARs
    for(int i = 0; i < 6; i++) {
        dev->bars[i] = pci_read_config32(dev->bus, dev->device, 
                                       dev->function, 0x10 + i*4);
    }
}

// 检查设备是否存在
static int pci_device_exists(uint8_t bus, uint8_t device, uint8_t function) {
    uint32_t vendor = pci_read_config32(bus, device, function, 0x00);
    return (vendor != 0xFFFFFFFF);
}

// 添加新设备到链表
static void pci_add_device(struct pci_device* dev) {
    dev->next = pci_devices;
    pci_devices = dev;
}

// 枚举 PCI 总线上的设备
void pci_enum_bus(uint8_t bus) {
    for (uint8_t device = 0; device < PCI_MAX_DEVICE; device++) {
        uint8_t function = 0;

        if (!pci_device_exists(bus, device, function)) continue;

        struct pci_device* dev = kmalloc(sizeof(struct pci_device));
        dev->bus = bus;
        dev->device = device;
        dev->function = function;
        pci_read_device_info(dev);
        pci_add_device(dev);

        // 检查是否为多功能设备
        if ((dev->header_type & 0x80) != 0) {
            for (function = 1; function < PCI_MAX_FUNC; function++) {
                if (pci_device_exists(bus, device, function)) {
                    struct pci_device* mdev = kmalloc(sizeof(struct pci_device));
                    mdev->bus = bus;
                    mdev->device = device;
                    mdev->function = function;
                    pci_read_device_info(mdev);
                    pci_add_device(mdev);
                }
            }
        }

        // 如果是 PCI-PCI 桥接器，递归枚举下游总线
        if (dev->class_code == 0x06 && dev->subclass == 0x04) {
            uint32_t reg = pci_read_config32(bus, device, 0, 0x18);
            uint8_t secondary_bus = (reg >> 8) & 0xFF;
            pci_enum_bus(secondary_bus);
        }
    }
}

// 初始化 PCI 子系统
void pci_init() {
    // 枚举总线0上的设备
    pci_enum_bus(0);

    // 打印枚举结果
    struct pci_device* current = pci_devices;
    while(current) {
        printf("PCI %02x:%02x.%d %04x:%04x Class %02x:%02x:%02x\n",
               current->bus, current->device, current->function,
               current->vendor_id, current->device_id,
               current->class_code, current->subclass, current->prog_if);
        current = current->next;
    }
}

// 查找指定设备
struct pci_device* pci_find_device(uint16_t vendor_id, uint16_t device_id) {
    struct pci_device* current = pci_devices;
    while(current) {
        if (current->vendor_id == vendor_id && 
            current->device_id == device_id) {
            return current;
        }
        current = current->next;
    }
    return NULL;
}