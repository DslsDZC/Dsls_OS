#ifndef PCI_H
#define PCI_H

#include <stdint.h>

struct pci_device {
    uint8_t bus;
    uint8_t device;
    uint8_t function;
    uint16_t vendor_id;
    uint16_t device_id;
    uint8_t class_code;
    uint8_t subclass;
    uint8_t prog_if;
    uint8_t revision_id;
    uint8_t header_type;
    uint32_t bars[6];
    struct pci_device* next;
};

// PCI 子系统初始化
void pci_init();

// 查找指定设备
struct pci_device* pci_find_device(uint16_t vendor_id, uint16_t device_id);

#endif // PCI_H