#ifndef PCI_H
#define PCI_H

#include <stdint.h>
#define PCI_MAX_BUS     256
#define PCI_MAX_DEVICE  32
#define PCI_MAX_FUNC    8
#define PCI_HEADER_TYPE_DEVICE  0x00
#define PCI_HEADER_TYPE_BRIDGE  0x01


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

void pci_init();


struct pci_device* pci_find_device(uint16_t vendor_id, uint16_t device_id);

// PCI 设备信息结构
struct pci_device {
    uint8_t bus;
    uint8_t device;
    uint8_t function;
    uint16_t vendor_id;
    uint16_t device_id;
    uint8_t revision_id;
    uint8_t class_code;
    uint8_t subclass;
    uint8_t prog_if;
    uint8_t header_type;
    uint32_t bars[6];
    struct pci_device* next;
};
static struct pci_device* pci_devices = NULL;

#endif
