#include <stdint.h>
#include <pci.h>
#include <slab.h>
#include <io.h>
#include <e1000.h>

void e1000_init(struct pci_device* dev) {
    nic.regs = (uint32_t*)(dev->bars[0] & ~0xF);
    
    nic.regs[E1000_CTRL/4] |= (1 << 26);
    while (nic.regs[E1000_CTRL/4] & (1 << 26));
    
    e1000_init_rx();
    e1000_init_tx();
}

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
#define E1001_DEVICE_ID 0x100F

static void e1001_init(struct pci_device* dev) {}
static void e1001_send_packet(void* data, uint16_t len) {}

static const struct nic_ops e1001_ops = {
    .init = e1001_init,
    .send = e1001_send_packet
};
#endif

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

void net_init() {
    struct pci_device* dev = find_pci_device(E1000_VENDOR_ID, E1000_DEVICE_ID);
    if (dev) {
        nic_drivers[0].ops->init(dev);
    }
}