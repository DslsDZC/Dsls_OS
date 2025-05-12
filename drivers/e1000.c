#include <stdint.h>
#include <pci.h>
#include <slab.h>
#include <io.h>
#include <e1000.h>

void e1000_init(struct pci_device* dev) {
    if ((dev->bars[0] & 0xF) != 0) panic("Invalid BAR0 alignment");
    nic.regs = mmio_map(dev->bars[0] & ~0xF, 0x20000);
    
    nic.regs[E1000_CTRL/4] |= (1 << 5);
    while (nic.regs[E1000_STATUS/4] & (1 << 19)); 
    
    e1000_init_rx();
    e1000_init_tx();
}

void e1000_send_packet(void* data, uint16_t len) {
    uint16_t idx = nic.tx_idx;
    assert((uintptr_t)data % 16 == 0);
    flush_dcache_range(data, len);
    nic.tx_ring[idx].cmd = DESC_EOP | DESC_OWN | (1 << 3);
	spin_lock(&tx_lock);
	wmb();
	nic.regs[E1000_TDT/4] = (idx + 1) % 256;
	nic.tx_idx = (idx + 1) % 256;
	spin_unlock(&tx_lock);
}

struct e1000_tx_desc {
    uint64_t addr;
    uint16_t length;
    uint8_t cso;
    uint8_t cmd;
    uint8_t status;
    uint8_t css;
    uint16_t special;
} __attribute__((packed));

void e1000_init_tx() {
    nic.tx_ring = alloc_phys_pages(1);
    memset(nic.tx_ring, 0, 4096);
    nic.regs[E1000_TDBAL/4] = (uint32_t)(uintptr_t)nic.tx_ring;
    nic.regs[E1000_TDBAH/4] = 0;
    nic.regs[E1000_TDLEN/4] = 4096;
    nic.regs[E1000_TDH/4] = 0;
    nic.regs[E1000_TDT/4] = 0;
    uint32_t tctl = nic.regs[E1000_TCTL/4];
    tctl |= TCTL_EN;
    tctl |= TCTL_PSP;
    tctl |= (0x10 << 4);
    tctl |= (0x40 << 12);
    nic.regs[E1000_TCTL/4] = tctl;
    
    for(int i=0; i<256; i++){
        nic.tx_ring[i].status = 0x0;
    }
    nic.regs[E1000_TXDCTL/4] = (0x3F << 16) |
                           (0x1 << 8) |
                           0x1;
}

void e1000_init_rx() {
    nic.rx_ring = alloc_phys_pages(2);
    memset(nic.rx_ring, 0, 2*4096);
    uint64_t rx_phys = virt_to_phys(nic.rx_ring);
    nic.regs[E1000_RDBAL/4] = rx_phys & 0xFFFFFFFF;
    nic.regs[E1000_RDBAH/4] = rx_phys >> 32;
    nic.regs[E1000_RDLEN/4] = RX_RING_SIZE * 16;
    nic.regs[E1000_RDH/4] = 0;
    nic.regs[E1000_RDT/4] = RX_RING_SIZE - 1;
    for(int i=0; i<RX_RING_SIZE; i++){
        void* buf = alloc_phys_pages(1);
        memset(buf, 0, 2048);
        nic.rx_ring[i].addr = virt_to_phys(buf);
        nic.rx_ring[i].status = (1 << 0);
    }
    uint32_t rctl = nic.regs[E1000_RCTL/4];
    rctl |= RCTL_EN | RCTL_BAM | (3 << 16);
    nic.regs[E1000_RCTL/4] = rctl;
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