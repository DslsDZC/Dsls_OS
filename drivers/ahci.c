#include <stdint.h>
#include <stddef.h>
#include <pci.h>
#include <slab.h>
#include <io.h>
#include <ahci.h>

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
