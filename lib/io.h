#ifndef _IO_H
#define _IO_H
#define SET_BIT(reg, bit)    mmio_write32(reg, mmio_read32(reg) | (1 << bit))
#define CLEAR_BIT(reg, bit)  mmio_write32(reg, mmio_read32(reg) & ~(1 << bit))
#define TEST_BIT(reg, bit)   (mmio_read32(reg) & (1 << bit))
#define VM_MMIO   0x1
#define VM_KERNEL 0x2
#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif
#define PAGE_PRESENT  (1 << 0)
#define PAGE_RW       (1 << 1)
#define PAGE_UNCACHED (1 << 4)

// 内存映射I/O读操作
static inline uint8_t mmio_read8(volatile void* addr) {
    mmio_barrier();
    return *(volatile uint8_t*)addr;
}

static inline uint16_t mmio_read16(volatile void* addr) {
    mmio_barrier();
    return *(volatile uint16_t*)addr;
}

static inline uint32_t mmio_read32(volatile void* addr) {
    mmio_barrier();
    return *(volatile uint32_t*)addr;
}

static inline uint64_t mmio_read64(volatile void* addr) {
    mmio_barrier();
    return *(volatile uint64_t*)addr;
}

// 内存映射I/O写操作
static inline void mmio_write8(volatile void* addr, uint8_t value) {
    *(volatile uint8_t*)addr = value;
    mmio_barrier();
}

static inline void mmio_write16(volatile void* addr, uint16_t value) {
    *(volatile uint16_t*)addr = value;
    mmio_barrier();
}

static inline void mmio_write32(volatile void* addr, uint32_t value) {
    *(volatile uint32_t*)addr = value;
    mmio_barrier();
}

static inline void mmio_write64(volatile void* addr, uint64_t value) {
    *(volatile uint64_t*)addr = value;
    mmio_barrier();
}

static inline volatile void* mmio_map(uintptr_t phys_addr, size_t size) {
    // 确保地址按页对齐
    uintptr_t aligned_phys = phys_addr & ~(PAGE_SIZE - 1);
    size_t aligned_size = ((phys_addr + size - aligned_phys) + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
    
    // 从内核虚拟地址空间分配区域（假设有valloc函数）
    void* virt_addr = valloc(aligned_size, VM_MMIO);
    if (!virt_addr) return NULL;

    // 建立页表映射（假设map_page函数已实现）
    for (size_t offset = 0; offset < aligned_size; offset += PAGE_SIZE) {
        map_page(
            (uintptr_t)virt_addr + offset,   // 虚拟地址
            aligned_phys + offset,           // 物理地址
            PAGE_PRESENT | PAGE_RW | PAGE_UNCACHED // 禁用缓存
        );
    }

    // 计算实际偏移量
    uintptr_t final_addr = (uintptr_t)virt_addr + (phys_addr - aligned_phys);
    
    // 刷新TLB（假设有tlb_flush函数）
    tlb_flush(final_addr, aligned_size);
    
    return (volatile void*)final_addr;
}

#endif // _IO_H