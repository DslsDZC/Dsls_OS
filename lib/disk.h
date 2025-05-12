#ifndef DISK_H
#define DISK_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

// 磁盘操作错误码
typedef enum {
    DISK_OK = 0,
    DISK_ERR_READ,
    DISK_ERR_WRITE,
    DISK_ERR_INVALID_LBA,
    DISK_ERR_TIMEOUT,
    DISK_ERR_DMA,
    DISK_ERR_NOT_INIT
} disk_error_t;

// 磁盘信息结构体
typedef struct {
    uint32_t sector_size;
    uint64_t total_sectors;
    char     model[40];
    char     serial[20];
    uint16_t firmware_version;
} disk_info_t;

disk_error_t disk_init(void);
bool read_sector(uint32_t lba, void* buffer);
bool write_sector(uint32_t lba, const void* buffer);

// 批量操作（可选优化）
disk_error_t read_multiple_sectors(uint32_t lba, 
                                  uint32_t count, 
                                  void* buffer);
                                  
disk_error_t write_multiple_sectors(uint32_t lba,
                                   uint32_t count,
                                   const void* buffer);

bool disk_is_write_protected(void);

void* kmalloc(size_t size);
void* alloc_phys_pages(size_t pages);
void free_phys_pages(void* addr, size_t pages);

void disk_enable_logging(bool enable);
const char* disk_strerror(disk_error_t err);

#endif