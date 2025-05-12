#ifdef _WIN32
#include <iconv.h>
#endif
#pragma pack(push, 1)

/* FAT32引导扇区结构 */
struct fat32_boot_sector {
    uint8_t  jump_code[3];
    char     oem_name[8];
    uint16_t bytes_per_sector;
    uint8_t  sectors_per_cluster;
    uint16_t reserved_sectors;
    uint8_t  fat_count;
    uint16_t root_entry_count;
    uint16_t total_sectors_16;
    uint8_t  media_type;
    uint16_t sectors_per_fat_16;
    uint16_t sectors_per_track;
    uint16_t head_count;
    uint32_t hidden_sectors;
    uint32_t total_sectors_32;
    
    // FAT32扩展部分
    uint32_t sectors_per_fat;
    uint16_t flags;
    uint16_t version;
    uint32_t root_cluster;
    uint16_t fs_info_sector;
    uint16_t backup_boot_sector;
    uint8_t  reserved[12];
    uint8_t  drive_number;
    uint8_t  nt_flags;
    uint8_t  signature;
    uint32_t volume_id;
    char     volume_label[11];
    char     fs_type[8];
};

/* FAT32目录项结构 */
struct fat32_dir_entry {
    char     name[8];        // 短文件名
    char     ext[3];         // 扩展名
    uint8_t  attr;           // 文件属性
    uint8_t  nt_reserved;
    uint8_t  create_time_tenth;
    uint16_t create_time;
    uint16_t create_date;
    uint16_t access_date;
    uint16_t cluster_high;   // 起始簇号高16位
    uint16_t modify_time;
    uint16_t modify_date;
    uint16_t cluster_low;    // 起始簇号低16位
    uint32_t file_size;
};

#pragma pack(pop)

// 文件属性掩码
#define ATTR_READ_ONLY  0x01
#define ATTR_HIDDEN     0x02
#define ATTR_SYSTEM     0x04
#define ATTR_VOLUME_ID  0x08
#define ATTR_DIRECTORY  0x10
#define ATTR_ARCHIVE    0x20

// 全局文件系统信息
static struct {
    uint32_t fat_start;      // FAT表起始扇区
    uint32_t data_start;     // 数据区起始扇区
    uint32_t sectors_per_cluster;
    uint32_t bytes_per_cluster;
    uint32_t root_cluster;   // 根目录起始簇
} fs_info;

// 当前目录信息
static uint32_t current_dir_cluster = 0;
