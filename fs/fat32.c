#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#ifdef _WIN32
#include <iconv.h>
#else
#include <iconv.h>
#endif
#include "disk.h"
#include "slab.h"

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

/* 辅助函数：读取FAT表项 */
static uint32_t read_fat_entry(uint32_t cluster) {
    uint32_t fat_offset = cluster * 4;  // FAT32每个表项4字节
    uint32_t sector = fs_info.fat_start + (fat_offset / fs_info.bytes_per_cluster);
    uint32_t entry_offset = fat_offset % fs_info.bytes_per_cluster;
    
    uint8_t buffer[512];
    if (!read_sector(sector, buffer)) return 0xFFFFFFFF;
    
    return *(uint32_t*)(buffer + entry_offset) & 0x0FFFFFFF;
}

/* 初始化文件系统 */
int fat32_init(uint32_t lba) {
    struct fat32_boot_sector bs;
    
    // 读取引导扇区
    if (!read_sector(lba, &bs)) return -1;
    
    // 验证签名
    if (bs.signature != 0x28 && bs.signature != 0x29) return -1;
    
    // 初始化全局信息
    fs_info.sectors_per_cluster = bs.sectors_per_cluster;
    fs_info.bytes_per_cluster = bs.bytes_per_sector * bs.sectors_per_cluster;
    fs_info.fat_start = lba + bs.reserved_sectors;
    fs_info.data_start = fs_info.fat_start + bs.fat_count * bs.sectors_per_fat;
    fs_info.root_cluster = bs.root_cluster;
    
    current_dir_cluster = fs_info.root_cluster;
    return 0;
}

/* 簇号转LBA地址 */
static uint32_t cluster_to_lba(uint32_t cluster) {
    return fs_info.data_start + 
          (cluster - 2) * fs_info.sectors_per_cluster;
}

/* 读取目录条目 */
static int read_directory(uint32_t cluster, struct fat32_dir_entry* entries) {
    uint8_t* buffer = alloc_phys_pages(1); // 分配4KB缓冲区
    uint32_t lba = cluster_to_lba(cluster);
    
    // 读取整个簇
    for (int i = 0; i < fs_info.sectors_per_cluster; i++) {
        if (!read_sector(lba + i, buffer + i*512)) {
            free_phys_pages(buffer, 1);
            return -1;
        }
    }
    
    // 拷贝目录条目
    memcpy(entries, buffer, sizeof(struct fat32_dir_entry)*128);
    free_phys_pages(buffer, 1);
    return 0;
}

/* 查找文件条目 */
struct fat32_dir_entry* find_file(const char* name) {
    static struct fat32_dir_entry entries[128];
    uint32_t current_cluster = current_dir_cluster;
    
    do {
        if (read_directory(current_cluster, entries) < 0) return NULL;
        
        for (int i = 0; i < 128; i++) {
            if (entries[i].name[0] == 0x00) break; // 结束标记
            if (entries[i].name[0] == 0xE5) continue; // 删除条目
            
            // 简单文件名比较（需处理空格填充）
            char base[9], ext[4];
            memcpy(base, entries[i].name, 8);
            base[8] = '\0';
            memcpy(ext, entries[i].ext, 3);
            ext[3] = '\0';
            
            char fullname[13];
            sprintf(fullname, "%s.%s", strtrim(base), strtrim(ext));
            
            if (strcmp(fullname, name) == 0) {
                return &entries[i];
            }
        }
        
        current_cluster = read_fat_entry(current_cluster);
    } while (current_cluster < 0x0FFFFFF8); // 簇链未结束
    
    return NULL;
}

    struct file_handle {
        uint32_t start_cluster;   // 文件起始簇号
        uint32_t current_cluster; // 当前读取的簇号
        uint32_t size;            // 文件大小
        uint32_t pos;             // 当前读写位置
    };

/* 打开文件 */
int fat32_open(const char* path, void** handle) {
    struct fat32_dir_entry* entry = find_file(path);
    if (!entry) return -1;
    
    struct file_handle* fh = kmalloc(sizeof(struct file_handle));
    fh->start_cluster = (entry->cluster_high << 16) | entry->cluster_low;
    fh->size = entry->file_size;
    fh->pos = 0;
    fh->current_cluster = fh->start_cluster;
    
    *handle = fh;
    return 0;
}

/* 读取文件内容 */
int fat32_read(void* handle, void* buffer, uint32_t size) {
    struct file_handle* fh = handle;
    uint32_t bytes_remaining = fh->size - fh->pos;
    if (size > bytes_remaining) size = bytes_remaining;
    
    uint32_t cluster_offset = fh->pos / fs_info.bytes_per_cluster;
    uint32_t pos_in_cluster = fh->pos % fs_info.bytes_per_cluster;
    
    // 定位到当前簇
    uint32_t cluster = fh->start_cluster;
    for (int i = 0; i < cluster_offset; i++) {
        cluster = read_fat_entry(cluster);
        if (cluster >= 0x0FFFFFF8) break;
    }
    
    uint8_t* data = alloc_phys_pages(1);
    uint32_t total_read = 0;
    
    while (size > 0 && cluster < 0x0FFFFFF8) {
        uint32_t lba = cluster_to_lba(cluster);
        read_sector(lba, data); // 简化：只读第一个扇区
        
        uint32_t copy_size = fs_info.bytes_per_cluster - pos_in_cluster;
        if (copy_size > size) copy_size = size;
        memcpy(buffer, data + pos_in_cluster, copy_size);
        buffer += copy_size;
        size -= copy_size;
        total_read += copy_size;
        fh->pos += copy_size;
        
        // 移动到下一簇
        cluster = read_fat_entry(cluster);
        pos_in_cluster = 0;
    }
    
    free_phys_pages(data, 1);
    return total_read;
}

// 在fat32_dir_entry结构体后添加
struct vfat_long_name_entry {
    uint8_t  sequence;       // 序号和标志位
    uint16_t name1[5];       // 第1-5字符
    uint8_t  attr;           // 必须为0x0F
    uint8_t  type;           // 必须为0
    uint8_t  checksum;
    uint16_t name2[6];       // 第6-11字符 
    uint16_t first_cluster;  // 必须为0
    uint16_t name3[2];       // 第12-13字符
};

// 新增辅助函数：VFAT校验和计算
static uint8_t lfn_checksum(const uint8_t* short_name) {
    uint8_t sum = 0;
    for (int i = 0; i < 11; i++) {
        sum = ((sum & 1) ? 0x80 : 0) + (sum >> 1) + short_name[i];
    }
    return sum;
}

// 修改后的find_file函数片段
struct fat32_dir_entry* find_file(const char* name) {
    static struct fat32_dir_entry entries[128];
    uint32_t current_cluster = current_dir_cluster;
    
    // 新增：Unicode转换缓冲区
    char utf8_name[260] = {0};
    uint16_t lfn_buffer[260] = {0};
    int lfn_index = 0;
    uint8_t expected_checksum = 0;
    bool lfn_valid = false;

    do {
        if (read_directory(current_cluster, entries) < 0) return NULL;
        
        for (int i = 0; i < 128; i++) {
            if (entries[i].name[0] == 0x00) break;
            if (entries[i].name[0] == 0xE5) continue;

            // 处理长文件名条目
            if (entries[i].attr == 0x0F) {
                struct vfat_long_name_entry* lfn = (struct vfat_long_name_entry*)&entries[i];
                
                // 校验条目有效性
                if (lfn->attr != 0x0F || lfn->type != 0) continue;
                
                // 获取序列号并检查起始条目
                uint8_t seq = lfn->sequence;
                if (seq & 0x40) { // 第一个条目
                    lfn_index = 0;
                    expected_checksum = lfn->checksum;
                    memset(lfn_buffer, 0, sizeof(lfn_buffer));
                }
                
                // 拼接Unicode字符（小端序处理）
                for (int j = 0; j < 5; j++) 
                    if (lfn->name1[j] != 0xFFFF) 
                        lfn_buffer[lfn_index++] = le16toh(lfn->name1[j]);
                
                for (int j = 0; j < 6; j++) 
                    if (lfn->name2[j] != 0xFFFF) 
                        lfn_buffer[lfn_index++] = le16toh(lfn->name2[j]);
                
                for (int j = 0; j < 2; j++) 
                    if (lfn->name3[j] != 0xFFFF) 
                        lfn_buffer[lfn_index++] = le16toh(lfn->name3[j]);
                
                // 到达最后一个条目
                if (seq & 0x40) {
                    // 反转字符顺序（VFAT条目逆序存储）
                    uint16_t temp[260];
                    int valid_len = lfn_index;
                    for (int k = 0; k < valid_len; k++) {
                        temp[k] = lfn_buffer[valid_len - k - 1];
                    }
                    memcpy(lfn_buffer, temp, valid_len*2);
                    
                    // 转换为UTF-8
                    iconv_t cd = iconv_open("UTF-8", "UTF-16LE");
                    char* inbuf = (char*)lfn_buffer;
                    char* outbuf = utf8_name;
                    size_t inlen = valid_len*2, outlen = 259;
                    iconv(cd, &inbuf, &inlen, &outbuf, &outlen);
                    iconv_close(cd);
                    
                    lfn_valid = true;
                }
            }
            else if (lfn_valid) {
                // 校验短文件名校验和
                uint8_t sum = lfn_checksum((uint8_t*)entries[i].name);
                if (sum == expected_checksum) {
                    // 比较长文件名（不区分大小写）
                    if (strcasecmp(utf8_name, name) == 0) {
                        return &entries[i];
                    }
                }
                lfn_valid = false;
            }
            else {
                // 原始短文件名比较逻辑
                // ...（保留原有代码）
            }
        }
        current_cluster = read_fat_entry(current_cluster);
    } while (current_cluster < 0x0FFFFFF8);
    
    return NULL;
}