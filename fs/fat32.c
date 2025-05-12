#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <disk.h>
#include <slab.h>
#include <fat32.h>

static uint32_t read_fat_entry(uint32_t cluster) {
    uint32_t fat_offset = cluster * 4;
    uint32_t sector = fs_info.fat_start + (fat_offset / fs_info.bytes_per_cluster);
    uint32_t entry_offset = fat_offset % fs_info.bytes_per_cluster;
    
    uint8_t buffer[512];
    if (!read_sector(sector, buffer)) return 0xFFFFFFFF;
    
    return *(uint32_t*)(buffer + entry_offset) & 0x0FFFFFFF;
}

int fat32_init(uint32_t lba) {
    struct fat32_boot_sector bs;
    
    if (!read_sector(lba, &bs)) return -1;
    
    if (bs.signature != 0x28 && bs.signature != 0x29) return -1;
    
    fs_info.sectors_per_cluster = bs.sectors_per_cluster;
    fs_info.bytes_per_cluster = bs.bytes_per_sector * bs.sectors_per_cluster;
    fs_info.fat_start = lba + bs.reserved_sectors;
    fs_info.data_start = fs_info.fat_start + bs.fat_count * bs.sectors_per_fat;
    fs_info.root_cluster = bs.root_cluster;
    
    current_dir_cluster = fs_info.root_cluster;
    return 0;
}

static uint32_t cluster_to_lba(uint32_t cluster) {
    return fs_info.data_start + 
          (cluster - 2) * fs_info.sectors_per_cluster;
}

static int read_directory(uint32_t cluster, struct fat32_dir_entry* entries) {
    uint8_t* buffer = alloc_phys_pages(1);
    uint32_t lba = cluster_to_lba(cluster);
    
    for (int i = 0; i < fs_info.sectors_per_cluster; i++) {
        if (!read_sector(lba + i, buffer + i*512)) {
            free_phys_pages(buffer, 1);
            return -1;
        }
    }
    
    memcpy(entries, buffer, sizeof(struct fat32_dir_entry)*128);
    free_phys_pages(buffer, 1);
    return 0;
}

struct file_handle {
    uint32_t start_cluster;
    uint32_t current_cluster;
    uint32_t size;
    uint32_t pos;
};

struct vfat_long_name_entry {
    uint8_t  sequence;
    uint16_t name1[5];
    uint8_t  attr;
    uint8_t  type;
    uint8_t  checksum;
    uint16_t name2[6];
    uint16_t first_cluster;
    uint16_t name3[2];
};

static uint8_t lfn_checksum(const uint8_t* short_name) {
    uint8_t sum = 0;
    for (int i = 0; i < 11; i++) {
        sum = ((sum & 1) ? 0x80 : 0) + (sum >> 1) + short_name[i];
    }
    return sum;
}

int strcasecmp(const char* s1, const char* s2) {
    while (*s1 && (tolower(*s1) == tolower(*s2))) 
        s1++, s2++;
    return tolower(*s1) - tolower(*s2);
}

struct fat32_dir_entry* find_file(const char* name) {
    static struct fat32_dir_entry entries[128];
    uint32_t current_cluster = current_dir_cluster;
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

            if (entries[i].attr == 0x0F) {
                struct vfat_long_name_entry* lfn = (struct vfat_long_name_entry*)&entries[i];
                
                if (lfn->attr != 0x0F || lfn->type != 0) continue;
                
                uint8_t seq = lfn->sequence;
                if (seq & 0x40) {
                    lfn_index = 0;
                    expected_checksum = lfn->checksum;
                    memset(lfn_buffer, 0, sizeof(lfn_buffer));
                }
                
                for (int j = 0; j < 5; j++) 
                    if (lfn->name1[j] != 0xFFFF) 
                        lfn_buffer[lfn_index++] = le16toh(lfn->name1[j]);
                
                for (int j = 0; j < 6; j++) 
                    if (lfn->name2[j] != 0xFFFF) 
                        lfn_buffer[lfn_index++] = le16toh(lfn->name2[j]);
                
                for (int j = 0; j < 2; j++) 
                    if (lfn->name3[j] != 0xFFFF) 
                        lfn_buffer[lfn_index++] = le16toh(lfn->name3[j]);
                
                if (seq & 0x40) {
                    uint16_t temp[260];
                    int valid_len = lfn_index;
                    for (int k = 0; k < valid_len; k++) {
                        temp[k] = lfn_buffer[valid_len - k - 1];
                    }
                    memcpy(lfn_buffer, temp, valid_len*2);
                    
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
                uint8_t sum = lfn_checksum((uint8_t*)entries[i].name);
                if (sum == expected_checksum) {
                    if (strcasecmp(utf8_name, name) == 0) {
                        return &entries[i];
                    }
                }
                lfn_valid = false;
            }
        }
        current_cluster = read_fat_entry(current_cluster);
    } while (current_cluster < 0x0FFFFFF8);
    
    return NULL;
}

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

int fat32_read(void* handle, void* buffer, uint32_t size) {
    struct file_handle* fh = handle;
    uint32_t bytes_remaining = fh->size - fh->pos;
    if (size > bytes_remaining) size = bytes_remaining;
    
    uint32_t cluster_offset = fh->pos / fs_info.bytes_per_cluster;
    uint32_t pos_in_cluster = fh->pos % fs_info.bytes_per_cluster;
    
    uint32_t cluster = fh->start_cluster;
    for (int i = 0; i < cluster_offset; i++) {
        cluster = read_fat_entry(cluster);
        if (cluster >= 0x0FFFFFF8) break;
    }
    
    uint8_t* data = alloc_phys_pages(1);
    uint32_t total_read = 0;
    
    while (size > 0 && cluster < 0x0FFFFFF8) {
        uint32_t lba = cluster_to_lba(cluster);
        read_sector(lba, data);
        
        uint32_t copy_size = fs_info.bytes_per_cluster - pos_in_cluster;
        if (copy_size > size) copy_size = size;
        memcpy(buffer, data + pos_in_cluster, copy_size);
        buffer += copy_size;
        size -= copy_size;
        total_read += copy_size;
        fh->pos += copy_size;
        
        cluster = read_fat_entry(cluster);
        pos_in_cluster = 0;
    }
    
    free_phys_pages(data, 1);
    return total_read;
}
