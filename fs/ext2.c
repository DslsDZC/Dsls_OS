#include <stdint.h>
#define EXT2_FEATURE_INCOMPAT_FILETYPE 0x0002
#define SUPPORTED_FEATURES (EXT2_FEATURE_INCOMPAT_FILETYPE)
uint32_t block_size;

struct ext2_superblock {
    uint32_t s_inodes_count;         // 总inode数量
    uint32_t s_blocks_count;         // 总块数量
    uint32_t s_r_blocks_count;       // 保留块数量
    uint32_t s_free_blocks_count;    // 空闲块计数
    uint32_t s_free_inodes_count;    // 空闲inode计数
    uint32_t s_first_data_block;     // 第一个数据块号
    uint32_t s_log_block_size;       // 块大小计算值（块大小=1024<<s_log_block_size）
    uint32_t s_log_frag_size;        // 碎片大小
    uint32_t s_blocks_per_group;     // 每块组块数
    uint32_t s_frags_per_group;      // 每块组碎片数
    uint32_t s_inodes_per_group;     // 每块组inode数
    uint32_t s_mtime;                // 最后挂载时间
    uint32_t s_wtime;                // 最后写入时间
    uint16_t s_mnt_count;            // 挂载计数
    uint16_t s_max_mnt_count;        // 最大挂载次数
    uint16_t s_magic;                // 魔数0xEF53
    uint16_t s_state;                // 文件系统状态
    uint16_t s_errors;               // 错误处理方式
    uint16_t s_minor_rev_level;      // 次版本号
    uint32_t s_lastcheck;            // 最后检查时间
    uint32_t s_checkinterval;        // 检查间隔
    uint32_t s_creator_os;           // 创建操作系统
    uint32_t s_rev_level;            // 主版本号
    uint16_t s_def_resuid;           // 默认保留用户ID
    uint16_t s_def_resgid;           // 默认保留组ID
    uint32_t s_first_ino;            // 第一个非保留inode号
    uint16_t s_inode_size;           // inode结构大小
    uint16_t s_block_group_nr;       // 当前块组号
    uint32_t s_feature_compat;       // 兼容特性集
    uint32_t s_feature_incompat;     // 不兼容特性集
    uint32_t s_feature_ro_compat;    // 只读兼容特性集
    uint8_t  s_uuid[16];             // 文件系统UUID
    char     s_volume_name[16];      // 卷名
    char     s_last_mounted[64];     // 最后挂载路径
    uint32_t s_algorithm_usage_bitmap;// 算法使用位图
    uint8_t  s_prealloc_blocks;      // 预分配块数
    uint8_t  s_prealloc_dir_blocks;  // 目录预分配块数
    uint16_t s_padding1;             // 对齐填充
    uint8_t  s_journal_uuid[16];     // 日志UUID
    uint32_t s_journal_inum;         // 日志inode号
    uint32_t s_journal_dev;          // 日志设备号
    uint32_t s_last_orphan;          // 最后孤立inode号
    uint32_t s_hash_seed[4];
    uint8_t  s_def_hash_version;     // 默认哈希版本
    uint8_t  s_reserved_char_pad;
    uint16_t s_reserved_word_pad;
    uint32_t s_default_mount_opts;
    uint32_t s_first_meta_bg;        // 第一个元块组
    uint32_t s_mkfs_time;            // 文件系统创建时间
    uint32_t s_jnl_blocks[17];       // 日志超级块备份
    uint32_t s_reserved[172];        // 保留字段
} __attribute__((packed));

struct ext2_inode {
    uint16_t i_mode;        // 文件模式及类型
    uint16_t i_uid;         // 所有者UID低16位
    uint32_t i_size;        // 文件大小（字节）
    uint32_t i_atime;       // 最后访问时间
    uint32_t i_ctime;       // 创建时间
    uint32_t i_mtime;       // 最后修改时间
    uint32_t i_dtime;       // 删除时间
    uint16_t i_gid;         // 组ID低16位
    uint16_t i_links_count; // 硬链接计数
    uint32_t i_blocks;      // 占用512字节块数
    uint32_t i_flags;       // 文件标志
    uint32_t i_osd1;        // 操作系统特定值1
    uint32_t i_block[15];   // 数据块指针（直接/间接）
    uint32_t i_generation;  // 文件版本（NFS使用）
    uint32_t i_file_acl;    // 文件ACL
    uint32_t i_dir_acl;     // 目录ACL
    uint32_t i_faddr;       // 碎片地址
    uint8_t  i_osd2[12];    // 操作系统特定值2
} __attribute__((packed));

struct ext2_group_desc {
    uint32_t bg_block_bitmap;     // 块位图块号
    uint32_t bg_inode_bitmap;     // inode位图块号
    uint32_t bg_inode_table;      // inode表起始块号
    uint16_t bg_free_blocks_count; // 本组空闲块数
    uint16_t bg_free_inodes_count; // 本组空闲inode数
    uint16_t bg_used_dirs_count;  // 目录inode计数
    uint16_t bg_pad;              // 对齐填充
    uint32_t bg_reserved[3];      // 保留字段
} __attribute__((packed));

struct ext2_dir_entry_2 {
    uint32_t inode;         // Inode编号
    uint16_t rec_len;       // 目录项总长度
    uint8_t  name_len;      // 文件名长度
    uint8_t  file_type;     // 文件类型标识
    char     name[];        // 变长文件名（最大255字节）
} __attribute__((packed));

enum {
    EXT2_FT_UNKNOWN = 0,
    EXT2_FT_REG_FILE = 1,   // 普通文件
    EXT2_FT_DIR = 2,        // 目录
    EXT2_FT_CHRDEV = 3,     // 字符设备
    EXT2_FT_BLKDEV = 4,     // 块设备
    EXT2_FT_FIFO = 5,       // FIFO
    EXT2_FT_SOCK = 6,       // Socket
    EXT2_FT_SYMLINK = 7     // 符号链接
};

int verify_superblock(struct ext2_superblock *sb) {
    if (sb->s_magic != 0xEF53) return -1;
    if (sb->s_rev_level == 1) {
        if (sb->s_feature_incompat & ~SUPPORTED_FEATURES) return -1;
    }
    block_size = 1024 << sb->s_log_block_size;
    return 0;
}

int read_inode_block(struct ext2_inode *inode, uint32_t block_num, void *buffer) {
    if (block_num < 12) {
        read_block(inode->i_block[block_num], buffer);
    } 
    else if (block_num < (12 + (block_size/4))) {
        uint32_t indirect[block_size/4];
        read_block(inode->i_block[12], indirect);
        read_block(indirect[block_num - 12], buffer);
    }
    else if (block_num < (12 + (block_size/4) + (block_size/4)*(block_size/4))) {
        uint32_t idx = block_num - (12 + (block_size/4));
        uint32_t secondary_idx = idx / (block_size/4);
        uint32_t primary_idx = idx % (block_size/4);

        uint32_t secondary_indirect[block_size/4];
        read_block(inode->i_block[13], secondary_indirect);

        uint32_t primary_indirect[block_size/4];
        read_block(secondary_indirect[secondary_idx], primary_indirect);

        read_block(primary_indirect[primary_idx], buffer);
    }
    else {
        uint32_t idx = block_num - (12 + (block_size/4) + (block_size/4)*(block_size/4));
        uint32_t tertiary_idx = idx / ((block_size/4)*(block_size/4));
        uint32_t secondary_idx = (idx % ((block_size/4)*(block_size/4))) / (block_size/4);
        uint32_t primary_idx = idx % (block_size/4);

        uint32_t tertiary_indirect[block_size/4];
        read_block(inode->i_block[14], tertiary_indirect);

        uint32_t secondary_indirect[block_size/4];
        read_block(tertiary_indirect[tertiary_idx], secondary_indirect);

        uint32_t primary_indirect[block_size/4];
        read_block(secondary_indirect[secondary_idx], primary_indirect);

        read_block(primary_indirect[primary_idx], buffer);
    }
    return 0;
}
void traverse_directory(uint32_t inode_num) {
    struct ext2_inode *dir_inode = get_inode(inode_num);
    uint32_t file_pos = 0;
    
    while (file_pos < dir_inode->i_size) {
        char block[block_size];
        read_inode_block(dir_inode, file_pos / block_size, block);
        
        struct ext2_dir_entry_2 *entry = (struct ext2_dir_entry_2 *)block;
        uint32_t pos_in_block = 0;
        
        while (pos_in_block < block_size) {
            if (entry->inode == 0) {
                pos_in_block += entry->rec_len;
                entry = (void*)entry + entry->rec_len;
                continue;
            }

            printf("[inode:%u] %.*s (type:%d)\n", 
                  entry->inode, 
                  entry->name_len, 
                  entry->name,
                  entry->file_type);
                  
            pos_in_block += entry->rec_len;
            entry = (void*)entry + entry->rec_len;
        }
        file_pos += block_size;
    }
}
