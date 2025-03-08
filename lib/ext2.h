// ext2.h
#pragma once
#include <stdint.h>

// --------------------- 系统常量定义 ---------------------
#define EXT2_FEATURE_INCOMPAT_FILETYPE 0x0002  // 文件类型不兼容特性标志
#define SUPPORTED_FEATURES (EXT2_FEATURE_INCOMPAT_FILETYPE) // 当前支持的特性集
#define EXT2_DIRECT_BLOCKS 12        // 直接块指针数量
#define EXT2_MAGIC 0xEF53            // 文件系统魔数标识
#define EXT2_NAME_MAX 255            // 最大文件名长度
#define BLOCK_SIZE_BASE 1024         // 基础块大小（单位：字节）
#define EXT2_MAX_BLOCK_SIZE 4096     // 系统支持的最大块尺寸

// --------------------- 磁盘结构定义 ---------------------

/* 超级块结构 (磁盘布局)
 * 描述文件系统全局信息，位于块组0的起始位置
 */
struct ext2_superblock {
    // 基础信息段
    uint32_t s_inodes_count;         // 总inode数量
    uint32_t s_blocks_count;         // 总数据块数量
    uint32_t s_r_blocks_count;       // 保留块数量（root保留）
    uint32_t s_free_blocks_count;    // 空闲块计数器
    uint32_t s_free_inodes_count;    // 空闲inode计数器
    
    // 布局信息段
    uint32_t s_first_data_block;     // 第一个数据块号（通常为1）
    uint32_t s_log_block_size;       // 块大小指数（实际大小=1024<<此值）
    uint32_t s_log_frag_size;        // 碎片大小（通常与块大小相同）
    uint32_t s_blocks_per_group;     // 每个块组包含的块数
    uint32_t s_frags_per_group;      // 每个块组包含的碎片数
    uint32_t s_inodes_per_group;     // 每个块组包含的inode数
    
    // 时间信息段
    uint32_t s_mtime;                // 最后挂载时间（Unix时间戳）
    uint32_t s_wtime;                // 最后写入时间
    
    // 挂载状态段
    uint16_t s_mnt_count;            // 挂载次数计数器
    uint16_t s_max_mnt_count;        // 最大允许挂载次数（0表示无限）
    uint16_t s_magic;                // 魔数标识（必须为0xEF53）
    uint16_t s_state;                // 文件系统状态标志
    uint16_t s_errors;               // 错误处理策略
    
    // 版本信息段
    uint16_t s_minor_rev_level;      // 次要修订版本号
    uint32_t s_lastcheck;            // 最后一致性检查时间
    uint32_t s_checkinterval;        // 强制检查间隔（秒）
    
    // 系统标识段
    uint32_t s_creator_os;           // 创建操作系统标识
    uint32_t s_rev_level;            // 主版本号（0=原始版本，1=v2版本）
    
    // 权限默认值
    uint16_t s_def_resuid;           // 保留块的默认用户ID
    uint16_t s_def_resgid;           // 保留块的默认组ID
    
    // Inode管理段
    uint32_t s_first_ino;            // 第一个非保留inode号（通常为11）
    uint16_t s_inode_size;           // inode结构大小（字节）
    uint16_t s_block_group_nr;       // 包含该超级块的块组号
    
    // 特性标志段
    uint32_t s_feature_compat;       // 兼容特性位图
    uint32_t s_feature_incompat;     // 不兼容特性位图
    uint32_t s_feature_ro_compat;    // 只读兼容特性位图
    
    // 存储标识段
    uint8_t  s_uuid[16];             // 文件系统UUID（128位唯一标识）
    char     s_volume_name[16];      // 卷标名称（最多15字符）
    char     s_last_mounted[64];     // 最后挂载路径
    
    // 算法与压缩
    uint32_t s_algorithm_usage_bitmap; // 压缩算法使用位图
    
    // 性能优化参数
    uint8_t  s_prealloc_blocks;      // 普通文件预分配块数
    uint8_t  s_prealloc_dir_blocks;  // 目录文件预分配块数
    
    // 对齐填充
    uint16_t s_padding1;
    
    // 日志系统参数
    uint8_t  s_journal_uuid[16];     // 日志设备UUID
    uint32_t s_journal_inum;         // 日志文件inode号
    uint32_t s_journal_dev;          // 日志设备号
    uint32_t s_last_orphan;          // 孤立inode链表头
    
    // 哈希参数
    uint32_t s_hash_seed[4];         // 目录哈希种子
    uint8_t  s_def_hash_version;     // 默认哈希算法版本
    
    // 保留字段
    uint8_t  s_reserved_char_pad;
    uint16_t s_reserved_word_pad;
    uint32_t s_default_mount_opts;
    
    // 元数据块组参数
    uint32_t s_first_meta_bg;        // 第一个元块组编号
    
    // 文件系统创建信息
    uint32_t s_mkfs_time;            // 文件系统创建时间
    
    // 日志备份区域
    uint32_t s_jnl_blocks[17];       // 日志超级块备份
    
    // 未来扩展保留空间
    uint32_t s_reserved[172];
} __attribute__((packed));

/* Inode结构 (磁盘布局)
 * 描述文件元数据，每个文件/目录对应一个inode
 */
struct ext2_inode {
    // 基础元数据
    uint16_t i_mode;        // 文件类型和访问权限（见S_IFMT）
    uint16_t i_uid;         // 属主用户ID低16位（高16位在i_osd1）
    uint32_t i_size;        // 文件大小（字节数），对设备文件表示设备号
    
    // 时间戳
    uint32_t i_atime;       // 最后访问时间（Unix时间戳）
    uint32_t i_ctime;       // 创建时间/状态变更时间
    uint32_t i_mtime;       // 最后修改时间
    uint32_t i_dtime;       // 删除时间
    
    // 权限与链接
    uint16_t i_gid;         // 属组ID低16位（高16位在i_osd1）
    uint16_t i_links_count; // 硬链接计数
    
    // 块使用情况
    uint32_t i_blocks;      // 512字节块使用量
    
    // 文件标志
    uint32_t i_flags;       // 扩展属性标志（如不可变文件等）
    
    // 操作系统特定字段
    uint32_t i_osd1;        // OS依赖值1
    
    // 数据块指针
    uint32_t i_block[15];   // 块指针数组：
                            // [0-11] 直接块指针
                            // [12]   一级间接块指针
                            // [13]   二级间接块指针
                            // [14]   三级间接块指针
    
    // 版本控制
    uint32_t i_generation;  // 文件版本号（NFS使用）
    
    // 扩展属性
    uint32_t i_file_acl;    // 文件访问控制表块指针
    uint32_t i_dir_acl;     // 目录访问控制表块指针
    
    // 碎片管理
    uint32_t i_faddr;       // 碎片地址
    
    // 操作系统特定字段扩展
    uint8_t  i_osd2[12];    // OS依赖值2
} __attribute__((packed));

/* 块组描述符结构 (磁盘布局)
 * 描述块组的元数据信息
 */
struct ext2_group_desc {
    uint32_t bg_block_bitmap;     // 块位图所在块号
    uint32_t bg_inode_bitmap;     // inode位图所在块号
    uint32_t bg_inode_table;      // inode表起始块号
    
    // 统计信息
    uint16_t bg_free_blocks_count; // 本组空闲块数
    uint16_t bg_free_inodes_count; // 本组空闲inode数
    uint16_t bg_used_dirs_count;  // 目录inode数量（用于平衡树分配）
    
    // 对齐填充
    uint16_t bg_pad;
    
    // 保留字段
    uint32_t bg_reserved[3];
} __attribute__((packed));

/* 目录项结构 (磁盘布局)
 * 用于目录文件中的条目存储
 */
struct ext2_dir_entry {
    uint32_t inode;         // 条目对应的inode号
    uint16_t rec_len;       // 目录项总长度（包含填充）
    uint8_t  name_len;      // 实际文件名长度（不含终止符）
    uint8_t  file_type;     // 文件类型标识（见ext2_file_type）
    char     name[EXT2_NAME_MAX]; // 变长文件名（实际长度由name_len决定）
} __attribute__((packed));

// --------------------- 文件类型枚举 ---------------------
/* 文件类型标识枚举
 * 用于目录项的file_type字段
 */
enum ext2_file_type {
    EXT2_FT_UNKNOWN = 0,   // 未知类型
    EXT2_FT_REG_FILE,      // 普通文件
    EXT2_FT_DIR,           // 目录
    EXT2_FT_CHRDEV,        // 字符设备文件
    EXT2_FT_BLKDEV,        // 块设备文件
    EXT2_FT_FIFO,          // 命名管道（FIFO）
    EXT2_FT_SOCK,          // 套接字文件
    EXT2_FT_SYMLINK        // 符号链接文件
};

// --------------------- 文件系统上下文 ---------------------
/* 文件系统操作上下文结构
 * 维护文件系统运行时状态
 */
struct ext2_context {
    uint32_t block_size;            // 当前块大小（根据超级块计算）
    struct ext2_superblock superblock; // 内存中的超级块副本
    // 可扩展字段：
    // - 块缓存指针
    // - 挂载选项标志
    // - 当前操作设备标识
};

// --------------------- 公开API接口 ---------------------
/* 超级块验证函数
 * @param ctx 文件系统上下文指针
 * @param sb 待验证的超级块指针
 * @return 0成功，负数表示错误
 */
int ext2_verify_superblock(struct ext2_context *ctx, const struct ext2_superblock *sb);

/* 读取inode数据块
 * @param ctx 文件系统上下文
 * @param inode 目标inode指针
 * @param block_num 逻辑块号（从0开始）
 * @param buffer 输出缓冲区（需至少block_size大小）
 * @return 0成功，负数表示错误
 */
int ext2_read_inode_block(const struct ext2_context *ctx, const struct ext2_inode *inode, 
                         uint32_t block_num, void *buffer);

/* 遍历目录内容
 * @param ctx 文件系统上下文
 * @param inode_num 目录inode编号
 */
void ext2_traverse_directory(struct ext2_context *ctx, uint32_t inode_num);
