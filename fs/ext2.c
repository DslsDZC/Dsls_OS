#include <ext2.h>
#include <stdio.h>
#include <string.h>

static int read_indirect_block(const struct ext2_context* ctx, uint32_t block,
                              uint32_t index, void* buffer);
static struct ext2_inode* get_inode(struct ext2_context* ctx, uint32_t inode_num);

static int read_block(const struct ext2_context* ctx, uint32_t block_num, void* buffer) {
    return 0;
}

int ext2_verify_superblock(struct ext2_context* ctx, const struct ext2_superblock* sb) {
    if (!ctx || !sb) return -1;
    if (sb->s_magic != EXT2_MAGIC) {
        fprintf(stderr, "Invalid superblock magic: 0x%04X\n", sb->s_magic);
        return -1;
    }
    if (sb->s_rev_level == 1 && (sb->s_feature_incompat & ~SUPPORTED_FEATURES)) {
        fprintf(stderr, "Unsupported features: 0x%08X\n", sb->s_feature_incompat);
        return -1;
    }
    ctx->block_size = BLOCK_SIZE_BASE << sb->s_log_block_size;
    memcpy(&ctx->superblock, sb, sizeof(struct ext2_superblock));
    return 0;
}

static int read_indirect_block(const struct ext2_context* ctx, uint32_t block,
                              uint32_t index, void* buffer) {
    uint32_t indirect[ctx->block_size / sizeof(uint32_t)];
    if (read_block(ctx, block, indirect) != 0) {
        fprintf(stderr, "Failed to read indirect block %u\n", block);
        return -1;
    }
    if (index >= ctx->block_size / sizeof(uint32_t)) {
        fprintf(stderr, "Index %u out of range\n", index);
        return -1;
    }
    return read_block(ctx, indirect[index], buffer);
}

int ext2_read_inode_block(const struct ext2_context* ctx, const struct ext2_inode* inode,
                         uint32_t block_num, void* buffer) {
    if (!ctx || !inode || !buffer) return -1;
    
    const uint32_t ptrs = ctx->block_size / sizeof(uint32_t);
    if (block_num < EXT2_DIRECT_BLOCKS) {
        return read_block(ctx, inode->i_block[block_num], buffer);
    }

    block_num -= EXT2_DIRECT_BLOCKS;
    if (block_num < ptrs) {
        return read_indirect_block(ctx, inode->i_block[12], block_num, buffer);
    }

    block_num -= ptrs;
    if (block_num < ptrs * ptrs) {
        uint32_t sec_idx = block_num / ptrs;
        uint32_t pri_idx = block_num % ptrs;
        uint32_t sec_block;
        if (read_indirect_block(ctx, inode->i_block[13], sec_idx, &sec_block) != 0) return -1;
        return read_indirect_block(ctx, sec_block, pri_idx, buffer);
    }

    block_num -= ptrs * ptrs;
    uint32_t ter_idx = block_num / (ptrs * ptrs);
    uint32_t sec_idx = (block_num % (ptrs * ptrs)) / ptrs;
    uint32_t pri_idx = block_num % ptrs;
    uint32_t ter_block;
    
    if (read_indirect_block(ctx, inode->i_block[14], ter_idx, &ter_block) != 0) return -1;
    uint32_t sec_block;
    if (read_indirect_block(ctx, ter_block, sec_idx, &sec_block) != 0) return -1;
    return read_indirect_block(ctx, sec_block, pri_idx, buffer);
}

void ext2_traverse_directory(struct ext2_context* ctx, uint32_t inode_num) {
    struct ext2_inode* dir_inode = get_inode(ctx, inode_num);
    if (!dir_inode) {
        fprintf(stderr, "Failed to get inode %u\n", inode_num);
        return;
    }

    uint8_t block[ctx->block_size];
    for (uint32_t pos = 0; pos < dir_inode->i_size; pos += ctx->block_size) {
        if (ext2_read_inode_block(ctx, dir_inode, pos / ctx->block_size, block) != 0) {
            fprintf(stderr, "Failed to read block at %u\n", pos);
            continue;
        }

        struct ext2_dir_entry* entry = (struct ext2_dir_entry*)block;
        uint32_t offset = 0;
        while (offset < ctx->block_size) {
            if (entry->inode && entry->name_len) {
                printf("[inode:%04u] %-20.*s (%d)\n",
                      entry->inode, entry->name_len, entry->name, entry->file_type);
            }
            if (!entry->rec_len) break;
            offset += entry->rec_len;
            entry = (struct ext2_dir_entry*)((uint8_t*)entry + entry->rec_len);
        }
    }
}

static struct ext2_inode* get_inode(struct ext2_context* ctx, uint32_t inode_num) {
    if (inode_num == 0 || inode_num > ctx->superblock.s_inodes_count) {
        fprintf(stderr, "Invalid inode number: %u\n", inode_num);
        return NULL;
    }

    const uint32_t inodes_per_group = ctx->superblock.s_inodes_per_group;
    const uint32_t group_idx = (inode_num - 1) / inodes_per_group;
    const uint32_t inode_idx = (inode_num - 1) % inodes_per_group;

    struct ext2_group_desc group;
    const uint32_t group_table_block = ctx->block_size == 1024 ? 2 : 1;
    
    if (read_block(ctx, group_table_block + group_idx, &group) != 0) {
        fprintf(stderr, "Failed to read group descriptor %u\n", group_idx);
        return NULL;
    }

    const uint32_t inode_table_block = group.bg_inode_table;
    const uint32_t inode_size = ctx->superblock.s_inode_size;
    const uint32_t inodes_per_block = ctx->block_size / inode_size;
    
    const uint32_t block_offset = inode_idx / inodes_per_block;
    const uint32_t inode_offset = (inode_idx % inodes_per_block) * inode_size;

    static uint8_t block_buffer[EXT2_MAX_BLOCK_SIZE];
    if (read_block(ctx, inode_table_block + block_offset, block_buffer) != 0) {
        fprintf(stderr, "Failed to read inode table block %u\n", inode_table_block + block_offset);
        return NULL;
    }

    return (struct ext2_inode*)(block_buffer + inode_offset);
}
