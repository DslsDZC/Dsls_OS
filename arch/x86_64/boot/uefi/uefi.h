#ifndef UEFI_H
#define UEFI_H

#include <efi.h>
#include <efilib.h>
#include <elf.h>
#include <Protocol/Security2.h>

// 图形模式信息结构
typedef struct {
    UINT32 width;
    UINT32 height;
    UINT32 pixels_per_scanline;
    EFI_GRAPHICS_PIXEL_FORMAT pixel_format;
    EFI_PHYSICAL_ADDRESS framebuffer_base;
    UINT64 framebuffer_size;
} graphics_info_t;

// 内存映射信息结构
typedef struct {
    EFI_MEMORY_DESCRIPTOR* memory_map;
    UINTN memory_map_size;
    UINTN descriptor_size;
    UINT32 descriptor_version;
    UINTN map_key;
} memory_map_info_t;

// 内核启动参数结构
typedef struct {
    graphics_info_t graphics;
    memory_map_info_t memory_map;
    VOID* acpi_rsdp;              // ACPI根系统描述指针
    CHAR16 cmdline[256];          // 内核命令行参数
    UINT32 crc32;                 // 引导参数CRC32校验和
} boot_params_t;

// 函数声明
EFI_STATUS EFIAPI uefi_main(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE* SystemTable);
EFI_STATUS init_graphics(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE* SystemTable, graphics_info_t* gfx_info);
EFI_STATUS load_kernel(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE* SystemTable, VOID** kernel_entry_point);
EFI_STATUS verify_kernel_signature(EFI_SYSTEM_TABLE* SystemTable, VOID* kernel_data, UINTN kernel_size);
EFI_STATUS set_kernel_memory_protection(EFI_SYSTEM_TABLE* SystemTable, Elf64_Ehdr* elf_header, EFI_PHYSICAL_ADDRESS kernel_address);
EFI_STATUS validate_memory_map(EFI_MEMORY_DESCRIPTOR* memory_map, UINTN memory_map_size, UINTN descriptor_size);
UINT32 calculate_boot_params_crc(boot_params_t* boot_params);
EFI_STATUS get_acpi_tables(EFI_SYSTEM_TABLE* SystemTable, VOID** rsdp);
EFI_STATUS get_kernel_command_line(EFI_SYSTEM_TABLE* SystemTable, CHAR16* cmdline, UINTN size);
EFI_STATUS setup_kernel_stack(EFI_SYSTEM_TABLE* SystemTable, EFI_PHYSICAL_ADDRESS* stack_top);

#endif // UEFI_H