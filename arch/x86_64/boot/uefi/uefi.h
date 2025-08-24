#ifndef UEFI_H
#define UEFI_H

#include <efi.h>
#include <efilib.h>

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
    // 可以添加其他启动参数，如ACPI表等
} boot_params_t;

// 函数声明
EFI_STATUS EFIAPI uefi_main(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE* SystemTable);
EFI_STATUS init_graphics(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE* SystemTable, graphics_info_t* gfx_info);
EFI_STATUS load_kernel(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE* SystemTable, VOID** kernel_entry_point);

#endif // UEFI_H