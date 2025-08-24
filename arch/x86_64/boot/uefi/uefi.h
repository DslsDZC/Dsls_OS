#ifndef UEFI_H
#define UEFI_H

#include <efi.h>
#include <efilib.h>

// ͼ��ģʽ��Ϣ�ṹ
typedef struct {
    UINT32 width;
    UINT32 height;
    UINT32 pixels_per_scanline;
    EFI_GRAPHICS_PIXEL_FORMAT pixel_format;
    EFI_PHYSICAL_ADDRESS framebuffer_base;
    UINT64 framebuffer_size;
} graphics_info_t;

// �ڴ�ӳ����Ϣ�ṹ
typedef struct {
    EFI_MEMORY_DESCRIPTOR* memory_map;
    UINTN memory_map_size;
    UINTN descriptor_size;
    UINT32 descriptor_version;
    UINTN map_key;
} memory_map_info_t;

// �ں����������ṹ
typedef struct {
    graphics_info_t graphics;
    memory_map_info_t memory_map;
    // �����������������������ACPI���
} boot_params_t;

// ��������
EFI_STATUS EFIAPI uefi_main(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE* SystemTable);
EFI_STATUS init_graphics(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE* SystemTable, graphics_info_t* gfx_info);
EFI_STATUS load_kernel(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE* SystemTable, VOID** kernel_entry_point);

#endif // UEFI_H