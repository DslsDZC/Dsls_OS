// uefi.h - 增强版头文件
#ifndef UEFI_H
#define UEFI_H

#include <efi.h>
#include <efilib.h>
#include <elf.h>
#include <Protocol/Security2.h>
#include <Protocol/DevicePath.h>
#include <Protocol/BlockIo.h>
#include <Protocol/SimpleFileSystem.h>
#include <Protocol/AbsolutePointer.h>
#include <Protocol/Hash2.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/PrintLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/BaseLib.h>
#include <Library/DebugLib.h>
#include <Library/PcdLib.h>

// 版本信息
#define BOOTLOADER_VERSION_MAJOR 1
#define BOOTLOADER_VERSION_MINOR 0
#define BOOTLOADER_VERSION_PATCH 0
#define BOOTLOADER_VERSION_STRING L"v1.0.0-20240520"

// 安全启动相关
#define SECURE_BOOT_ENABLED 1
#define KERNEL_HASH_SIZE 32  // SHA-256
#define KERNEL_SIGNATURE_SIZE 256
#define MAX_CPU_CORES 256
#define MAX_BOOT_ENTRIES 10
#define MAX_LOG_SIZE 16384   // 16KB日志缓冲区

// 图形信息结构
typedef struct {
    UINT32 width;
    UINT32 height;
    UINT32 pixels_per_scanline;
    EFI_GRAPHICS_PIXEL_FORMAT pixel_format;
    EFI_PHYSICAL_ADDRESS framebuffer_base;
    UINT64 framebuffer_size;
    BOOLEAN initialized;
} graphics_info_t;

// 内存映射信息结构
typedef struct {
    EFI_MEMORY_DESCRIPTOR* memory_map;
    UINTN memory_map_size;
    UINTN descriptor_size;
    UINT32 descriptor_version;
    UINTN map_key;
} memory_map_info_t;

// ACPI信息结构
typedef struct {
    VOID* rsdp;
    VOID* xsdt;
    VOID* fadt;
    VOID* madt;
    VOID* hpet;
} acpi_info_t;

// 硬件信息结构
typedef struct {
    UINT64 cpu_features;
    UINT64 cpu_count;
    UINT64 timer_frequency;
    UINT64 pm_timer_address;
    UINT64 apic_address;
} hardware_info_t;

// 引导参数结构
typedef struct {
    graphics_info_t graphics;
    memory_map_info_t memory_map;
    acpi_info_t acpi;
    hardware_info_t hardware;
    CHAR16 cmdline[512];
    UINT32 crc32;
    UINT64 kernel_base;
    UINT64 kernel_size;
    UINT64 initrd_base;
    UINT64 initrd_size;
    UINT64 boot_time;
    UINT64 tsc_frequency;
} boot_params_t;

// 内核哈希和签名信息
typedef struct {
    UINT8 expected_hash[KERNEL_HASH_SIZE];
    UINT8 signature[KERNEL_SIGNATURE_SIZE];
    UINTN signature_size;
} kernel_security_info_t;

// 启动菜单项
typedef struct {
    CHAR16 name[64];
    CHAR16 kernel_path[256];
    CHAR16 initrd_path[256];
    CHAR16 cmdline[512];
    BOOLEAN default_entry;
} boot_entry_t;

// 启动菜单
typedef struct {
    boot_entry_t entries[MAX_BOOT_ENTRIES];
    UINTN count;
    UINTN default_index;
    UINTN timeout_seconds;
} boot_menu_t;

// 函数声明
EFI_STATUS EFIAPI uefi_main(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE* SystemTable);
EFI_STATUS init_graphics(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE* SystemTable, graphics_info_t* gfx_info);
EFI_STATUS load_kernel(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE* SystemTable, VOID** kernel_entry_point,
    UINT64* kernel_base, UINT64* kernel_size, const CHAR16* kernel_path);
EFI_STATUS verify_kernel_signature(EFI_SYSTEM_TABLE* SystemTable, VOID* kernel_data, UINTN kernel_size);
EFI_STATUS set_kernel_memory_protection(EFI_SYSTEM_TABLE* SystemTable, Elf64_Ehdr* elf_header, EFI_PHYSICAL_ADDRESS kernel_address);
EFI_STATUS validate_memory_map(EFI_MEMORY_DESCRIPTOR* memory_map, UINTN memory_map_size, UINTN descriptor_size);
UINT32 calculate_boot_params_crc(boot_params_t* boot_params);
EFI_STATUS get_acpi_tables(EFI_SYSTEM_TABLE* SystemTable, acpi_info_t* acpi_info);
EFI_STATUS get_kernel_command_line(EFI_SYSTEM_TABLE* SystemTable, CHAR16* cmdline, UINTN size, const CHAR16* default_cmdline);
EFI_STATUS setup_kernel_stack(EFI_SYSTEM_TABLE* SystemTable, EFI_PHYSICAL_ADDRESS* stack_top, UINTN stack_pages);
EFI_STATUS detect_hardware(EFI_SYSTEM_TABLE* SystemTable, hardware_info_t* hw_info);
EFI_STATUS load_initrd(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE* SystemTable,
    UINT64* initrd_base, UINT64* initrd_size, const CHAR16* initrd_path);
EFI_STATUS setup_paging(EFI_SYSTEM_TABLE* SystemTable);
EFI_STATUS save_boot_log(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE* SystemTable, const CHAR16* log_msg);
EFI_STATUS read_kernel_security_info(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE* SystemTable,
    kernel_security_info_t* sec_info, const CHAR16* kernel_path);
EFI_STATUS check_secure_boot_status(EFI_SYSTEM_TABLE* SystemTable);
EFI_STATUS enable_nx_protection(EFI_SYSTEM_TABLE* SystemTable);
EFI_STATUS reserve_critical_memory(EFI_SYSTEM_TABLE* SystemTable);
EFI_STATUS get_memory_map_with_retry(EFI_SYSTEM_TABLE* SystemTable, EFI_MEMORY_DESCRIPTOR** memory_map,
    UINTN* memory_map_size, UINTN* map_key, UINTN* descriptor_size,
    UINT32* descriptor_version);
EFI_STATUS calculate_sha256_hash(EFI_SYSTEM_TABLE* SystemTable, VOID* data, UINTN size, UINT8* hash);
EFI_STATUS parse_boot_menu(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE* SystemTable, boot_menu_t* menu);
EFI_STATUS show_boot_menu(EFI_SYSTEM_TABLE* SystemTable, boot_menu_t* menu, UINTN* selected_index);
EFI_STATUS get_expected_kernel_hash(EFI_SYSTEM_TABLE* SystemTable, UINT8* hash, UINTN hash_size, const CHAR16* kernel_path);
EFI_STATUS detect_cpu_cores(EFI_SYSTEM_TABLE* SystemTable, hardware_info_t* hw_info);
EFI_STATUS get_tsc_frequency(EFI_SYSTEM_TABLE* SystemTable, UINT64* tsc_freq);

// 调试和日志功能
#define LOG_LEVEL_INFO 1
#define LOG_LEVEL_WARNING 2
#define LOG_LEVEL_ERROR 3
#define LOG_LEVEL_DEBUG 4

VOID log_message(EFI_SYSTEM_TABLE* SystemTable, UINTN level, const CHAR16* format, ...);

#endif // UEFI_H
