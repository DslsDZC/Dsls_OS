#ifndef UEFI_H
#define UEFI_H

#include <efi.h>
#include <efilib.h>
#include <stddef.h>
#include <stdint.h>

// 基本类型
typedef uint64_t EFI_PHYSICAL_ADDRESS;
typedef uint64_t EFI_VIRTUAL_ADDRESS;
typedef uint64_t EFI_STATUS;
typedef void*    EFI_HANDLE;
typedef void*    EFI_EVENT;
typedef uint16_t CHAR16;
typedef uint64_t EFI_LBA;
typedef unsigned long UINTN;
typedef uint32_t UINT32;
typedef uint8_t  UINT8;
typedef void     VOID;
typedef uint64_t UINT64;

// EFI_LOADED_IMAGE_PROTOCOL_GUID
static const EFI_GUID EFI_LOADED_IMAGE_PROTOCOL_GUID = 
    { 0x5B1B31A1, 0x9562, 0x11d2, {0x8E,0x3F,0x00,0xA0,0xC9,0x69,0x72,0x3B} };

// EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID
static const EFI_GUID EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID = 
    { 0x0964e5b22, 0x6459, 0x11d2, {0x8e,0x39,0x00,0xa0,0xc9,0x69,0x72,0x3b} };

// gEfiFileInfoGuid
static const EFI_GUID gEfiFileInfoGuid = 
    { 0x09576e92, 0x6d3f, 0x11d2, {0x8e,0x39,0x00,0xa0,0xc9,0x69,0x72,0x3b} };

// EFI_FILE_MODE_READ、EFI_FILE_READ_ONLY
#define EFI_FILE_MODE_READ      0x0000000000000001ULL
#define EFI_FILE_READ_ONLY      0x0000000000000001ULL

// EFI_SIZE_TO_PAGES 宏
#define EFI_SIZE_TO_PAGES(a)  (((a) >> 12) + (((a) & 0xfff) ? 1 : 0))

// EfiLoaderData、AllocateAddress
#define EfiLoaderData      4
#define AllocateAddress    2

// EFI_GRAPHICS_OUTPUT_PROTOCOL
typedef struct _EFI_GRAPHICS_OUTPUT_PROTOCOL EFI_GRAPHICS_OUTPUT_PROTOCOL;

// EFI_GRAPHICS_OUTPUT_MODE_INFORMATION 结构体
typedef struct {
    UINT32 Version;
    UINT32 HorizontalResolution;
    UINT32 VerticalResolution;
    UINT32 PixelFormat;
    UINT32 PixelsPerScanLine;
} EFI_GRAPHICS_OUTPUT_MODE_INFORMATION;

// EFI_GRAPHICS_OUTPUT_BLT_PIXEL 结构体
typedef struct {
    UINT8 Blue;
    UINT8 Green;
    UINT8 Red;
    UINT8 Reserved;
} EFI_GRAPHICS_OUTPUT_BLT_PIXEL;

// FrameBuffer 结构体
typedef struct {
    UINT32 *Base;          // 帧缓冲区基地址
    UINTN Width;          // 宽度
    UINTN Height;         // 高度
    UINTN Stride;         // 每行字节数
} FrameBuffer;

// EFI_GRAPHICS_OUTPUT_PROTOCOL_GUID
static const EFI_GUID EFI_GRAPHICS_OUTPUT_PROTOCOL_GUID =
    { 0x9042a9de, 0x23dc, 0x4a38, { 0x96, 0xfb, 0x7a, 0xde, 0xd0, 0x80, 0x51, 0x6a } };

// EFI_MEMORY_DESCRIPTOR 结构体
typedef struct {
    UINT32 Type;
    UINT32 Pad;
    EFI_PHYSICAL_ADDRESS PhysicalStart;
    EFI_VIRTUAL_ADDRESS VirtualStart;
    UINT64 NumberOfPages;
    UINT64 Attribute;
} EFI_MEMORY_DESCRIPTOR;

typedef struct _EFI_FILE_PROTOCOL EFI_FILE_PROTOCOL;
typedef struct {
    UINT64 Size;
    UINT64 FileSize;
    UINT64 PhysicalSize;
    UINT64 CreateTime;
    UINT64 LastAccessTime;
    UINT64 ModificationTime;
    UINT64 Attribute;
    CHAR16 FileName[1];

} EFI_FILE_INFO;

// MemoryMapInfo 结构体
typedef struct {
    EFI_MEMORY_DESCRIPTOR *Map;
    UINTN Size;
    UINTN MapKey;
    UINTN DescriptorSize;
    UINT32 DescriptorVersion;
} MemoryMapInfo;

// BootServices 指针
typedef struct _EFI_BOOT_SERVICES EFI_BOOT_SERVICES;
extern EFI_BOOT_SERVICES *BS;

#define EFIAPI __attribute__((ms_abi))
#define EFI_ERROR(Status) (((INTN)(Status)) < 0)
void Print(const CHAR16 *fmt, ...);

#endif // UEFI_H