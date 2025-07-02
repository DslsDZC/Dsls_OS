#ifndef EFILIB_H
#define EFILIB_H

#include <efi.h>
#include <stddef.h>
#include <stdint.h>

// 常用EFI类型简写
typedef uint64_t UINTN;
typedef uint32_t UINT32;
typedef uint16_t UINT16;
typedef uint8_t  UINT8;
typedef int64_t  INTN;
typedef int32_t  INT32;
typedef int16_t  INT16;
typedef int8_t   INT8;
typedef uint64_t EFI_PHYSICAL_ADDRESS;
typedef uint64_t EFI_VIRTUAL_ADDRESS;

// EFI_SYSTEM_TABLE、EFI_HANDLE等已在 efi.h 定义

// EFI_GRAPHICS_OUTPUT_PROTOCOL 结构体（简化版）
typedef struct {
    uint64_t                _pad1[4];
    struct {
        UINT32              Version;
        UINT32              HorizontalResolution;
        UINT32              VerticalResolution;
        UINT32              PixelFormat;
        UINT32              PixelInformation[4];
        UINT32              PixelsPerScanLine;
    } *Mode;
    void*                   _pad2[3];
} EFI_GRAPHICS_OUTPUT_PROTOCOL;

// 常用EFI函数声明（可根据实际需要补充）
void Print(const CHAR16 *fmt, ...);
void WaitForKey();
void Halt();

typedef struct {
    uint32_t Type;
    uint32_t Pad;
    uint64_t PhysicalStart;
    uint64_t VirtualStart;
    uint64_t NumberOfPages;
    uint64_t Attribute;
} EFI_MEMORY_DESCRIPTOR;

#endif // EFILIB_H
