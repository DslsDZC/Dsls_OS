#ifndef EFI_H
#define EFI_H

#include <stdint.h>
#include <stddef.h>

// EFI 基本类型定义
typedef uint64_t EFI_STATUS;
typedef void*    EFI_HANDLE;
typedef void*    EFI_EVENT;
typedef uint16_t CHAR16;
typedef uint64_t EFI_LBA;
typedef uint64_t EFI_PHYSICAL_ADDRESS;
typedef uint64_t EFI_VIRTUAL_ADDRESS;

// EFI GUID 结构体
typedef struct {
    uint32_t  Data1;
    uint16_t  Data2;
    uint16_t  Data3;
    uint8_t   Data4[8];
} EFI_GUID;

// EFI 表头
typedef struct {
    uint64_t  Signature;
    uint32_t  Revision;
    uint32_t  HeaderSize;
    uint32_t  CRC32;
    uint32_t  Reserved;
} EFI_TABLE_HEADER;

// EFI 系统表
typedef struct {
    EFI_TABLE_HEADER Hdr;
    CHAR16           *FirmwareVendor;
    uint32_t         FirmwareRevision;
    EFI_HANDLE       ConsoleInHandle;
    void*            ConIn;
    EFI_HANDLE       ConsoleOutHandle;
    void*            ConOut;
    EFI_HANDLE       StandardErrorHandle;
    void*            StdErr;
    void*            RuntimeServices;
    void*            BootServices;
    size_t           NumberOfTableEntries;
    void*            ConfigurationTable;
} EFI_SYSTEM_TABLE;

#endif // EFI_H