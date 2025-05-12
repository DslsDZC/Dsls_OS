typedef unsigned long long uint64_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
typedef uint16_t CHAR16;

typedef enum {
    AllocateAnyPages,
    EfiLoaderData,
    EfiRuntimeServicesCode
} EFI_ALLOC_TYPE;

typedef struct {
    uint64_t (*GetMemoryMap)(uint64_t*, void*, uint64_t*, uint64_t*, uint32_t*);
    uint64_t (*ExitBootServices)(void*, uint64_t);
    uint64_t (*AllocatePages)(EFI_ALLOC_TYPE, uint32_t, uint64_t, uint64_t*);
    uint64_t (*WaitForEvent)(uint64_t, void**, uint64_t*);
    uint64_t (*SetMem)(void*, uint64_t, uint8_t);
} EFI_BOOT_SERVICES;

typedef struct {
    uint64_t (*SetVirtualAddressMap)(uint64_t, uint64_t, uint32_t, void*);
    uint64_t (*ResetSystem)(uint64_t, uint64_t, uint64_t, void*);
} EFI_RUNTIME_SERVICES;

typedef struct {
    uint64_t (*Output)(void*, CHAR16*);
} EFI_SIMPLE_TEXT_OUTPUT;

typedef struct {
    uint64_t Signature;               // 0x00: "SYST" 签名
    uint32_t Revision;                // 0x08: 规范版本
    uint32_t HeaderSize;              // 0x0C: 表头大小
    uint64_t FirmwareVendor;          // 0x10: 固件厂商字符串指针
    uint32_t FirmwareRevision;        // 0x18: 固件版本
    uint32_t Pad;                     // 0x1C: 对齐填充
    uint64_t ConsoleInHandle;         // 0x20: 控制台输入句柄
    EFI_SIMPLE_TEXT_OUTPUT* ConOut;   // 0x28: 正确偏移量
    EFI_BOOT_SERVICES* BootServices;  // 0x30: 正确偏移量
    EFI_RUNTIME_SERVICES* RuntimeServices; // 0x38
} EFI_SYSTEM_TABLE;

typedef struct {
    uint32_t type;
    uint32_t pad;
    uint64_t phys_addr;
    uint64_t virt_addr;
    uint64_t num_pages;
    uint64_t attr;
} EFI_MEMORY_DESCRIPTOR;

typedef uint64_t EFI_STATUS;
typedef void* EFI_HANDLE;

EFI_STATUS EfiMain(EFI_HANDLE ImageHandle, struct EFI_SYSTEM_TABLE* SystemTable) {
    EFI_STATUS Status;
    static const CHAR16 message[] = L"裸机UEFI模式";
    printf("ConOut Offset: 0x%llx\n", offsetof(EFI_SYSTEM_TABLE, ConOut));

    if (SystemTable->ConOut && SystemTable->ConOut->Output) {
        Status = SystemTable->ConOut->Output(SystemTable->ConOut, (CHAR16*)message);
        if (Status) return Status;
    }

    uint64_t MemMapSize = 0, MapKey, DescSize, Pages;
    uint32_t DescVer;
    uint64_t MemMapBuf;

    SystemTable->BootServices->GetMemoryMap(&MemMapSize, NULL, &MapKey, &DescSize, &DescVer);
    MemMapSize += (MemMapSize / 5);
    Pages = (MemMapSize + 4095) / 4096;
    SystemTable->BootServices->AllocatePages(AllocateAnyPages, EfiRuntimeServicesCode, Pages, &MemMapBuf);
    SystemTable->BootServices->SetMem((void*)MemMapBuf, Pages * 4096, 0);

    EFI_MEMORY_DESCRIPTOR* Desc = (EFI_MEMORY_DESCRIPTOR*)MemMapBuf;
    uint64_t BufferEnd = MemMapBuf + Pages * 4096;

    do {
        Status = SystemTable->BootServices->GetMemoryMap(&MemMapSize, (void*)MemMapBuf, &MapKey, &DescSize, &DescVer);
    } while (Status == 0x8000000000000002);

    if (!EFI_ERROR(Status)) {
        for (uint64_t i = 0; i < MemMapSize / DescSize; i++) {
            if ((uint8_t*)(Desc + 1) > (uint8_t*)BufferEnd) break;
            if (Desc->Type == EfiLoaderData) Desc->Type = EfiRuntimeServicesCode;
            Desc = (EFI_MEMORY_DESCRIPTOR*)((uint8_t*)Desc + DescSize);
        }

        if (SystemTable->RuntimeServices->SetVirtualAddressMap) {
            SystemTable->RuntimeServices->SetVirtualAddressMap(MemMapSize, DescSize, DescVer, (void*)MemMapBuf);
        }

        Status = SystemTable->BootServices->ExitBootServices(ImageHandle, MapKey);
    }

    if (EFI_ERROR(Status)) {
        void* waitList[] = { SystemTable->RuntimeServices };
        SystemTable->BootServices->WaitForEvent(1, waitList, 0);
    }

    while(1) __asm__("hlt");
    return 0x800000000000000F;
}
