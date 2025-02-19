typedef unsigned long long uint64_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;

struct EFI_SYSTEM_TABLE;

typedef uint64_t EFI_STATUS;
typedef void* EFI_HANDLE;
typedef void (*EFI_TEXT_OUTPUT)(struct EFI_SYSTEM_TABLE*, uint16_t*);

struct EFI_SYSTEM_TABLE {
    char _pad[60];
    EFI_TEXT_OUTPUT ConOut;
};

EFI_STATUS EfiMain(EFI_HANDLE ImageHandle, struct EFI_SYSTEM_TABLE* SystemTable) {
    uint16_t message[] = u"裸机UEFI模式";
    SystemTable->ConOut(SystemTable, message);
    
    // 脱离UEFI服务的关键步骤
    uint64_t* exit_boot_services = (uint64_t*)0x40;
    *exit_boot_services = 0; // 实际应调用ExitBootServices()
    
    while(1);
    return 0;
}