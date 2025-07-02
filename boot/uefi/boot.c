#include <uefi.h>

EFI_STATUS EFIAPI efi_main(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE *SystemTable) {
    EFI_STATUS status = EFI_SUCCESS;
    
    // 初始化标准库
    InitializeLib(ImageHandle, SystemTable);
    
    // 第1阶段：系统初始化
    Print(L"\nDSLs_OS UEFI Bootloader\n");
    Print(L"Version 1.0\n");
    Print(L"Initializing system...\n");
    
    // 初始化图形系统
    status = InitializeGraphics();
    if (EFI_ERROR(status)) {
        Print(L"Warning: Graphics initialization failed (Status: %r)\n", status);
        Print(L"Continuing in text mode...\n");
    }
    
    // 第2阶段：内核加载
    Print(L"Loading kernel image...\n");
    status = LoadKernelImage(ImageHandle);
    if (EFI_ERROR(status)) {
        BootFailure(status, L"Kernel loading failed");
    }
    
    Print(L"Kernel loaded at 0x%016llx, Size: %d KB\n", 
          KernelEntryPoint, KernelSize / 1024);
    
    // 第3阶段：系统准备
    Print(L"Preparing system for kernel handoff...\n");
    
    EFI_MEMORY_DESCRIPTOR* memory_map = NULL;
    UINTN map_size = 0;
    UINTN descriptor_size = 0;
    UINTN map_key = 0;
    UINTN descriptor_version = 0;
    
    // 获取系统内存映射
    status = GetSystemMemoryMap(&memory_map, &map_size, &descriptor_size, &map_key);
    if (EFI_ERROR(status)) {
        BootFailure(status, L"Failed to retrieve memory map");
    }
    
    // 第4阶段：退出UEFI环境
    Print(L"Exiting UEFI boot services...\n");
    status = ExitBootServicesSafely(ImageHandle, memory_map, map_size, descriptor_size, map_key);
    if (EFI_ERROR(status)) {
        BootFailure(status, L"Failed to exit boot services");
    }
    
    // 第5阶段：启动内核
    Print(L"Starting kernel at 0x%016llx...\n", KernelEntryPoint);
    
    // 定义内核入口函数类型
    typedef void (__attribute__((ms_abi)) *KernelEntryPoint_t)(
        EFI_MEMORY_DESCRIPTOR* memory_map, 
        UINTN map_size, 
        UINTN descriptor_size
    );
    
    // 调用内核
    KernelEntryPoint_t kernel_entry = (KernelEntryPoint_t)KernelEntryPoint;
    kernel_entry(memory_map, map_size, descriptor_size);
    
    // 内核不应返回 - 安全处理
    Print(L"KERNEL RETURNED - SYSTEM HALTED\n");
    while (1) {
        __asm__ __volatile__("cli; hlt");
    }
    
    // 永远不会到达这里
    return EFI_SUCCESS;
}

EFI_STATUS LoadKernel(EFI_HANDLE ImageHandle) {
    // 简化实现 - 实际中需要从文件系统加载内核
    KernelEntryPoint = 0x100000;  // 1MB 地址
    KernelSize = 512 * 1024;     // 512KB
    
    // 模拟内核加载
    EFI_PHYSICAL_ADDRESS kernel_addr = KernelEntryPoint;
    EFI_STATUS status = gBS->AllocatePages(
        AllocateAddress,
        EfiLoaderData,
        (KernelSize + EFI_PAGE_SIZE - 1) / EFI_PAGE_SIZE,
        &kernel_addr
    );
    
    if (EFI_ERROR(status)) {
        Print(L"Failed to allocate kernel memory: %r\n", status);
        return status;
    }
    
    // 实际中这里需要从磁盘读取内核到kernel_addr
    // ...
    
    return EFI_SUCCESS;
}

/**
 * 初始化图形输出系统
 */
static EFI_STATUS InitializeGraphics(VOID) {
    EFI_STATUS status = InitGraphics();
    if (!EFI_ERROR(status)) {
        // 设置背景色
        ClearScreen(0x1A2B3C);
        
        // 在图形模式下显示启动信息
        DrawString(100, 50, L"DSLs_OS Bootloader", 0xFFFFFF, 0x1A2B3C);
        DrawString(100, 70, L"Initializing system...", 0xFFFFFF, 0x1A2B3C);
    }
    return status;
}

/**
 * 加载内核映像
 */
static EFI_STATUS LoadKernelImage(EFI_HANDLE ImageHandle) {
    EFI_STATUS status = LoadKernel(ImageHandle);
    if (EFI_ERROR(status)) {
        return status;
    }
    
    // 验证内核加载地址
    if (KernelEntryPoint == 0 || KernelSize == 0) {
        return EFI_LOAD_ERROR;
    }
    
    // 检查内核是否在可用内存中
    if (KernelEntryPoint < 0x100000 || KernelEntryPoint > 0xFFFFFFFFFFFF) {
        return EFI_INVALID_PARAMETER;
    }
    
    return EFI_SUCCESS;
}

/**
 * 获取系统内存映射
 */
static EFI_STATUS GetSystemMemoryMap(EFI_MEMORY_DESCRIPTOR** Map, UINTN* MapSize, 
                                    UINTN* DescriptorSize, UINTN* MapKey) {
    EFI_STATUS status;
    UINT32 descriptor_version;
    
    // 第一次调用获取所需大小
    *MapSize = 0;
    status = gBS->GetMemoryMap(
        MapSize,
        *Map,
        MapKey,
        DescriptorSize,
        &descriptor_version
    );
    
    if (status != EFI_BUFFER_TOO_SMALL) {
        return status;
    }
    
    // 分配额外空间防止内存映射变化
    UINTN buffer_size = *MapSize + 2 * (*DescriptorSize);
    
    // 分配内存池
    status = gBS->AllocatePool(
        EfiLoaderData,
        buffer_size,
        (VOID**)Map
    );
    
    if (EFI_ERROR(status)) {
        return status;
    }
    
    // 获取实际内存映射
    status = gBS->GetMemoryMap(
        MapSize,
        *Map,
        MapKey,
        DescriptorSize,
        &descriptor_version
    );
    
    if (EFI_ERROR(status)) {
        gBS->FreePool(*Map);
        *Map = NULL;
    }
    
    return status;
}

/**
 * 安全退出引导服务（带重试机制）
 */
static EFI_STATUS ExitBootServicesSafely(EFI_HANDLE ImageHandle, EFI_MEMORY_DESCRIPTOR* Map, 
                                         UINTN MapSize, UINTN DescriptorSize, UINTN MapKey) {
    EFI_STATUS status;
    
    // 最多重试5次
    for (int attempt = 0; attempt < 5; attempt++) {
        status = gBS->ExitBootServices(ImageHandle, MapKey);
        
        if (!EFI_ERROR(status)) {
            return EFI_SUCCESS;
        }
        
        // 内存映射可能已变化 - 重新获取
        Print(L"Retrying ExitBootServices (attempt %d)...\n", attempt + 1);
        
        // 释放旧内存映射
        gBS->FreePool(Map);
        Map = NULL;
        
        // 获取新内存映射
        status = GetSystemMemoryMap(&Map, &MapSize, &DescriptorSize, &MapKey);
        if (EFI_ERROR(status)) {
            return status;
        }
    }
    
    // 所有尝试都失败
    if (Map) {
        gBS->FreePool(Map);
    }
    return EFI_ABORTED;
}

/**
 * 处理启动失败情况
 */
static VOID BootFailure(EFI_STATUS Status, CHAR16* Message) {
    Print(L"\nBOOT FAILURE\n");
    Print(L"Error: %s\n", Message);
    Print(L"Status: %r\n\n", Status);
    
    // 等待用户按键
    Print(L"Press any key to reboot...");
    EFI_INPUT_KEY key;
    gST->ConIn->Reset(gST->ConIn, FALSE);
    while (gST->ConIn->ReadKeyStroke(gST->ConIn, &key) == EFI_NOT_READY);
    
    // 重启系统
    gRT->ResetSystem(EfiResetCold, EFI_SUCCESS, 0, NULL);
    
    // 永远不会到达这里
    for(;;);
}
