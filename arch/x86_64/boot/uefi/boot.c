#include "uefi.h"

// 安全打印函数，在ConOut有效时才打印
static void SafePrint(EFI_SYSTEM_TABLE* SystemTable, const CHAR16* format, ...) {
    if (SystemTable->ConOut) {
        VA_LIST args;
        VA_START(args, format);
        VPrint(format, args);
        VA_END(args);
    }
}

// UEFI应用程序入口点
EFI_STATUS EFIAPI uefi_main(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE* SystemTable) {
    EFI_STATUS status = EFI_SUCCESS;
    VOID* kernel_entry = NULL;
    graphics_info_t gfx_info = { 0 };
    boot_params_t* boot_params = NULL;
    EFI_MEMORY_DESCRIPTOR* memory_map = NULL;
    UINTN memory_map_size = 0;
    UINTN map_key = 0;
    UINTN descriptor_size = 0;
    UINT32 descriptor_version = 0;

    // 初始化EFI库
    InitializeLib(ImageHandle, SystemTable);

    // 检查控制台输出接口有效性
    if (SystemTable->ConOut != NULL) {
        SystemTable->ConOut->ClearScreen(SystemTable->ConOut);
        SafePrint(SystemTable, L"Starting UEFI Bootloader...\n");
    }

    // 初始化图形模式
    status = init_graphics(ImageHandle, SystemTable, &gfx_info);
    if (EFI_ERROR(status)) {
        SafePrint(SystemTable, L"Failed to initialize graphics: %r\n", status);
        // 清零图形信息，避免内核使用无效值
        gfx_info = (graphics_info_t){ 0 };
    }
    else {
        SafePrint(SystemTable, L"Graphics initialized: %dx%d\n", gfx_info.width, gfx_info.height);
    }

    // 加载内核
    status = load_kernel(ImageHandle, SystemTable, &kernel_entry);
    if (EFI_ERROR(status)) {
        SafePrint(SystemTable, L"Failed to load kernel: %r\n", status);
        return status;
    }

    // 显式检查内核入口点有效性
    if (kernel_entry == NULL) {
        SafePrint(SystemTable, L"Kernel entry point is NULL\n");
        return EFI_LOAD_ERROR;
    }

    // 分配运行时持久内存存储启动参数
    status = SystemTable->BootServices->AllocatePool(
        EfiRuntimeServicesData,
        sizeof(boot_params_t),
        (VOID**)&boot_params
    );

    if (EFI_ERROR(status)) {
        SafePrint(SystemTable, L"Failed to allocate boot params: %r\n", status);
        return status;
    }

    // 初始化启动参数
    boot_params->graphics = gfx_info;

    // 退出启动服务，不再使用UEFI服务

    // 获取当前内存映射大小
    status = SystemTable->BootServices->GetMemoryMap(
        &memory_map_size,
        memory_map,
        &map_key,
        &descriptor_size,
        &descriptor_version
    );

    if (status != EFI_BUFFER_TOO_SMALL) {
        SafePrint(SystemTable, L"Failed to get memory map size: %r\n", status);
        SystemTable->BootServices->FreePool(boot_params);
        return status;
    }

    // 分配额外2个描述符大小的空间，防止内存映射在获取过程中动态增长
    UINTN alloc_size = memory_map_size + 2 * descriptor_size;
    status = SystemTable->BootServices->AllocatePool(
        EfiRuntimeServicesData,  // 使用运行时数据，确保退出后仍有效
        alloc_size,
        (VOID**)&memory_map
    );

    if (EFI_ERROR(status)) {
        SafePrint(SystemTable, L"Failed to allocate memory for memory map: %r\n", status);
        SystemTable->BootServices->FreePool(boot_params);
        return status;
    }

    // 获取完整的内存映射
    status = SystemTable->BootServices->GetMemoryMap(
        &memory_map_size,
        memory_map,
        &map_key,
        &descriptor_size,
        &descriptor_version
    );

    if (EFI_ERROR(status)) {
        SafePrint(SystemTable, L"Failed to get memory map: %r\n", status);
        SystemTable->BootServices->FreePool(memory_map);
        SystemTable->BootServices->FreePool(boot_params);
        return status;
    }

    // 填充内存映射信息到启动参数
    boot_params->memory_map.memory_map = memory_map;
    boot_params->memory_map.memory_map_size = memory_map_size;
    boot_params->memory_map.descriptor_size = descriptor_size;
    boot_params->memory_map.descriptor_version = descriptor_version;
    boot_params->memory_map.map_key = map_key;

    // 在退出启动服务前打印最后的消息
    SafePrint(SystemTable, L"Exiting boot services, jumping to kernel...\n");

    // 添加ExitBootServices重试机制
    UINTN retry_count = 3;
    while (retry_count-- > 0) {
        status = SystemTable->BootServices->ExitBootServices(ImageHandle, map_key);
        if (!EFI_ERROR(status)) {
            break;
        }

        SafePrint(SystemTable, L"ExitBootServices failed: %r, retrying...\n", status);

        // 短暂延迟，减少内存映射变化
        SystemTable->BootServices->Stall(100000); // 100ms

        // 释放旧内存映射缓冲区
        if (memory_map != NULL) {
            SystemTable->BootServices->FreePool(memory_map);
            memory_map = NULL;
        }

        // 重新获取所需大小
        status = SystemTable->BootServices->GetMemoryMap(
            &memory_map_size,
            NULL,
            &map_key,
            &descriptor_size,
            &descriptor_version
        );

        if (status != EFI_BUFFER_TOO_SMALL) {
            SafePrint(SystemTable, L"Failed to get memory map size during retry: %r\n", status);
            break;
        }

        // 重新分配内存映射缓冲区（保留余量）
        alloc_size = memory_map_size + 2 * descriptor_size;
        status = SystemTable->BootServices->AllocatePool(
            EfiRuntimeServicesData,
            alloc_size,
            (VOID**)&memory_map
        );

        if (EFI_ERROR(status)) {
            SafePrint(SystemTable, L"Failed to allocate memory map during retry: %r\n", status);
            break;
        }

        // 重新获取完整的内存映射
        status = SystemTable->BootServices->GetMemoryMap(
            &memory_map_size,
            memory_map,
            &map_key,
            &descriptor_size,
            &descriptor_version
        );

        if (EFI_ERROR(status)) {
            SafePrint(SystemTable, L"Failed to get memory map during retry: %r\n", status);
            break;
        }

        // 更新内存映射指针
        boot_params->memory_map.memory_map = memory_map;
        boot_params->memory_map.memory_map_size = memory_map_size;
        boot_params->memory_map.descriptor_size = descriptor_size;
        boot_params->memory_map.descriptor_version = descriptor_version;
        boot_params->memory_map.map_key = map_key;
    }

    if (EFI_ERROR(status)) {
        SafePrint(SystemTable, L"Failed to exit boot services after retries: %r\n", status);
        SystemTable->BootServices->FreePool(memory_map);
        SystemTable->BootServices->FreePool(boot_params);
        return status;
    }

    // 注意：从这里开始，不能再使用任何UEFI Boot Services函数

    // 定义内核入口点函数类型
    typedef void (*kernel_entry_t)(boot_params_t*);
    kernel_entry_t kernel_start = (kernel_entry_t)kernel_entry;

    // 调用内核入口点，传递启动参数
    kernel_start(boot_params);

    // 内核不应返回，如果返回则循环停机
    while (1) {
        __asm__("hlt");
    }

    return EFI_LOAD_ERROR;
}