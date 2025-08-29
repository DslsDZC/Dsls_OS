// boot.c
#include "uefi.h"

// 安全打印函数（确保ConOut有效时输出）
static void SafePrint(EFI_SYSTEM_TABLE* SystemTable, const CHAR16* format, ...) {
    if (SystemTable->ConOut) {
        VA_LIST args;
        VA_START(args, format);
        VPrint(format, args);
        VA_END(args);
    }
}

// 验证内存映射的合法性
EFI_STATUS validate_memory_map(EFI_MEMORY_DESCRIPTOR* memory_map, UINTN memory_map_size, UINTN descriptor_size) {
    UINTN num_descriptors = memory_map_size / descriptor_size;

    // 检查内存映射指针有效性
    if (memory_map == NULL) {
        return EFI_INVALID_PARAMETER;
    }

    for (UINTN i = 0; i < num_descriptors; i++) {
        EFI_MEMORY_DESCRIPTOR* desc = (EFI_MEMORY_DESCRIPTOR*)((UINT8*)memory_map + i * descriptor_size);

        // 检查内存类型是否有效
        if (desc->Type >= EfiMaxMemoryType) {
            return EFI_INVALID_PARAMETER;
        }

        // 检查物理地址和页面数是否合理（防止溢出）
        if (desc->NumberOfPages == 0) {
            return EFI_INVALID_PARAMETER;
        }

        // 检查地址是否对齐
        if ((desc->PhysicalStart & (EFI_PAGE_SIZE - 1)) != 0) {
            return EFI_INVALID_PARAMETER;
        }

        // 检查内存区域是否重叠
        for (UINTN j = i + 1; j < num_descriptors; j++) {
            EFI_MEMORY_DESCRIPTOR* other_desc = (EFI_MEMORY_DESCRIPTOR*)((UINT8*)memory_map + j * descriptor_size);

            UINT64 desc_end = desc->PhysicalStart + desc->NumberOfPages * EFI_PAGE_SIZE;
            UINT64 other_desc_end = other_desc->PhysicalStart + other_desc->NumberOfPages * EFI_PAGE_SIZE;

            // 检查是否有重叠区域
            if (!(desc_end <= other_desc->PhysicalStart || other_desc_end <= desc->PhysicalStart)) {
                return EFI_INVALID_PARAMETER;
            }
        }

        // 检查属性是否为合法组合
        UINT64 valid_attributes = EFI_MEMORY_UC | EFI_MEMORY_WC | EFI_MEMORY_WT |
            EFI_MEMORY_WB | EFI_MEMORY_UCE | EFI_MEMORY_WP |
            EFI_MEMORY_RP | EFI_MEMORY_XP | EFI_MEMORY_RO;

        if (desc->Attribute & ~valid_attributes) {
            return EFI_INVALID_PARAMETER;
        }
    }

    return EFI_SUCCESS;
}

// 计算引导参数的CRC32校验和
UINT32 calculate_boot_params_crc(boot_params_t* boot_params) {
    if (boot_params == NULL) {
        return 0;
    }

    UINT32 crc = 0;
    UINT8* data = (UINT8*)boot_params;
    UINTN size = sizeof(boot_params_t);

    // 临时保存原始CRC并清零（避免校验和包含自身）
    UINT32 original_crc = boot_params->crc32;
    boot_params->crc32 = 0;

    // 使用更健壮的CRC32算法
    for (UINTN i = 0; i < size; i++) {
        crc ^= data[i];
        for (UINTN j = 0; j < 8; j++) {
            if (crc & 1) {
                crc = (crc >> 1) ^ 0xEDB88320;
            }
            else {
                crc >>= 1;
            }
        }
    }

    // 恢复原始CRC
    boot_params->crc32 = original_crc;
    return ~crc; // CRC32标准使用取反
}

// 获取ACPI表
EFI_STATUS get_acpi_tables(EFI_SYSTEM_TABLE* SystemTable, VOID** rsdp) {
    EFI_STATUS status;
    EFI_GUID acpi_guid = EFI_ACPI_20_TABLE_GUID;

    if (SystemTable == NULL || rsdp == NULL) {
        return EFI_INVALID_PARAMETER;
    }

    // 尝试获取ACPI 2.0表
    status = SystemTable->BootServices->GetConfigurationTable(&acpi_guid, rsdp);
    if (EFI_ERROR(status)) {
        // 尝试获取ACPI 1.0表
        EFI_GUID acpi10_guid = EFI_ACPI_10_TABLE_GUID;
        status = SystemTable->BootServices->GetConfigurationTable(&acpi10_guid, rsdp);
    }

    // 尝试获取XSDT (ACPI 5.0+)
    if (EFI_ERROR(status)) {
        EFI_GUID xsdt_guid = EFI_ACPI_TABLE_GUID;
        status = SystemTable->BootServices->GetConfigurationTable(&xsdt_guid, rsdp);
    }

    return status;
}

// 获取内核命令行参数
EFI_STATUS get_kernel_command_line(EFI_SYSTEM_TABLE* SystemTable, CHAR16* cmdline, UINTN size) {
    EFI_STATUS status;
    UINTN data_size = size;
    EFI_GUID global_guid = EFI_GLOBAL_VARIABLE_GUID;

    if (SystemTable == NULL || cmdline == NULL || size == 0) {
        return EFI_INVALID_PARAMETER;
    }

    // 首先尝试获取安全启动变量（如果启用）
    BOOLEAN secure_boot_enabled = FALSE;
    UINT8 secure_boot;
    UINTN secure_boot_size = sizeof(secure_boot);
    EFI_GUID secure_boot_guid = EFI_SECURE_BOOT_MODE_GUID;

    status = SystemTable->RuntimeServices->GetVariable(
        L"SecureBoot",
        &secure_boot_guid,
        NULL,
        &secure_boot_size,
        &secure_boot
    );

    secure_boot_enabled = (!EFI_ERROR(status) && secure_boot);

    status = SystemTable->RuntimeServices->GetVariable(
        L"KernelCommandLine",
        &global_guid,
        NULL,
        &data_size,
        cmdline
    );

    if (status == EFI_NOT_FOUND) {
        // 使用默认空命令行
        StrnCpyS(cmdline, size / sizeof(CHAR16), L"", 1);
        return EFI_SUCCESS;
    }

    // 如果安全启动启用，验证变量属性
    if (secure_boot_enabled && !EFI_ERROR(status)) {
        UINT32 attributes;
        status = SystemTable->RuntimeServices->GetVariable(
            L"KernelCommandLine",
            &global_guid,
            &attributes,
            &data_size,
            cmdline
        );

        // 检查变量是否受保护（NV+RT）
        if (!EFI_ERROR(status) && (attributes & (EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_RUNTIME_ACCESS)) !=
            (EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_RUNTIME_ACCESS)) {
            return EFI_SECURITY_VIOLATION;
        }
    }

    return status;
}

// 设置内核栈（64KB）
EFI_STATUS setup_kernel_stack(EFI_SYSTEM_TABLE* SystemTable, EFI_PHYSICAL_ADDRESS* stack_top) {
    EFI_STATUS status;
    EFI_PHYSICAL_ADDRESS stack_base = 0;
    UINTN stack_pages = 16; // 16页 = 64KB（假设4KB页）

    if (SystemTable == NULL || stack_top == NULL) {
        return EFI_INVALID_PARAMETER;
    }

    status = SystemTable->BootServices->AllocatePages(
        AllocateAnyPages,
        EfiKernelData,
        stack_pages,
        &stack_base
    );

    // 如果分配失败，尝试更小的栈
    if (EFI_ERROR(status)) {
        stack_pages = 8; // 32KB
        status = SystemTable->BootServices->AllocatePages(
            AllocateAnyPages,
            EfiKernelData,
            stack_pages,
            &stack_base
        );
    }

    // 如果仍然失败，尝试最小的栈
    if (EFI_ERROR(status)) {
        stack_pages = 4; // 16KB
        status = SystemTable->BootServices->AllocatePages(
            AllocateAnyPages,
            EfiKernelData,
            stack_pages,
            &stack_base
        );
    }

    if (EFI_ERROR(status)) {
        return status;
    }

    // 栈向下增长，栈顶为分配区域的末尾
    *stack_top = stack_base + stack_pages * EFI_PAGE_SIZE;

    // 填充栈内存以检测溢出
    SetMem((VOID*)stack_base, stack_pages * EFI_PAGE_SIZE, 0xCD);

    return EFI_SUCCESS;
}

// UEFI应用程序入口
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
    EFI_PHYSICAL_ADDRESS kernel_stack = 0;
    BOOLEAN graphics_initialized = FALSE;
    BOOLEAN memory_map_allocated = FALSE;
    BOOLEAN boot_params_allocated = FALSE;

    // 初始化EFI库
    InitializeLib(ImageHandle, SystemTable);

    // 清屏并输出启动信息
    if (SystemTable->ConOut != NULL) {
        SystemTable->ConOut->ClearScreen(SystemTable->ConOut);
        SafePrint(SystemTable, L"Starting UEFI Bootloader...\n");
    }

    // 初始化图形模式
    status = init_graphics(ImageHandle, SystemTable, &gfx_info);
    if (EFI_ERROR(status)) {
        SafePrint(SystemTable, L"Warning: Failed to initialize graphics: %r\n", status);
        SafePrint(SystemTable, L"Falling back to text mode\n");
        gfx_info = (graphics_info_t){ 0 }; // 重置为无效状态
    }
    else {
        SafePrint(SystemTable, L"Graphics initialized: %dx%d\n", gfx_info.width, gfx_info.height);
        graphics_initialized = TRUE;
    }

    // 加载内核
    status = load_kernel(ImageHandle, SystemTable, &kernel_entry);
    if (EFI_ERROR(status)) {
        SafePrint(SystemTable, L"Failed to load kernel: %r\n", status);
        goto cleanup;
    }

    // 验证内核入口点有效性
    if (kernel_entry == NULL) {
        SafePrint(SystemTable, L"Kernel entry point is NULL\n");
        status = EFI_LOAD_ERROR;
        goto cleanup;
    }

    // 分配引导参数内存
    status = SystemTable->BootServices->AllocatePool(
        EfiRuntimeServicesData,
        sizeof(boot_params_t),
        (VOID**)&boot_params
    );
    if (EFI_ERROR(status)) {
        SafePrint(SystemTable, L"Failed to allocate boot params: %r\n", status);
        goto cleanup;
    }
    boot_params_allocated = TRUE;

    // 初始化引导参数
    ZeroMem(boot_params, sizeof(boot_params_t));
    boot_params->graphics = gfx_info;
    boot_params->acpi_rsdp = NULL;
    boot_params->cmdline[0] = L'\0';
    boot_params->crc32 = 0;

    // 获取ACPI表信息
    status = get_acpi_tables(SystemTable, &boot_params->acpi_rsdp);
    if (EFI_ERROR(status)) {
        SafePrint(SystemTable, L"Warning: Failed to get ACPI tables: %r\n", status);
    }
    else {
        SafePrint(SystemTable, L"ACPI tables found at 0x%llx\n", boot_params->acpi_rsdp);
    }

    // 获取内核命令行
    status = get_kernel_command_line(SystemTable, boot_params->cmdline, sizeof(boot_params->cmdline));
    if (EFI_ERROR(status)) {
        SafePrint(SystemTable, L"Warning: Failed to get kernel command line: %r\n", status);
        // 使用空命令行而不是失败
        boot_params->cmdline[0] = L'\0';
    }
    else {
        SafePrint(SystemTable, L"Kernel command line: %s\n", boot_params->cmdline);
    }

    // 获取内存映射大小
    status = SystemTable->BootServices->GetMemoryMap(
        &memory_map_size,
        memory_map,
        &map_key,
        &descriptor_size,
        &descriptor_version
    );
    if (status != EFI_BUFFER_TOO_SMALL) {
        SafePrint(SystemTable, L"Failed to get memory map size: %r\n", status);
        goto cleanup;
    }

    // 分配内存映射缓冲区（额外预留4个描述符空间防止动态增长）
    UINTN alloc_size = memory_map_size + 4 * descriptor_size;
    status = SystemTable->BootServices->AllocatePool(
        EfiRuntimeServicesData,
        alloc_size,
        (VOID**)&memory_map
    );
    if (EFI_ERROR(status)) {
        SafePrint(SystemTable, L"Failed to allocate memory for memory map: %r\n", status);
        goto cleanup;
    }
    memory_map_allocated = TRUE;

    // 获取完整内存映射
    status = SystemTable->BootServices->GetMemoryMap(
        &memory_map_size,
        memory_map,
        &map_key,
        &descriptor_size,
        &descriptor_version
    );
    if (EFI_ERROR(status)) {
        SafePrint(SystemTable, L"Failed to get memory map: %r\n", status);
        goto cleanup;
    }

    // 验证内存映射合法性
    status = validate_memory_map(memory_map, memory_map_size, descriptor_size);
    if (EFI_ERROR(status)) {
        SafePrint(SystemTable, L"Invalid memory map detected: %r\n", status);
        goto cleanup;
    }

    // 填充内存映射到引导参数
    boot_params->memory_map.memory_map = memory_map;
    boot_params->memory_map.memory_map_size = memory_map_size;
    boot_params->memory_map.descriptor_size = descriptor_size;
    boot_params->memory_map.descriptor_version = descriptor_version;
    boot_params->memory_map.map_key = map_key;

    // 设置内核栈
    status = setup_kernel_stack(SystemTable, &kernel_stack);
    if (EFI_ERROR(status)) {
        SafePrint(SystemTable, L"Warning: Failed to setup kernel stack: %r (using bootloader stack)\n", status);
        kernel_stack = 0; // 使用引导加载程序的栈
    }
    else {
        SafePrint(SystemTable, L"Kernel stack initialized at 0x%llx\n", kernel_stack);
    }

    // 计算引导参数CRC校验和
    boot_params->crc32 = calculate_boot_params_crc(boot_params);

    // 退出引导服务
    SafePrint(SystemTable, L"Exiting boot services, jumping to kernel...\n");
    UINTN retry_count = 5; // 增加重试次数
    while (retry_count-- > 0) {
        status = SystemTable->BootServices->ExitBootServices(ImageHandle, map_key);
        if (!EFI_ERROR(status)) break;

        SafePrint(SystemTable, L"ExitBootServices failed: %r, retrying...\n", status);
        SystemTable->BootServices->Stall(200000); // 等待200ms

        // 释放旧内存映射并重新获取
        if (memory_map) {
            SystemTable->BootServices->FreePool(memory_map);
            memory_map = NULL;
            memory_map_allocated = FALSE;
        }

        status = SystemTable->BootServices->GetMemoryMap(&memory_map_size, NULL, &map_key, &descriptor_size, &descriptor_version);
        if (status != EFI_BUFFER_TOO_SMALL) {
            SafePrint(SystemTable, L"Failed to get memory map size during retry: %r\n", status);
            break;
        }

        alloc_size = memory_map_size + 4 * descriptor_size;
        status = SystemTable->BootServices->AllocatePool(EfiRuntimeServicesData, alloc_size, (VOID**)&memory_map);
        if (EFI_ERROR(status)) {
            SafePrint(SystemTable, L"Failed to allocate memory map during retry: %r\n", status);
            break;
        }
        memory_map_allocated = TRUE;

        status = SystemTable->BootServices->GetMemoryMap(&memory_map_size, memory_map, &map_key, &descriptor_size, &descriptor_version);
        if (EFI_ERROR(status)) {
            SafePrint(SystemTable, L"Failed to get memory map during retry: %r\n", status);
            break;
        }

        // 更新引导参数中的内存映射
        boot_params->memory_map.memory_map = memory_map;
        boot_params->memory_map.memory_map_size = memory_map_size;
        boot_params->memory_map.descriptor_size = descriptor_size;
        boot_params->memory_map.descriptor_version = descriptor_version;
        boot_params->memory_map.map_key = map_key;
    }

    if (EFI_ERROR(status)) {
        SafePrint(SystemTable, L"Failed to exit boot services after retries: %r\n", status);
        goto cleanup;
    }

    // 切换到内核栈并跳转到内核（若栈初始化成功）
    typedef void (*kernel_entry_t)(boot_params_t*);
    kernel_entry_t kernel_start = (kernel_entry_t)kernel_entry;

    if (kernel_stack != 0) {
        // 内联汇编切换栈并调用内核（x86_64）
        __asm__ volatile (
            "mov %0, %%rsp\n"    // 设置新栈顶
            "jmp *%1"            // 跳转到内核入口
            : : "r"(kernel_stack), "r"(kernel_start) : "memory"
            );
    }
    else {
        // 使用引导加载程序的栈
        kernel_start(boot_params);
    }

    // 内核不应返回，若返回则进入停机循环
    while (1) {
        __asm__("hlt");
    }

cleanup:
    // 释放所有分配的资源
    if (memory_map_allocated && memory_map) {
        SystemTable->BootServices->FreePool(memory_map);
    }

    if (boot_params_allocated && boot_params) {
        SystemTable->BootServices->FreePool(boot_params);
    }

    return status;
}v 