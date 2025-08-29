// boot.c - 增强版主引导程序
#include "uefi.h"

// 全局日志缓冲区
static CHAR16 g_log_buffer[MAX_LOG_SIZE] = { 0 };
static UINTN g_log_position = 0;

// 安全打印函数
static void SafePrint(EFI_SYSTEM_TABLE* SystemTable, const CHAR16* format, ...) {
    if (SystemTable->ConOut) {
        VA_LIST args;
        VA_START(args, format);
        VPrint(format, args);
        VA_END(args);
    }
}

// 日志记录函数
VOID log_message(EFI_SYSTEM_TABLE* SystemTable, UINTN level, const CHAR16* format, ...) {
    CHAR16 prefix[32] = L"";
    CHAR16 message[512] = { 0 };
    VA_LIST args;

    // 添加日志级别前缀
    switch (level) {
    case LOG_LEVEL_INFO:
        StrCpy(prefix, L"[INFO] ");
        break;
    case LOG_LEVEL_WARNING:
        StrCpy(prefix, L"[WARN] ");
        break;
    case LOG_LEVEL_ERROR:
        StrCpy(prefix, L"[ERROR] ");
        break;
    case LOG_LEVEL_DEBUG:
        StrCpy(prefix, L"[DEBUG] ");
        break;
    default:
        StrCpy(prefix, L"[UNKNOWN] ");
        break;
    }

    // 格式化消息
    VA_START(args, format);
    UnicodeVSPrint(message, sizeof(message), format, args);
    VA_END(args);

    // 输出到控制台
    SafePrint(SystemTable, L"%s%s", prefix, message);

    // 保存到日志缓冲区
    if (g_log_position < sizeof(g_log_buffer) - 1) {
        UINTN prefix_len = StrLen(prefix);
        UINTN message_len = StrLen(message);

        if (g_log_position + prefix_len + message_len < sizeof(g_log_buffer) - 1) {
            StrCpy(g_log_buffer + g_log_position, prefix);
            g_log_position += prefix_len;
            StrCpy(g_log_buffer + g_log_position, message);
            g_log_position += message_len;
        }
        else {
            // 日志缓冲区已满，覆盖最早的日志
            UINTN overflow = (g_log_position + prefix_len + message_len) - (sizeof(g_log_buffer) - 1);
            UINTN new_start = overflow;

            // 移动现有日志内容
            for (UINTN i = new_start; i < g_log_position; i++) {
                g_log_buffer[i - new_start] = g_log_buffer[i];
            }

            g_log_position -= new_start;

            // 添加新日志
            StrCpy(g_log_buffer + g_log_position, prefix);
            g_log_position += prefix_len;
            StrCpy(g_log_buffer + g_log_position, message);
            g_log_position += message_len;
        }
    }
}

// 验证内存映射
EFI_STATUS validate_memory_map(EFI_MEMORY_DESCRIPTOR* memory_map, UINTN memory_map_size, UINTN descriptor_size) {
    UINTN num_descriptors = memory_map_size / descriptor_size;

    for (UINTN i = 0; i < num_descriptors; i++) {
        EFI_MEMORY_DESCRIPTOR* desc = (EFI_MEMORY_DESCRIPTOR*)((UINT8*)memory_map + i * descriptor_size);

        // 检查内存类型
        if (desc->Type >= EfiMaxMemoryType) {
            return EFI_INVALID_PARAMETER;
        }

        // 检查地址和页面数
        if (desc->NumberOfPages == 0 ||
            desc->PhysicalStart + desc->NumberOfPages * EFI_PAGE_SIZE < desc->PhysicalStart) {
            return EFI_INVALID_PARAMETER;
        }

        // 检查属性
        if (desc->Attribute & ~(EFI_MEMORY_UC | EFI_MEMORY_WC | EFI_MEMORY_WT |
            EFI_MEMORY_WB | EFI_MEMORY_UCE | EFI_MEMORY_WP |
            EFI_MEMORY_RP | EFI_MEMORY_XP | EFI_MEMORY_RO)) {
            return EFI_INVALID_PARAMETER;
        }
    }

    return EFI_SUCCESS;
}

// 计算CRC32校验和
UINT32 calculate_boot_params_crc(boot_params_t* boot_params) {
    UINT32 crc = 0;
    UINT8* data = (UINT8*)boot_params;
    UINTN size = sizeof(boot_params_t);

    // 临时保存原始CRC并清零
    UINT32 original_crc = boot_params->crc32;
    boot_params->crc32 = 0;

    // 使用UEFI的CRC32服务
    gBS->CalculateCrc32(data, size, &crc);

    // 恢复原始CRC
    boot_params->crc32 = original_crc;
    return crc;
}

// 获取ACPI表
EFI_STATUS get_acpi_tables(EFI_SYSTEM_TABLE* SystemTable, acpi_info_t* acpi_info) {
    EFI_STATUS status;

    // 初始化ACPI信息结构
    ZeroMem(acpi_info, sizeof(acpi_info_t));

    // 尝试获取ACPI 2.0表
    EFI_GUID acpi20_guid = EFI_ACPI_20_TABLE_GUID;
    status = SystemTable->BootServices->GetConfigurationTable(&acpi20_guid, &acpi_info->rsdp);

    if (EFI_ERROR(status)) {
        // 尝试获取ACPI 1.0表
        EFI_GUID acpi10_guid = EFI_ACPI_10_TABLE_GUID;
        status = SystemTable->BootServices->GetConfigurationTable(&acpi10_guid, &acpi_info->rsdp);
    }

    if (EFI_ERROR(status)) {
        log_message(SystemTable, LOG_LEVEL_WARNING, L"Failed to get ACPI tables: %r\n", status);
        return status;
    }

    // 验证RSDP有效性
    if (acpi_info->rsdp == NULL) {
        log_message(SystemTable, LOG_LEVEL_WARNING, L"ACPI RSDP is NULL\n");
        return EFI_NOT_FOUND;
    }

    log_message(SystemTable, LOG_LEVEL_INFO, L"ACPI RSDP found at 0x%llx\n", acpi_info->rsdp);
    return EFI_SUCCESS;
}

// 获取内核命令行
EFI_STATUS get_kernel_command_line(EFI_SYSTEM_TABLE* SystemTable, CHAR16* cmdline, UINTN size, const CHAR16* default_cmdline) {
    EFI_STATUS status;
    UINTN data_size = size;
    EFI_GUID global_guid = EFI_GLOBAL_VARIABLE_GUID;

    status = SystemTable->RuntimeServices->GetVariable(
        L"KernelCommandLine",
        &global_guid,
        NULL,
        &data_size,
        cmdline);

    if (status == EFI_NOT_FOUND) {
        // 使用默认命令行
        if (default_cmdline != NULL) {
            StrnCpyS(cmdline, size / sizeof(CHAR16), default_cmdline, StrLen(default_cmdline));
        }
        else {
            StrnCpyS(cmdline, size / sizeof(CHAR16), L"", 1);
        }
        return EFI_SUCCESS;
    }

    return status;
}

// 设置内核栈
EFI_STATUS setup_kernel_stack(EFI_SYSTEM_TABLE* SystemTable, EFI_PHYSICAL_ADDRESS* stack_top, UINTN stack_pages) {
    EFI_STATUS status;
    EFI_PHYSICAL_ADDRESS stack_base = 0;

    // 获取栈大小配置
    UINTN configured_stack_pages = stack_pages;
    UINTN data_size = sizeof(configured_stack_pages);
    EFI_GUID global_guid = EFI_GLOBAL_VARIABLE_GUID;

    // 尝试从UEFI变量获取栈大小
    status = SystemTable->RuntimeServices->GetVariable(
        L"KernelStackPages",
        &global_guid,
        NULL,
        &data_size,
        &configured_stack_pages);

    if (EFI_ERROR(status) || configured_stack_pages < 16) {
        // 使用默认值或最小值
        configured_stack_pages = stack_pages;
    }

    status = SystemTable->BootServices->AllocatePages(
        AllocateAnyPages,
        EfiRuntimeServicesData,
        configured_stack_pages,
        &stack_base);

    if (EFI_ERROR(status)) {
        log_message(SystemTable, LOG_LEVEL_WARNING, L"Failed to allocate kernel stack: %r\n", status);
        return status;
    }

    // 栈向下增长，栈顶为分配区域的末尾
    *stack_top = stack_base + configured_stack_pages * EFI_PAGE_SIZE;

    // 保护栈内存
    status = SystemTable->RuntimeServices->SetMemoryAttributes(
        stack_base,
        configured_stack_pages * EFI_PAGE_SIZE,
        EFI_MEMORY_RW | EFI_MEMORY_XP); // 可写，不可执行

    if (EFI_ERROR(status)) {
        log_message(SystemTable, LOG_LEVEL_WARNING, L"Failed to protect kernel stack: %r\n", status);
    }

    log_message(SystemTable, LOG_LEVEL_INFO, L"Kernel stack allocated at 0x%llx (%llu pages)\n",
        *stack_top, configured_stack_pages);
    return EFI_SUCCESS;
}

// 检测CPU核心数
EFI_STATUS detect_cpu_cores(EFI_SYSTEM_TABLE* SystemTable, hardware_info_t* hw_info) {
    UINT32 eax, ebx, ecx, edx;
    UINT32 max_leaf, max_subleaf;
    UINT32 core_count = 0;

    // 获取最大CPUID叶号
    AsmCpuid(0, &max_leaf, &ebx, &ecx, &edx);

    // 检测Intel CPU拓扑
    if (max_leaf >= 0x0B) {
        // 使用CPUID 0x0B (Intel扩展拓扑枚举)
        UINT32 level_type, num_logical;

        for (UINT32 subleaf = 0; ; subleaf++) {
            AsmCpuidEx(0x0B, subleaf, &eax, &ebx, &ecx, &edx);

            level_type = (ecx >> 8) & 0xFF;
            num_logical = ebx & 0xFFFF;

            if (num_logical == 0) break;

            if (level_type == 1) { // 线程级
                core_count = num_logical;
            }
            else if (level_type == 2) { // 核心级
                core_count = num_logical;
                break;
            }
        }
    }
    // 检测AMD CPU拓扑
    else if (max_leaf >= 0x80000008) {
        // 使用CPUID 0x80000008 (AMD核心数)
        AsmCpuid(0x80000008, &eax, &ebx, &ecx, &edx);
        core_count = (ecx & 0xFF) + 1;
    }
    // 使用传统方法检测
    else if (max_leaf >= 4) {
        // 使用CPUID 4 (Intel Deterministic Cache Parameters)
        AsmCpuid(4, &eax, &ebx, &ecx, &edx);
        core_count = ((eax >> 26) & 0x3F) + 1;
    }
    // 无法检测，使用默认值
    else {
        core_count = 1;
        log_message(SystemTable, LOG_LEVEL_WARNING, L"Unable to detect CPU cores, using default: 1\n");
    }

    hw_info->cpu_count = core_count;
    log_message(SystemTable, LOG_LEVEL_INFO, L"Detected %llu CPU cores\n", hw_info->cpu_count);
    return EFI_SUCCESS;
}

// 获取TSC频率
EFI_STATUS get_tsc_frequency(EFI_SYSTEM_TABLE* SystemTable, UINT64* tsc_freq) {
    EFI_STATUS status;
    EFI_GUID tsc_freq_guid = EFI_TSC_FREQUENCY_GUID;
    UINT64 frequency = 0;
    UINTN data_size = sizeof(frequency);

    // 尝试从UEFI变量获取TSC频率
    status = SystemTable->RuntimeServices->GetVariable(
        L"TscFrequency",
        &tsc_freq_guid,
        NULL,
        &data_size,
        &frequency);

    if (EFI_ERROR(status)) {
        // 使用CPUID和时间戳计数器估算TSC频率
        UINT64 start_tsc, end_tsc;
        UINT64 start_time, end_time;

        // 获取当前时间和TSC值
        start_time = GetTimeInNanoSeconds(SystemTable);
        start_tsc = AsmReadTsc();

        // 等待1毫秒
        SystemTable->BootServices->Stall(1000);

        // 获取结束时间和TSC值
        end_time = GetTimeInNanoSeconds(SystemTable);
        end_tsc = AsmReadTsc();

        // 计算TSC频率
        if (end_time > start_time) {
            frequency = (end_tsc - start_tsc) * 1000000000ULL / (end_time - start_time);
        }
        else {
            frequency = 0;
        }

        if (frequency == 0) {
            log_message(SystemTable, LOG_LEVEL_WARNING, L"Failed to calculate TSC frequency\n");
            return EFI_UNSUPPORTED;
        }

        log_message(SystemTable, LOG_LEVEL_INFO, L"Estimated TSC frequency: %llu Hz\n", frequency);
    }
    else {
        log_message(SystemTable, LOG_LEVEL_INFO, L"TSC frequency from UEFI: %llu Hz\n", frequency);
    }

    *tsc_freq = frequency;
    return EFI_SUCCESS;
}

// 检测硬件信息
EFI_STATUS detect_hardware(EFI_SYSTEM_TABLE* SystemTable, hardware_info_t* hw_info) {
    EFI_STATUS status;

    // 初始化硬件信息结构
    ZeroMem(hw_info, sizeof(hardware_info_t));

    // 获取CPU特性
    UINT32 eax, ebx, ecx, edx;
    AsmCpuid(1, &eax, &ebx, &ecx, &edx);
    hw_info->cpu_features = ((UINT64)ecx << 32) | edx;

    // 检测CPU核心数
    status = detect_cpu_cores(SystemTable, hw_info);
    if (EFI_ERROR(status)) {
        log_message(SystemTable, LOG_LEVEL_WARNING, L"CPU core detection failed: %r\n", status);
        hw_info->cpu_count = 1; // 默认值
    }

    // 获取TSC频率
    status = get_tsc_frequency(SystemTable, &hw_info->timer_frequency);
    if (EFI_ERROR(status)) {
        log_message(SystemTable, LOG_LEVEL_WARNING, L"TSC frequency detection failed: %r\n", status);
        hw_info->timer_frequency = 0;
    }

    return EFI_SUCCESS;
}

// 加载initrd
EFI_STATUS load_initrd(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE* SystemTable,
    UINT64* initrd_base, UINT64* initrd_size, const CHAR16* initrd_path) {
    EFI_STATUS status;
    EFI_LOADED_IMAGE_PROTOCOL* loaded_image = NULL;
    EFI_GUID loaded_image_guid = EFI_LOADED_IMAGE_PROTOCOL_GUID;
    EFI_SIMPLE_FILE_SYSTEM_PROTOCOL* volume = NULL;
    EFI_GUID simple_fs_guid = EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID;
    EFI_FILE_PROTOCOL* volume_root = NULL;
    EFI_FILE_PROTOCOL* initrd_file = NULL;
    EFI_FILE_INFO* file_info = NULL;
    UINTN info_size = 0;
    UINTN read_size = 0;
    EFI_PHYSICAL_ADDRESS initrd_address = 0;
    CHAR16* fallback_paths[] = { L"initrd.img", L"\\EFI\\BOOT\\initrd.img", L"\\initrd.img" };
    BOOLEAN file_found = FALSE;

    // 初始化输出参数
    *initrd_base = 0;
    *initrd_size = 0;

    // 如果未指定initrd路径，则跳过加载
    if (initrd_path == NULL || initrd_path[0] == L'\0') {
        log_message(SystemTable, LOG_LEVEL_INFO, L"No initrd specified, continuing without it\n");
        return EFI_SUCCESS;
    }

    // 获取已加载镜像协议
    status = SystemTable->BootServices->HandleProtocol(
        ImageHandle, &loaded_image_guid, (VOID**)&loaded_image);
    if (EFI_ERROR(status)) {
        log_message(SystemTable, LOG_LEVEL_WARNING, L"Failed to get loaded image protocol: %r\n", status);
        return status;
    }

    // 获取文件系统协议
    status = SystemTable->BootServices->HandleProtocol(
        loaded_image->DeviceHandle, &simple_fs_guid, (VOID**)&volume);
    if (EFI_ERROR(status)) {
        log_message(SystemTable, LOG_LEVEL_WARNING, L"Failed to get volume protocol: %r\n", status);
        return status;
    }

    // 打开根目录
    status = volume->OpenVolume(volume, &volume_root);
    if (EFI_ERROR(status)) {
        log_message(SystemTable, LOG_LEVEL_WARNING, L"Failed to open volume: %r\n", status);
        return status;
    }

    // 首先尝试指定的initrd路径
    if (initrd_path != NULL && initrd_path[0] != L'\0') {
        status = volume_root->Open(
            volume_root, &initrd_file, initrd_path,
            EFI_FILE_MODE_READ, EFI_FILE_READ_ONLY);

        if (!EFI_ERROR(status)) {
            file_found = TRUE;
            log_message(SystemTable, LOG_LEVEL_INFO, L"Found initrd at: %s\n", initrd_path);
        }
    }

    // 如果指定路径未找到，尝试备用路径
    if (!file_found) {
        for (UINTN i = 0; i < ARRAY_SIZE(fallback_paths); i++) {
            status = volume_root->Open(
                volume_root, &initrd_file, fallback_paths[i],
                EFI_FILE_MODE_READ, EFI_FILE_READ_ONLY);

            if (!EFI_ERROR(status)) {
                file_found = TRUE;
                log_message(SystemTable, LOG_LEVEL_INFO, L"Found initrd at: %s\n", fallback_paths[i]);
                break;
            }
        }
    }

    if (!file_found) {
        log_message(SystemTable, LOG_LEVEL_INFO, L"No initrd found, continuing without it\n");
        status = EFI_SUCCESS;
        goto cleanup;
    }

    // 获取文件信息
    status = initrd_file->GetInfo(initrd_file, &gEfiFileInfoGuid, &info_size, NULL);
    if (status != EFI_BUFFER_TOO_SMALL) {
        log_message(SystemTable, LOG_LEVEL_WARNING, L"Failed to get initrd info size: %r\n", status);
        goto cleanup;
    }

    status = SystemTable->BootServices->AllocatePool(EfiLoaderData, info_size, (VOID**)&file_info);
    if (EFI_ERROR(status)) {
        log_message(SystemTable, LOG_LEVEL_WARNING, L"Failed to allocate initrd info memory: %r\n", status);
        goto cleanup;
    }

    status = initrd_file->GetInfo(initrd_file, &gEfiFileInfoGuid, &info_size, file_info);
    if (EFI_ERROR(status)) {
        log_message(SystemTable, LOG_LEVEL_WARNING, L"Failed to get initrd info: %r\n", status);
        goto cleanup;
    }

    *initrd_size = file_info->FileSize;
    SystemTable->BootServices->FreePool(file_info);
    file_info = NULL;

    log_message(SystemTable, LOG_LEVEL_INFO, L"Initrd size: %llu bytes\n", *initrd_size);

    // 分配initrd内存
    status = SystemTable->BootServices->AllocatePages(
        AllocateAnyPages, EfiLoaderData,
        EFI_SIZE_TO_PAGES(*initrd_size), &initrd_address);

    if (EFI_ERROR(status)) {
        log_message(SystemTable, LOG_LEVEL_WARNING, L"Failed to allocate initrd memory: %r\n", status);
        goto cleanup;
    }

    *initrd_base = initrd_address;
    log_message(SystemTable, LOG_LEVEL_INFO, L"Initrd allocated at 0x%llx\n", initrd_address);

    // 读取initrd文件
    read_size = *initrd_size;
    status = initrd_file->Read(initrd_file, &read_size, (VOID*)initrd_address);
    if (EFI_ERROR(status) || read_size != *initrd_size) {
        log_message(SystemTable, LOG_LEVEL_WARNING, L"Failed to read initrd: %r\n", status);
        SystemTable->BootServices->FreePages(initrd_address, EFI_SIZE_TO_PAGES(*initrd_size));
        *initrd_base = 0;
        *initrd_size = 0;
        goto cleanup;
    }

    log_message(SystemTable, LOG_LEVEL_INFO, L"Initrd loaded successfully\n");
    status = EFI_SUCCESS;

cleanup:
    if (initrd_file) initrd_file->Close(initrd_file);
    if (volume_root) volume_root->Close(volume_root);
    if (file_info) SystemTable->BootServices->FreePool(file_info);

    return status;
}

// 设置分页
EFI_STATUS setup_paging(EFI_SYSTEM_TABLE* SystemTable) {
    // 在现代UEFI系统中，分页通常已由固件设置
    // 这里可以添加自定义分页设置如果需要
    return EFI_SUCCESS;
}

// 保存启动日志
EFI_STATUS save_boot_log(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE* SystemTable, const CHAR16* log_msg) {
    EFI_STATUS status;
    EFI_LOADED_IMAGE_PROTOCOL* loaded_image = NULL;
    EFI_GUID loaded_image_guid = EFI_LOADED_IMAGE_PROTOCOL_GUID;
    EFI_SIMPLE_FILE_SYSTEM_PROTOCOL* volume = NULL;
    EFI_GUID simple_fs_guid = EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID;
    EFI_FILE_PROTOCOL* volume_root = NULL;
    EFI_FILE_PROTOCOL* log_file = NULL;
    UINTN write_size = 0;
    UINTN retry_count = 3;

    // 获取已加载镜像协议
    status = SystemTable->BootServices->HandleProtocol(
        ImageHandle, &loaded_image_guid, (VOID**)&loaded_image);
    if (EFI_ERROR(status)) {
        return status;
    }

    // 获取文件系统协议
    status = SystemTable->BootServices->HandleProtocol(
        loaded_image->DeviceHandle, &simple_fs_guid, (VOID**)&volume);
    if (EFI_ERROR(status)) {
        return status;
    }

    // 打开根目录
    status = volume->OpenVolume(volume, &volume_root);
    if (EFI_ERROR(status)) {
        return status;
    }

    // 重试机制处理文件系统错误
    while (retry_count-- > 0) {
        // 打开或创建日志文件
        status = volume_root->Open(
            volume_root, &log_file, L"boot.log",
            EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE | EFI_FILE_MODE_CREATE, 0);

        if (EFI_ERROR(status)) {
            SystemTable->BootServices->Stall(100000); // 等待100ms
            continue;
        }

        // 移动到文件末尾
        status = log_file->SetPosition(log_file, 0);
        if (status == EFI_UNSUPPORTED) {
            status = EFI_SUCCESS; // 某些文件系统不支持设置位置
        }

        if (EFI_ERROR(status)) {
            log_file->Close(log_file);
            SystemTable->BootServices->Stall(100000);
            continue;
        }

        // 写入日志
        write_size = StrSize(log_msg);
        status = log_file->Write(log_file, &write_size, (VOID*)log_msg);

        if (EFI_ERROR(status)) {
            log_file->Close(log_file);
            SystemTable->BootServices->Stall(100000);
            continue;
        }

        // 成功，退出循环
        break;
    }

    // 关闭文件
    if (log_file) {
        log_file->Close(log_file);
    }

    if (volume_root) {
        volume_root->Close(volume_root);
    }

    return status;
}

// 检查安全启动状态
EFI_STATUS check_secure_boot_status(EFI_SYSTEM_TABLE* SystemTable) {
    EFI_STATUS status;
    UINT8 secure_boot_enabled = 0;
    UINTN data_size = sizeof(secure_boot_enabled);
    EFI_GUID global_guid = EFI_GLOBAL_VARIABLE_GUID;

    status = SystemTable->RuntimeServices->GetVariable(
        L"SecureBoot",
        &global_guid,
        NULL,
        &data_size,
        &secure_boot_enabled);

    if (status == EFI_NOT_FOUND) {
        // 老固件可能没有SecureBoot变量
        log_message(SystemTable, LOG_LEVEL_WARNING, L"SecureBoot variable not found, assuming disabled\n");
        return EFI_NOT_FOUND;
    }

    if (EFI_ERROR(status)) {
        return status;
    }

    return secure_boot_enabled ? EFI_SUCCESS : EFI_NOT_FOUND;
}

// 启用NX保护
EFI_STATUS enable_nx_protection(EFI_SYSTEM_TABLE* SystemTable) {
    // 在现代UEFI系统中，NX保护通常已由固件启用
    // 这里可以添加自定义NX保护设置如果需要
    return EFI_SUCCESS;
}

// 保留关键内存区域
EFI_STATUS reserve_critical_memory(EFI_SYSTEM_TABLE* SystemTable) {
    EFI_STATUS status;
    EFI_MEMORY_DESCRIPTOR* memory_map = NULL;
    UINTN memory_map_size = 0;
    UINTN map_key = 0;
    UINTN descriptor_size = 0;
    UINT32 descriptor_version = 0;

    // 获取内存映射
    status = get_memory_map_with_retry(SystemTable, &memory_map, &memory_map_size, &map_key, &descriptor_size, &descriptor_version);
    if (EFI_ERROR(status)) {
        log_message(SystemTable, LOG_LEVEL_WARNING, L"Failed to get memory map for reservation: %r\n", status);
        return status;
    }

    // 检查低1MB内存是否已被占用
    BOOLEAN low_mem_occupied = FALSE;
    UINTN num_descriptors = memory_map_size / descriptor_size;

    for (UINTN i = 0; i < num_descriptors; i++) {
        EFI_MEMORY_DESCRIPTOR* desc = (EFI_MEMORY_DESCRIPTOR*)((UINT8*)memory_map + i * descriptor_size);
        UINT64 desc_end = desc->PhysicalStart + desc->NumberOfPages * EFI_PAGE_SIZE;

        if (desc_end <= 0x100000 && desc->Type != EfiConventionalMemory) {
            low_mem_occupied = TRUE;
            break;
        }
    }

    // 如果低1MB内存未被占用，则保留它
    if (!low_mem_occupied) {
        EFI_PHYSICAL_ADDRESS low_mem_start = 0;
        UINTN low_mem_pages = 0x100000 / EFI_PAGE_SIZE; // 1MB

        status = SystemTable->BootServices->AllocatePages(
            AllocateAddress,
            EfiReservedMemoryType,
            low_mem_pages,
            &low_mem_start);

        if (EFI_ERROR(status)) {
            log_message(SystemTable, LOG_LEVEL_WARNING, L"Failed to reserve low memory: %r\n", status);
        }
        else {
            log_message(SystemTable, LOG_LEVEL_INFO, L"Reserved low memory: 0x0-0x%llx\n", low_mem_start + low_mem_pages * EFI_PAGE_SIZE);
        }
    }
    else {
        log_message(SystemTable, LOG_LEVEL_INFO, L"Low memory already occupied, skipping reservation\n");
    }

    SystemTable->BootServices->FreePool(memory_map);
    return EFI_SUCCESS;
}

// 带重试机制获取内存映射
EFI_STATUS get_memory_map_with_retry(EFI_SYSTEM_TABLE* SystemTable, EFI_MEMORY_DESCRIPTOR** memory_map,
    UINTN* memory_map_size, UINTN* map_key, UINTN* descriptor_size,
    UINT32* descriptor_version) {
    EFI_STATUS status;
    UINTN retry_count = 5;
    UINTN alloc_size = 0;

    while (retry_count-- > 0) {
        // 获取内存映射大小
        status = SystemTable->BootServices->GetMemoryMap(
            memory_map_size,
            *memory_map,
            map_key,
            descriptor_size,
            descriptor_version);

        if (status != EFI_BUFFER_TOO_SMALL) {
            log_message(SystemTable, LOG_LEVEL_ERROR, L"Failed to get memory map size: %r\n", status);
            return status;
        }

        // 分配内存映射缓冲区（额外预留空间）
        alloc_size = *memory_map_size + 4 * *descriptor_size; // 额外4个描述符空间

        if (*memory_map != NULL) {
            SystemTable->BootServices->FreePool(*memory_map);
        }

        status = SystemTable->BootServices->AllocatePool(
            EfiRuntimeServicesData,
            alloc_size,
            (VOID**)memory_map);

        if (EFI_ERROR(status)) {
            log_message(SystemTable, LOG_LEVEL_ERROR, L"Failed to allocate memory for memory map: %r\n", status);
            return status;
        }

        // 获取完整内存映射
        status = SystemTable->BootServices->GetMemoryMap(
            memory_map_size,
            *memory_map,
            map_key,
            descriptor_size,
            descriptor_version);

        if (!EFI_ERROR(status)) {
            break; // 成功
        }

        if (status == EFI_BUFFER_TOO_SMALL) {
            // 内存映射在获取过程中发生了变化，重试
            log_message(SystemTable, LOG_LEVEL_WARNING, L"Memory map changed during retrieval, retrying...\n");
            SystemTable->BootServices->Stall(100000); // 等待100ms
            continue;
        }

        log_message(SystemTable, LOG_LEVEL_ERROR, L"Failed to get memory map: %r\n", status);
        SystemTable->BootServices->FreePool(*memory_map);
        *memory_map = NULL;
        return status;
    }

    if (EFI_ERROR(status)) {
        log_message(SystemTable, LOG_LEVEL_ERROR, L"Failed to get memory map after retries: %r\n", status);
        return status;
    }

    return EFI_SUCCESS;
}

// 解析启动菜单
EFI_STATUS parse_boot_menu(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE* SystemTable, boot_menu_t* menu) {
    EFI_STATUS status;
    EFI_LOADED_IMAGE_PROTOCOL* loaded_image = NULL;
    EFI_GUID loaded_image_guid = EFI_LOADED_IMAGE_PROTOCOL_GUID;
    EFI_SIMPLE_FILE_SYSTEM_PROTOCOL* volume = NULL;
    EFI_GUID simple_fs_guid = EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID;
    EFI_FILE_PROTOCOL* volume_root = NULL;
    EFI_FILE_PROTOCOL* menu_file = NULL;
    EFI_FILE_INFO* file_info = NULL;
    UINTN info_size = 0;
    UINTN read_size = 0;
    CHAR8* menu_data = NULL;
    UINTN menu_data_size = 0;

    // 初始化菜单
    ZeroMem(menu, sizeof(boot_menu_t));

    // 获取已加载镜像协议
    status = SystemTable->BootServices->HandleProtocol(
        ImageHandle, &loaded_image_guid, (VOID**)&loaded_image);
    if (EFI_ERROR(status)) {
        log_message(SystemTable, LOG_LEVEL_WARNING, L"Failed to get loaded image protocol: %r\n", status);
        return status;
    }

    // 获取文件系统协议
    status = SystemTable->BootServices->HandleProtocol(
        loaded_image->DeviceHandle, &simple_fs_guid, (VOID**)&volume);
    if (EFI_ERROR(status)) {
        log_message(SystemTable, LOG_LEVEL_WARNING, L"Failed to get volume protocol: %r\n", status);
        return status;
    }

    // 打开根目录
    status = volume->OpenVolume(volume, &volume_root);
    if (EFI_ERROR(status)) {
        log_message(SystemTable, LOG_LEVEL_WARNING, L"Failed to open volume: %r\n", status);
        return status;
    }

    // 打开菜单文件
    status = volume_root->Open(
        volume_root, &menu_file, L"boot.cfg",
        EFI_FILE_MODE_READ, EFI_FILE_READ_ONLY);

    if (EFI_ERROR(status)) {
        log_message(SystemTable, LOG_LEVEL_INFO, L"No boot menu configuration found, using defaults\n");
        volume_root->Close(volume_root);
        return EFI_NOT_FOUND;
    }

    // 获取文件信息
    status = menu_file->GetInfo(menu_file, &gEfiFileInfoGuid, &info_size, NULL);
    if (status != EFI_BUFFER_TOO_SMALL) {
        log_message(SystemTable, LOG_LEVEL_WARNING, L"Failed to get menu file info size: %r\n", status);
        menu_file->Close(menu_file);
        volume_root->Close(volume_root);
        return status;
    }

    status = SystemTable->BootServices->AllocatePool(EfiLoaderData, info_size, (VOID**)&file_info);
    if (EFI_ERROR(status)) {
        log_message(SystemTable, LOG_LEVEL_WARNING, L"Failed to allocate menu file info memory: %r\n", status);
        menu_file->Close(menu_file);
        volume_root->Close(volume_root);
        return status;
    }

    status = menu_file->GetInfo(menu_file, &gEfiFileInfoGuid, &info_size, file_info);
    if (EFI_ERROR(status)) {
        log_message(SystemTable, LOG_LEVEL_WARNING, L"Failed to get menu file info: %r\n", status);
        SystemTable->BootServices->FreePool(file_info);
        menu_file->Close(menu_file);
        volume_root->Close(volume_root);
        return status;
    }

    menu_data_size = file_info->FileSize;
    SystemTable->BootServices->FreePool(file_info);
    file_info = NULL;

    // 分配菜单数据缓冲区
    status = SystemTable->BootServices->AllocatePool(EfiLoaderData, menu_data_size + 1, (VOID**)&menu_data);
    if (EFI_ERROR(status)) {
        log_message(SystemTable, LOG_LEVEL_WARNING, L"Failed to allocate menu data memory: %r\n", status);
        menu_file->Close(menu_file);
        volume_root->Close(volume_root);
        return status;
    }

    // 读取菜单文件
    read_size = menu_data_size;
    status = menu_file->Read(menu_file, &read_size, menu_data);
    if (EFI_ERROR(status) || read_size != menu_data_size) {
        log_message(SystemTable, LOG_LEVEL_WARNING, L"Failed to read menu file: %r\n", status);
        SystemTable->BootServices->FreePool(menu_data);
        menu_file->Close(menu_file);
        volume_root->Close(volume_root);
        return status;
    }

    menu_data[menu_data_size] = '\0'; // 确保以null结尾

    // 简单解析菜单文件（实际实现应更健壮）
    CHAR8* line = menu_data;
    CHAR8* end = menu_data + menu_data_size;

    while (line < end && menu->count < MAX_BOOT_ENTRIES) {
        // 跳过空行和注释
        while (line < end && (*line == ' ' || *line == '\t' || *line == '\r' || *line == '\n' || *line == '#')) {
            if (*line == '#') {
                // 跳过注释行
                while (line < end && *line != '\n') line++;
            }
            line++;
        }

        if (line >= end) break;

        // 解析菜单项
        boot_entry_t* entry = &menu->entries[menu->count];

        // 解析名称
        CHAR8* name_start = line;
        while (line < end && *line != ' ' && *line != '\t' && *line != '\r' && *line != '\n') line++;
        UINTN name_len = line - name_start;

        if (name_len > 0) {
            // 转换ASCII到UTF-16
            for (UINTN i = 0; i < name_len && i < sizeof(entry->name) / sizeof(CHAR16) - 1; i++) {
                entry->name[i] = name_start[i];
            }
            entry->name[name_len] = L'\0';
        }

        // 跳过空白
        while (line < end && (*line == ' ' || *line == '\t')) line++;

        // 解析内核路径
        CHAR8* kernel_start = line;
        while (line < end && *line != ' ' && *line != '\t' && *line != '\r' && *line != '\n') line++;
        UINTN kernel_len = line - kernel_start;

        if (kernel_len > 0) {
            // 转换ASCII到UTF-16
            for (UINTN i = 0; i < kernel_len && i < sizeof(entry->kernel_path) / sizeof(CHAR16) - 1; i++) {
                entry->kernel_path[i] = kernel_start[i];
            }
            entry->kernel_path[kernel_len] = L'\0';
        }

        // 跳过空白
        while (line < end && (*line == ' ' || *line == '\t')) line++;

        // 解析initrd路径
        CHAR8* initrd_start = line;
        while (line < end && *line != ' ' && *line != '\t' && *line != '\r' && *line != '\n') line++;
        UINTN initrd_len = line - initrd_start;

        if (initrd_len > 0) {
            // 转换ASCII到UTF-16
            for (UINTN i = 0; i < initrd_len && i < sizeof(entry->initrd_path) / sizeof(CHAR16) - 1; i++) {
                entry->initrd_path[i] = initrd_start[i];
            }
            entry->initrd_path[initrd_len] = L'\0';
        }

        // 跳过空白
        while (line < end && (*line == ' ' || *line == '\t')) line++;

        // 解析命令行
        CHAR8* cmdline_start = line;
        while (line < end && *line != '\r' && *line != '\n') line++;
        UINTN cmdline_len = line - cmdline_start;

        if (cmdline_len > 0) {
            // 转换ASCII到UTF-16
            for (UINTN i = 0; i < cmdline_len && i < sizeof(entry->cmdline) / sizeof(CHAR16) - 1; i++) {
                entry->cmdline[i] = cmdline_start[i];
            }
            entry->cmdline[cmdline_len] = L'\0';
        }

        // 检查是否为默认条目
        if (StrStr(entry->name, L"(default)") != NULL) {
            entry->default_entry = TRUE;
            menu->default_index = menu->count;
        }

        menu->count++;

        // 跳到下一行
        while (line < end && *line != '\n') line++;
        if (line < end) line++; // 跳过换行符
    }

    // 设置超时时间
    menu->timeout_seconds = 5; // 默认5秒

    SystemTable->BootServices->FreePool(menu_data);
    menu_file->Close(menu_file);
    volume_root->Close(volume_root);

    log_message(SystemTable, LOG_LEVEL_INFO, L"Parsed %d boot menu entries\n", menu->count);
    return EFI_SUCCESS;
}

// 显示启动菜单
EFI_STATUS show_boot_menu(EFI_SYSTEM_TABLE* SystemTable, boot_menu_t* menu, UINTN* selected_index) {
    EFI_STATUS status;
    EFI_INPUT_KEY key;
    UINT64 start_time;
    UINT64 current_time;
    UINT64 timeout_ns = menu->timeout_seconds * 1000000000ULL; // 转换为纳秒

    // 如果没有菜单项或只有一个菜单项，直接返回默认项
    if (menu->count <= 1) {
        *selected_index = 0;
        return EFI_SUCCESS;
    }

    // 清屏
    SystemTable->ConOut->ClearScreen(SystemTable->ConOut);

    // 显示菜单标题
    Print(L"\n\n  UEFI Boot Menu\n\n");
    Print(L"  Version: %s\n\n", BOOTLOADER_VERSION_STRING);

    // 显示菜单项
    for (UINTN i = 0; i < menu->count; i++) {
        if (i == menu->default_index) {
            Print(L"  %d. %s (default)\n", i + 1, menu->entries[i].name);
        }
        else {
            Print(L"  %d. %s\n", i + 1, menu->entries[i].name);
        }
    }

    Print(L"\n  Press a key to select or wait for default (%d seconds)...\n", menu->timeout_seconds);

    // 获取开始时间
    start_time = GetTimeInNanoSeconds(SystemTable);

    // 等待用户输入或超时
    while (TRUE) {
        current_time = GetTimeInNanoSeconds(SystemTable);

        // 检查是否超时
        if (current_time - start_time >= timeout_ns) {
            *selected_index = menu->default_index;
            Print(L"\n  Timeout, selecting default: %s\n", menu->entries[menu->default_index].name);
            SystemTable->BootServices->Stall(2000000); // 等待2秒
            return EFI_SUCCESS;
        }

        // 检查是否有按键
        status = SystemTable->ConIn->ReadKeyStroke(SystemTable->ConIn, &key);
        if (!EFI_ERROR(status)) {
            // 处理数字键选择
            if (key.UnicodeChar >= L'1' && key.UnicodeChar <= L'0' + menu->count) {
                *selected_index = key.UnicodeChar - L'1';
                Print(L"\n  Selected: %s\n", menu->entries[*selected_index].name);
                SystemTable->BootServices->Stall(1000000); // 等待1秒
                return EFI_SUCCESS;
            }

            // 处理回车键选择默认项
            if (key.UnicodeChar == L'\r' || key.UnicodeChar == L'\n') {
                *selected_index = menu->default_index;
                Print(L"\n  Selected default: %s\n", menu->entries[menu->default_index].name);
                SystemTable->BootServices->Stall(1000000); // 等待1秒
                return EFI_SUCCESS;
            }
        }

        // 短暂等待以避免CPU占用过高
        SystemTable->BootServices->Stall(10000); // 等待10ms
    }

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
    UINT64 kernel_base = 0;
    UINT64 kernel_size = 0;
    UINT64 initrd_base = 0;
    UINT64 initrd_size = 0;
    hardware_info_t hw_info = { 0 };
    acpi_info_t acpi_info = { 0 };
    UINT64 boot_time = 0;
    boot_menu_t boot_menu = { 0 };
    UINTN selected_menu_index = 0;
    boot_entry_t* selected_entry = NULL;

    // 初始化EFI库
    InitializeLib(ImageHandle, SystemTable);

    // 清屏并输出启动信息
    if (SystemTable->ConOut != NULL) {
        SystemTable->ConOut->ClearScreen(SystemTable->ConOut);
        log_message(SystemTable, LOG_LEVEL_INFO, L"Starting Production UEFI Bootloader %s...\n", BOOTLOADER_VERSION_STRING);
    }

    // 获取启动时间
    boot_time = GetTimeInNanoSeconds(SystemTable);

    // 解析启动菜单
    status = parse_boot_menu(ImageHandle, SystemTable, &boot_menu);
    if (EFI_ERROR(status) && status != EFI_NOT_FOUND) {
        log_message(SystemTable, LOG_LEVEL_WARNING, L"Boot menu parsing failed: %r\n", status);
    }

    // 显示启动菜单并获取选择
    if (boot_menu.count > 0) {
        status = show_boot_menu(SystemTable, &boot_menu, &selected_menu_index);
        if (EFI_ERROR(status)) {
            log_message(SystemTable, LOG_LEVEL_WARNING, L"Boot menu selection failed: %r\n", status);
            selected_menu_index = 0;
        }
    }

    // 获取选中的启动项
    if (boot_menu.count > 0) {
        selected_entry = &boot_menu.entries[selected_menu_index];
        log_message(SystemTable, LOG_LEVEL_INFO, L"Selected boot entry: %s\n", selected_entry->name);
    }
    else {
        // 创建默认启动项
        selected_entry = &boot_menu.entries[0];
        StrnCpyS(selected_entry->name, sizeof(selected_entry->name) / sizeof(CHAR16), L"Default", 7);
        StrnCpyS(selected_entry->kernel_path, sizeof(selected_entry->kernel_path) / sizeof(CHAR16), L"kernel.elf", 10);
        StrnCpyS(selected_entry->initrd_path, sizeof(selected_entry->initrd_path) / sizeof(CHAR16), L"initrd.img", 10);
        StrnCpyS(selected_entry->cmdline, sizeof(selected_entry->cmdline) / sizeof(CHAR16), L"", 1);
        selected_entry->default_entry = TRUE;
        boot_menu.count = 1;
        boot_menu.default_index = 0;
    }

    // 保留关键内存区域
    status = reserve_critical_memory(SystemTable);
    if (EFI_ERROR(status)) {
        log_message(SystemTable, LOG_LEVEL_WARNING, L"Critical memory reservation failed: %r\n", status);
    }

    // 初始化图形模式
    status = init_graphics(ImageHandle, SystemTable, &gfx_info);
    if (EFI_ERROR(status)) {
        log_message(SystemTable, LOG_LEVEL_WARNING, L"Graphics initialization failed: %r\n", status);
        gfx_info.initialized = FALSE;
    }
    else {
        log_message(SystemTable, LOG_LEVEL_INFO, L"Graphics initialized: %dx%d\n", gfx_info.width, gfx_info.height);
    }

    // 检测硬件信息
    status = detect_hardware(SystemTable, &hw_info);
    if (EFI_ERROR(status)) {
        log_message(SystemTable, LOG_LEVEL_WARNING, L"Hardware detection failed: %r\n", status);
    }

    // 获取ACPI表
    status = get_acpi_tables(SystemTable, &acpi_info);
    if (EFI_ERROR(status)) {
        log_message(SystemTable, LOG_LEVEL_WARNING, L"ACPI tables not available: %r\n", status);
    }

    // 加载initrd
    status = load_initrd(ImageHandle, SystemTable, &initrd_base, &initrd_size, selected_entry->initrd_path);
    if (EFI_ERROR(status)) {
        log_message(SystemTable, LOG_LEVEL_WARNING, L"Initrd loading failed: %r\n", status);
    }

    // 加载内核
    status = load_kernel(ImageHandle, SystemTable, &kernel_entry, &kernel_base, &kernel_size, selected_entry->kernel_path);
    if (EFI_ERROR(status)) {
        // 尝试备用内核
        log_message(SystemTable, LOG_LEVEL_ERROR, L"Kernel loading failed: %r, trying fallback...\n", status);

        // 尝试备用内核路径
        status = load_kernel(ImageHandle, SystemTable, &kernel_entry, &kernel_base, &kernel_size, L"kernel.elf.backup");
        if (EFI_ERROR(status)) {
            log_message(SystemTable, LOG_LEVEL_ERROR, L"Fallback kernel loading failed: %r\n", status);
            goto cleanup;
        }
    }

    // 验证内核入口点
    if (kernel_entry == NULL) {
        log_message(SystemTable, LOG_LEVEL_ERROR, L"Kernel entry point is NULL\n");
        status = EFI_LOAD_ERROR;
        goto cleanup;
    }

    // 分配引导参数内存
    status = SystemTable->BootServices->AllocatePool(
        EfiRuntimeServicesData,
        sizeof(boot_params_t),
        (VOID**)&boot_params);

    if (EFI_ERROR(status)) {
        log_message(SystemTable, LOG_LEVEL_ERROR, L"Failed to allocate boot params: %r\n", status);
        goto cleanup;
    }

    // 初始化引导参数
    ZeroMem(boot_params, sizeof(boot_params_t));
    boot_params->graphics = gfx_info;
    boot_params->acpi = acpi_info;
    boot_params->hardware = hw_info;
    boot_params->kernel_base = kernel_base;
    boot_params->kernel_size = kernel_size;
    boot_params->initrd_base = initrd_base;
    boot_params->initrd_size = initrd_size;
    boot_params->boot_time = boot_time;

    // 获取TSC频率
    status = get_tsc_frequency(SystemTable, &boot_params->tsc_frequency);
    if (EFI_ERROR(status)) {
        log_message(SystemTable, LOG_LEVEL_WARNING, L"TSC frequency detection failed: %r\n", status);
        boot_params->tsc_frequency = 0;
    }

    // 获取内核命令行
    status = get_kernel_command_line(SystemTable, boot_params->cmdline, sizeof(boot_params->cmdline), selected_entry->cmdline);
    if (EFI_ERROR(status)) {
        log_message(SystemTable, LOG_LEVEL_WARNING, L"Failed to get kernel command line: %r\n", status);
        StrnCpyS(boot_params->cmdline, sizeof(boot_params->cmdline) / sizeof(CHAR16), selected_entry->cmdline, StrLen(selected_entry->cmdline));
    }
    else {
        log_message(SystemTable, LOG_LEVEL_INFO, L"Kernel command line: %s\n", boot_params->cmdline);
    }

    // 获取内存映射
    status = get_memory_map_with_retry(SystemTable, &memory_map, &memory_map_size, &map_key, &descriptor_size, &descriptor_version);
    if (EFI_ERROR(status)) {
        log_message(SystemTable, LOG_LEVEL_ERROR, L"Failed to get memory map: %r\n", status);
        goto cleanup;
    }

    // 验证内存映射
    status = validate_memory_map(memory_map, memory_map_size, descriptor_size);
    if (EFI_ERROR(status)) {
        log_message(SystemTable, LOG_LEVEL_ERROR, L"Invalid memory map detected: %r\n", status);
        goto cleanup;
    }

    // 填充内存映射到引导参数
    boot_params->memory_map.memory_map = memory_map;
    boot_params->memory_map.memory_map_size = memory_map_size;
    boot_params->memory_map.descriptor_size = descriptor_size;
    boot_params->memory_map.descriptor_version = descriptor_version;
    boot_params->memory_map.map_key = map_key;

    // 设置内核栈
    status = setup_kernel_stack(SystemTable, &kernel_stack, 16); // 默认16页(64KB)
    if (EFI_ERROR(status)) {
        log_message(SystemTable, LOG_LEVEL_WARNING, L"Failed to setup kernel stack: %r\n", status);
        kernel_stack = 0;
    }

    // 设置分页
    status = setup_paging(SystemTable);
    if (EFI_ERROR(status)) {
        log_message(SystemTable, LOG_LEVEL_WARNING, L"Failed to setup paging: %r\n", status);
    }

    // 计算引导参数CRC校验和
    boot_params->crc32 = calculate_boot_params_crc(boot_params);

    // 保存启动日志
    status = save_boot_log(ImageHandle, SystemTable, g_log_buffer);
    if (EFI_ERROR(status)) {
        log_message(SystemTable, LOG_LEVEL_WARNING, L"Failed to save boot log: %r\n", status);
    }

    // 退出引导服务
    log_message(SystemTable, LOG_LEVEL_INFO, L"Exiting boot services, jumping to kernel...\n");

    UINTN retry_count = 3;
    while (retry_count-- > 0) {
        status = SystemTable->BootServices->ExitBootServices(ImageHandle, map_key);
        if (!EFI_ERROR(status)) break;

        log_message(SystemTable, LOG_LEVEL_WARNING, L"ExitBootServices failed: %r, retrying...\n", status);
        SystemTable->BootServices->Stall(100000); // 等待100ms

        // 重新获取内存映射
        if (memory_map) SystemTable->BootServices->FreePool(memory_map);
        memory_map = NULL;

        status = get_memory_map_with_retry(SystemTable, &memory_map, &memory_map_size, &map_key, &descriptor_size, &descriptor_version);
        if (EFI_ERROR(status)) {
            log_message(SystemTable, LOG_LEVEL_ERROR, L"Failed to get memory map during retry: %r\n", status);
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
        log_message(SystemTable, LOG_LEVEL_ERROR, L"Failed to exit boot services after retries: %r\n", status);
        goto cleanup;
    }

    // 切换到内核栈并跳转到内核
    typedef void (*kernel_entry_t)(boot_params_t*);
    kernel_entry_t kernel_start = (kernel_entry_t)kernel_entry;

    if (kernel_stack != 0) {
        // 内联汇编切换栈并调用内核（x86_64）
        __asm__ volatile (
            "mov %0, %%rsp\n"    // 设置新栈顶
            "jmp *%1"            // 跳转到内核入口
            : : "r"(kernel_stack), "r"(kernel_start), "D"(boot_params) : "memory"
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
    // 清理资源
    if (memory_map) SystemTable->BootServices->FreePool(memory_map);
    if (boot_params) SystemTable->BootServices->FreePool(boot_params);

    return status;
}
