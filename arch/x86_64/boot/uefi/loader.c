// loader.c - 增强版内核加载器
#include "uefi.h"

// 使用UEFI安全协议验证内核签名
EFI_STATUS verify_kernel_signature(EFI_SYSTEM_TABLE* SystemTable, VOID* kernel_data, UINTN kernel_size, const CHAR16* kernel_path) {
    EFI_STATUS status;
    EFI_GUID security_guid = EFI_IMAGE_SECURITY_DATABASE_GUID;
    EFI_IMAGE_SECURITY_DATABASE_PROTOCOL* security_proto = NULL;

    // 检查安全启动状态
    status = check_secure_boot_status(SystemTable);
    if (EFI_ERROR(status)) {
        log_message(SystemTable, LOG_LEVEL_WARNING, L"Secure Boot is not enabled, using hash verification\n");

        // 使用SHA-256哈希验证
        UINT8 calculated_hash[KERNEL_HASH_SIZE] = { 0 };
        UINT8 expected_hash[KERNEL_HASH_SIZE] = { 0 };

        // 计算实际哈希
        status = calculate_sha256_hash(SystemTable, kernel_data, kernel_size, calculated_hash);
        if (EFI_ERROR(status)) {
            log_message(SystemTable, LOG_LEVEL_ERROR, L"Failed to calculate kernel hash: %r\n", status);
            return status;
        }

        // 从安全存储获取预期哈希
        status = get_expected_kernel_hash(SystemTable, expected_hash, KERNEL_HASH_SIZE, kernel_path);
        if (EFI_ERROR(status)) {
            log_message(SystemTable, LOG_LEVEL_ERROR, L"Failed to get expected kernel hash: %r\n", status);
            return status;
        }

        // 比较哈希值
        if (CompareMem(expected_hash, calculated_hash, KERNEL_HASH_SIZE) != 0) {
            log_message(SystemTable, LOG_LEVEL_ERROR, L"Kernel hash verification failed\n");
            return EFI_SECURITY_VIOLATION;
        }

        log_message(SystemTable, LOG_LEVEL_INFO, L"Kernel hash verification successful\n");
        return EFI_SUCCESS;
    }

    // 安全启动已启用，使用安全协议验证
    status = SystemTable->BootServices->LocateProtocol(&security_guid, NULL, (VOID**)&security_proto);
    if (EFI_ERROR(status)) {
        log_message(SystemTable, LOG_LEVEL_ERROR, L"Failed to locate security protocol: %r\n", status);
        return status;
    }

    status = security_proto->Verify(kernel_data, kernel_size);
    if (EFI_ERROR(status)) {
        log_message(SystemTable, LOG_LEVEL_ERROR, L"Kernel signature verification failed: %r\n", status);
        return status;
    }

    log_message(SystemTable, LOG_LEVEL_INFO, L"Kernel signature verified successfully\n");
    return EFI_SUCCESS;
}

// 设置内核内存保护属性
EFI_STATUS set_kernel_memory_protection(EFI_SYSTEM_TABLE* SystemTable, Elf64_Ehdr* elf_header, EFI_PHYSICAL_ADDRESS kernel_address) {
    EFI_STATUS status;
    Elf64_Phdr* phdr = (Elf64_Phdr*)(kernel_address + elf_header->e_phoff);

    // 启用NX保护
    status = enable_nx_protection(SystemTable);
    if (EFI_ERROR(status)) {
        log_message(SystemTable, LOG_LEVEL_WARNING, L"Failed to enable NX protection: %r\n", status);
    }

    for (UINTN i = 0; i < elf_header->e_phnum; i++) {
        if (phdr[i].p_type != PT_LOAD) continue;

        UINT64 seg_start = phdr[i].p_vaddr;
        UINT64 seg_end = seg_start + phdr[i].p_memsz;

        // 对齐到页面边界
        UINT64 page_start = seg_start & ~(EFI_PAGE_SIZE - 1);
        UINT64 page_end = (seg_end + EFI_PAGE_SIZE - 1) & ~(EFI_PAGE_SIZE - 1);
        UINTN page_count = EFI_SIZE_TO_PAGES(page_end - page_start);

        // 根据ELF段标志设置内存属性
        UINT64 attributes = EFI_MEMORY_RO; // 默认只读

        if (phdr[i].p_flags & PF_W) {
            attributes = EFI_MEMORY_RW; // 可写
        }

        if (!(phdr[i].p_flags & PF_X)) {
            attributes |= EFI_MEMORY_XP; // 不可执行
        }

        status = SystemTable->RuntimeServices->SetMemoryAttributes(
            page_start,
            page_count * EFI_PAGE_SIZE,
            attributes
        );

        if (EFI_ERROR(status)) {
            log_message(SystemTable, LOG_LEVEL_ERROR,
                L"Failed to set memory attributes for segment %d: %r\n", i, status);
            return status;
        }
    }

    return EFI_SUCCESS;
}

// 加载并验证内核
EFI_STATUS load_kernel(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE* SystemTable,
    VOID** kernel_entry_point, UINT64* kernel_base, UINT64* kernel_size, const CHAR16* kernel_path) {
    EFI_STATUS status = EFI_SUCCESS;
    EFI_LOADED_IMAGE_PROTOCOL* loaded_image = NULL;
    EFI_GUID loaded_image_guid = EFI_LOADED_IMAGE_PROTOCOL_GUID;
    EFI_SIMPLE_FILE_SYSTEM_PROTOCOL* volume = NULL;
    EFI_GUID simple_fs_guid = EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID;
    EFI_FILE_PROTOCOL* volume_root = NULL;
    EFI_FILE_PROTOCOL* kernel_file = NULL;
    EFI_FILE_INFO* file_info = NULL;
    UINTN info_size = 0;
    UINTN read_size = 0;
    EFI_PHYSICAL_ADDRESS kernel_address = 0;
    UINT64 kernel_end = 0;
    CHAR16* fallback_paths[] = { L"kernel.elf", L"\\EFI\\BOOT\\kernel.elf", L"\\kernel.elf" };
    BOOLEAN file_found = FALSE;
    CHAR16 actual_kernel_path[256] = { 0 };

    // 初始化输出参数
    *kernel_entry_point = NULL;
    *kernel_base = 0;
    *kernel_size = 0;

    // 获取已加载镜像协议
    status = SystemTable->BootServices->HandleProtocol(
        ImageHandle, &loaded_image_guid, (VOID**)&loaded_image);
    if (EFI_ERROR(status)) {
        log_message(SystemTable, LOG_LEVEL_ERROR, L"Failed to get loaded image protocol: %r\n", status);
        goto cleanup;
    }

    // 获取文件系统协议
    status = SystemTable->BootServices->HandleProtocol(
        loaded_image->DeviceHandle, &simple_fs_guid, (VOID**)&volume);
    if (EFI_ERROR(status)) {
        log_message(SystemTable, LOG_LEVEL_ERROR, L"Failed to get volume protocol: %r\n", status);
        goto cleanup;
    }

    // 打开根目录
    status = volume->OpenVolume(volume, &volume_root);
    if (EFI_ERROR(status)) {
        log_message(SystemTable, LOG_LEVEL_ERROR, L"Failed to open volume: %r\n", status);
        goto cleanup;
    }

    // 首先尝试指定的内核路径
    if (kernel_path != NULL && kernel_path[0] != L'\0') {
        status = volume_root->Open(
            volume_root, &kernel_file, kernel_path,
            EFI_FILE_MODE_READ, EFI_FILE_READ_ONLY);

        if (!EFI_ERROR(status)) {
            file_found = TRUE;
            StrnCpyS(actual_kernel_path, sizeof(actual_kernel_path) / sizeof(CHAR16), kernel_path, StrLen(kernel_path));
            log_message(SystemTable, LOG_LEVEL_INFO, L"Found kernel at: %s\n", kernel_path);
        }
    }

    // 如果指定路径未找到，尝试备用路径
    if (!file_found) {
        for (UINTN i = 0; i < ARRAY_SIZE(fallback_paths); i++) {
            status = volume_root->Open(
                volume_root, &kernel_file, fallback_paths[i],
                EFI_FILE_MODE_READ, EFI_FILE_READ_ONLY);

            if (!EFI_ERROR(status)) {
                file_found = TRUE;
                StrnCpyS(actual_kernel_path, sizeof(actual_kernel_path) / sizeof(CHAR16), fallback_paths[i], StrLen(fallback_paths[i]));
                log_message(SystemTable, LOG_LEVEL_INFO, L"Found kernel at: %s\n", fallback_paths[i]);
                break;
            }
        }
    }

    if (!file_found) {
        log_message(SystemTable, LOG_LEVEL_ERROR, L"Failed to find kernel file\n");
        status = EFI_NOT_FOUND;
        goto cleanup;
    }

    // 获取文件信息
    status = kernel_file->GetInfo(kernel_file, &gEfiFileInfoGuid, &info_size, NULL);
    if (status != EFI_BUFFER_TOO_SMALL) {
        log_message(SystemTable, LOG_LEVEL_ERROR, L"Failed to get file info size: %r\n", status);
        goto cleanup;
    }

    status = SystemTable->BootServices->AllocatePool(EfiLoaderData, info_size, (VOID**)&file_info);
    if (EFI_ERROR(status)) {
        log_message(SystemTable, LOG_LEVEL_ERROR, L"Failed to allocate file info memory: %r\n", status);
        goto cleanup;
    }

    status = kernel_file->GetInfo(kernel_file, &gEfiFileInfoGuid, &info_size, file_info);
    if (EFI_ERROR(status)) {
        log_message(SystemTable, LOG_LEVEL_ERROR, L"Failed to get file info: %r\n", status);
        goto cleanup;
    }

    *kernel_size = file_info->FileSize;
    SystemTable->BootServices->FreePool(file_info);
    file_info = NULL;

    log_message(SystemTable, LOG_LEVEL_INFO, L"Kernel size: %llu bytes\n", *kernel_size);

    // 验证文件大小
    if (*kernel_size < sizeof(Elf64_Ehdr)) {
        log_message(SystemTable, LOG_LEVEL_ERROR, L"Kernel too small for ELF header\n");
        status = EFI_LOAD_ERROR;
        goto cleanup;
    }

    // 分配内核内存
    status = SystemTable->BootServices->AllocatePages(
        AllocateAnyPages, EfiLoaderData,
        EFI_SIZE_TO_PAGES(*kernel_size), &kernel_address);

    if (EFI_ERROR(status)) {
        log_message(SystemTable, LOG_LEVEL_ERROR, L"Auto allocation failed: %r\n", status);

        // 尝试在高内存地址分配
        kernel_address = 0x1000000; // 16MB
        status = SystemTable->BootServices->AllocatePages(
            AllocateAddress, EfiLoaderData,
            EFI_SIZE_TO_PAGES(*kernel_size), &kernel_address);

        if (EFI_ERROR(status)) {
            log_message(SystemTable, LOG_LEVEL_ERROR, L"Fixed allocation failed: %r\n", status);
            goto cleanup;
        }
    }

    *kernel_base = kernel_address;
    log_message(SystemTable, LOG_LEVEL_INFO, L"Kernel allocated at 0x%llx\n", kernel_address);

    // 读取内核文件
    read_size = *kernel_size;
    status = kernel_file->Read(kernel_file, &read_size, (VOID*)kernel_address);
    if (EFI_ERROR(status) || read_size != *kernel_size) {
        log_message(SystemTable, LOG_LEVEL_ERROR, L"Failed to read kernel: %r\n", status);
        SystemTable->BootServices->FreePages(kernel_address, EFI_SIZE_TO_PAGES(*kernel_size));
        status = EFI_LOAD_ERROR;
        goto cleanup;
    }

    // 验证内核签名/哈希
    status = verify_kernel_signature(SystemTable, (VOID*)kernel_address, *kernel_size, actual_kernel_path);
    if (EFI_ERROR(status)) {
        log_message(SystemTable, LOG_LEVEL_ERROR, L"Kernel verification failed: %r\n", status);
        SystemTable->BootServices->FreePages(kernel_address, EFI_SIZE_TO_PAGES(*kernel_size));
        goto cleanup;
    }

    // 解析ELF头部
    Elf64_Ehdr* elf_header = (Elf64_Ehdr*)kernel_address;
    kernel_end = kernel_address + *kernel_size;

    // 验证ELF魔数
    if (elf_header->e_ident[EI_MAG0] != ELFMAG0 ||
        elf_header->e_ident[EI_MAG1] != ELFMAG1 ||
        elf_header->e_ident[EI_MAG2] != ELFMAG2 ||
        elf_header->e_ident[EI_MAG3] != ELFMAG3) {
        log_message(SystemTable, LOG_LEVEL_ERROR, L"Invalid ELF magic\n");
        SystemTable->BootServices->FreePages(kernel_address, EFI_SIZE_TO_PAGES(*kernel_size));
        status = EFI_LOAD_ERROR;
        goto cleanup;
    }

    // 验证ELF格式
    if (elf_header->e_ident[EI_CLASS] != ELFCLASS64) {
        log_message(SystemTable, LOG_LEVEL_ERROR, L"Unsupported ELF class\n");
        SystemTable->BootServices->FreePages(kernel_address, EFI_SIZE_TO_PAGES(*kernel_size));
        status = EFI_LOAD_ERROR;
        goto cleanup;
    }

    if (elf_header->e_machine != EM_X86_64) {
        log_message(SystemTable, LOG_LEVEL_ERROR, L"Unsupported architecture\n");
        SystemTable->BootServices->FreePages(kernel_address, EFI_SIZE_TO_PAGES(*kernel_size));
        status = EFI_LOAD_ERROR;
        goto cleanup;
    }

    if (elf_header->e_type != ET_EXEC) {
        log_message(SystemTable, LOG_LEVEL_ERROR, L"Not an executable ELF\n");
        SystemTable->BootServices->FreePages(kernel_address, EFI_SIZE_TO_PAGES(*kernel_size));
        status = EFI_LOAD_ERROR;
        goto cleanup;
    }

    // 验证程序头表
    if (elf_header->e_phoff + (elf_header->e_phnum * elf_header->e_phentsize) > *kernel_size) {
        log_message(SystemTable, LOG_LEVEL_ERROR, L"ELF program headers exceed file size\n");
        SystemTable->BootServices->FreePages(kernel_address, EFI_SIZE_TO_PAGES(*kernel_size));
        status = EFI_LOAD_ERROR;
        goto cleanup;
    }

    // 验证所有LOAD段
    Elf64_Phdr* phdr = (Elf64_Phdr*)(kernel_address + elf_header->e_phoff);
    for (UINTN i = 0; i < elf_header->e_phnum; i++) {
        if (phdr[i].p_type == PT_LOAD) {
            if (phdr[i].p_offset + phdr[i].p_filesz > *kernel_size) {
                log_message(SystemTable, LOG_LEVEL_ERROR, L"Segment %d exceeds file bounds\n", i);
                SystemTable->BootServices->FreePages(kernel_address, EFI_SIZE_TO_PAGES(*kernel_size));
                status = EFI_LOAD_ERROR;
                goto cleanup;
            }
        }
    }

    // 验证入口点
    if (elf_header->e_entry < kernel_address || elf_header->e_entry >= kernel_end) {
        log_message(SystemTable, LOG_LEVEL_ERROR, L"Entry point outside kernel memory\n");
        SystemTable->BootServices->FreePages(kernel_address, EFI_SIZE_TO_PAGES(*kernel_size));
        status = EFI_LOAD_ERROR;
        goto cleanup;
    }

    // 设置内存保护
    status = set_kernel_memory_protection(SystemTable, elf_header, kernel_address);
    if (EFI_ERROR(status)) {
        log_message(SystemTable, LOG_LEVEL_ERROR, L"Failed to set memory protection: %r\n", status);
        SystemTable->BootServices->FreePages(kernel_address, EFI_SIZE_TO_PAGES(*kernel_size));
        goto cleanup;
    }

    // 设置入口点
    *kernel_entry_point = (VOID*)(elf_header->e_entry);
    log_message(SystemTable, LOG_LEVEL_INFO, L"Kernel entry point: 0x%llx\n", elf_header->e_entry);

    status = EFI_SUCCESS;

cleanup:
    if (kernel_file) kernel_file->Close(kernel_file);
    if (volume_root) volume_root->Close(volume_root);
    if (file_info) SystemTable->BootServices->FreePool(file_info);

    return status;
}

// 计算SHA-256哈希
EFI_STATUS calculate_sha256_hash(EFI_SYSTEM_TABLE* SystemTable, VOID* data, UINTN size, UINT8* hash) {
    EFI_STATUS status;
    EFI_GUID hash_guid = EFI_HASH2_PROTOCOL_GUID;
    EFI_HASH2_PROTOCOL* hash_protocol = NULL;
    EFI_HASH2_OUTPUT* hash_output = NULL;

    // 定位哈希协议
    status = SystemTable->BootServices->LocateProtocol(&hash_guid, NULL, (VOID**)&hash_protocol);
    if (EFI_ERROR(status)) {
        log_message(SystemTable, LOG_LEVEL_ERROR, L"Failed to locate hash protocol: %r\n", status);
        return status;
    }

    // 获取哈希大小
    UINTN hash_size = 0;
    status = hash_protocol->GetHashSize(hash_protocol, &gEfiHashAlgorithmSha256Guid, &hash_size);
    if (EFI_ERROR(status)) {
        log_message(SystemTable, LOG_LEVEL_ERROR, L"Failed to get hash size: %r\n", status);
        return status;
    }

    if (hash_size != KERNEL_HASH_SIZE) {
        log_message(SystemTable, LOG_LEVEL_ERROR, L"Unexpected hash size: %d, expected %d\n", hash_size, KERNEL_HASH_SIZE);
        return EFI_UNSUPPORTED;
    }

    // 分配哈希输出缓冲区
    status = SystemTable->BootServices->AllocatePool(EfiLoaderData, hash_size, (VOID**)&hash_output);
    if (EFI_ERROR(status)) {
        log_message(SystemTable, LOG_LEVEL_ERROR, L"Failed to allocate hash output: %r\n", status);
        return status;
    }

    // 计算哈希
    status = hash_protocol->Hash(hash_protocol, &gEfiHashAlgorithmSha256Guid, data, size, hash_output);
    if (EFI_ERROR(status)) {
        log_message(SystemTable, LOG_LEVEL_ERROR, L"Failed to calculate hash: %r\n", status);
        SystemTable->BootServices->FreePool(hash_output);
        return status;
    }

    // 复制哈希结果
    CopyMem(hash, hash_output, hash_size);
    SystemTable->BootServices->FreePool(hash_output);

    return EFI_SUCCESS;
}

// 从安全存储获取预期内核哈希
EFI_STATUS get_expected_kernel_hash(EFI_SYSTEM_TABLE* SystemTable, UINT8* hash, UINTN hash_size, const CHAR16* kernel_path) {
    EFI_STATUS status;
    UINTN data_size = hash_size;
    EFI_GUID kernel_hash_guid = { 0 };

    // 根据内核路径生成唯一的GUID
    // 这里使用简单的CRC32作为示例，实际生产环境中应使用更安全的方法
    UINT32 crc = 0;
    SystemTable->BootServices->CalculateCrc32(kernel_path, StrSize(kernel_path), &crc);

    kernel_hash_guid.Data1 = crc;
    kernel_hash_guid.Data2 = (UINT16)(crc >> 16);
    kernel_hash_guid.Data3 = (UINT16)(crc >> 24);

    // 尝试从UEFI变量读取哈希
    status = SystemTable->RuntimeServices->GetVariable(
        L"KernelHash",
        &kernel_hash_guid,
        NULL,
        &data_size,
        hash);

    if (EFI_ERROR(status)) {
        log_message(SystemTable, LOG_LEVEL_WARNING, L"Failed to get kernel hash from UEFI variable: %r\n", status);

        // 尝试从文件读取哈希
        EFI_LOADED_IMAGE_PROTOCOL* loaded_image = NULL;
        EFI_GUID loaded_image_guid = EFI_LOADED_IMAGE_PROTOCOL_GUID;
        EFI_SIMPLE_FILE_SYSTEM_PROTOCOL* volume = NULL;
        EFI_GUID simple_fs_guid = EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID;
        EFI_FILE_PROTOCOL* volume_root = NULL;
        EFI_FILE_PROTOCOL* hash_file = NULL;
        UINTN read_size = hash_size;
        CHAR16 hash_path[256] = { 0 };

        // 构建哈希文件路径
        StrnCpyS(hash_path, sizeof(hash_path) / sizeof(CHAR16), kernel_path, StrLen(kernel_path));
        StrnCatS(hash_path, sizeof(hash_path) / sizeof(CHAR16), L".sha256", 7);

        // 获取已加载镜像协议
        status = SystemTable->BootServices->HandleProtocol(
            gImageHandle, &loaded_image_guid, (VOID**)&loaded_image);
        if (EFI_ERROR(status)) {
            log_message(SystemTable, LOG_LEVEL_ERROR, L"Failed to get loaded image protocol: %r\n", status);
            return status;
        }

        // 获取文件系统协议
        status = SystemTable->BootServices->HandleProtocol(
            loaded_image->DeviceHandle, &simple_fs_guid, (VOID**)&volume);
        if (EFI_ERROR(status)) {
            log_message(SystemTable, LOG_LEVEL_ERROR, L"Failed to get volume protocol: %r\n", status);
            return status;
        }

        // 打开根目录
        status = volume->OpenVolume(volume, &volume_root);
        if (EFI_ERROR(status)) {
            log_message(SystemTable, LOG_LEVEL_ERROR, L"Failed to open volume: %r\n", status);
            return status;
        }

        // 打开哈希文件
        status = volume_root->Open(
            volume_root, &hash_file, hash_path,
            EFI_FILE_MODE_READ, EFI_FILE_READ_ONLY);

        if (EFI_ERROR(status)) {
            log_message(SystemTable, LOG_LEVEL_ERROR, L"Failed to open hash file: %s, status: %r\n", hash_path, status);
            volume_root->Close(volume_root);
            return status;
        }

        // 读取哈希
        status = hash_file->Read(hash_file, &read_size, hash);
        if (EFI_ERROR(status) || read_size != hash_size) {
            log_message(SystemTable, LOG_LEVEL_ERROR, L"Failed to read hash file: %r\n", status);
            hash_file->Close(hash_file);
            volume_root->Close(volume_root);
            return EFI_LOAD_ERROR;
        }

        hash_file->Close(hash_file);
        volume_root->Close(volume_root);

        log_message(SystemTable, LOG_LEVEL_INFO, L"Loaded kernel hash from file: %s\n", hash_path);
    }
    else {
        log_message(SystemTable, LOG_LEVEL_INFO, L"Loaded kernel hash from UEFI variable\n");
    }

    return EFI_SUCCESS;
}
