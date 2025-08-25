#include "uefi.h"

// ��ȫ��ӡ������ȷ��ConOut��Чʱ�����
static void SafePrint(EFI_SYSTEM_TABLE* SystemTable, const CHAR16* format, ...) {
    if (SystemTable->ConOut) {
        VA_LIST args;
        VA_START(args, format);
        VPrint(format, args);
        VA_END(args);
    }
}

// ��֤�ڴ�ӳ��ĺϷ���
EFI_STATUS validate_memory_map(EFI_MEMORY_DESCRIPTOR* memory_map, UINTN memory_map_size, UINTN descriptor_size) {
    UINTN num_descriptors = memory_map_size / descriptor_size;

    for (UINTN i = 0; i < num_descriptors; i++) {
        EFI_MEMORY_DESCRIPTOR* desc = (EFI_MEMORY_DESCRIPTOR*)((UINT8*)memory_map + i * descriptor_size);

        // ����ڴ������Ƿ���Ч
        if (desc->Type >= EfiMaxMemoryType) {
            return EFI_INVALID_PARAMETER;
        }

        // ��������ַ��ҳ�����Ƿ������ֹ�����
        if (desc->NumberOfPages == 0 ||
            desc->PhysicalStart + desc->NumberOfPages * EFI_PAGE_SIZE < desc->PhysicalStart) {
            return EFI_INVALID_PARAMETER;
        }

        // ��������Ƿ�Ϊ�Ϸ����
        if (desc->Attribute & ~(EFI_MEMORY_UC | EFI_MEMORY_WC | EFI_MEMORY_WT |
            EFI_MEMORY_WB | EFI_MEMORY_UCE | EFI_MEMORY_WP |
            EFI_MEMORY_RP | EFI_MEMORY_XP | EFI_MEMORY_RO)) {
            return EFI_INVALID_PARAMETER;
        }
    }

    return EFI_SUCCESS;
}

// ��������������CRC32У���
UINT32 calculate_boot_params_crc(boot_params_t* boot_params) {
    UINT32 crc = 0;
    UINT8* data = (UINT8*)boot_params;
    UINTN size = sizeof(boot_params_t);

    // ��ʱ����ԭʼCRC�����㣨����У��Ͱ�������
    UINT32 original_crc = boot_params->crc32;
    boot_params->crc32 = 0;

    for (UINTN i = 0; i < size; i++) {
        crc = (crc << 5) - crc + data[i]; // �򻯵�CRC�㷨
    }

    // �ָ�ԭʼCRC
    boot_params->crc32 = original_crc;
    return crc;
}

// ��ȡACPI��
EFI_STATUS get_acpi_tables(EFI_SYSTEM_TABLE* SystemTable, VOID** rsdp) {
    EFI_STATUS status;
    EFI_GUID acpi_guid = EFI_ACPI_TABLE_GUID;

    // ���Ի�ȡACPI 2.0��
    status = SystemTable->BootServices->GetConfigurationTable(&acpi_guid, rsdp);
    if (EFI_ERROR(status)) {
        // ���Ի�ȡACPI 1.0��
        EFI_GUID acpi10_guid = EFI_ACPI_10_TABLE_GUID;
        status = SystemTable->BootServices->GetConfigurationTable(&acpi10_guid, rsdp);
    }

    return status;
}

// ��ȡ�ں������в���
EFI_STATUS get_kernel_command_line(EFI_SYSTEM_TABLE* SystemTable, CHAR16* cmdline, UINTN size) {
    EFI_STATUS status;
    UINTN data_size = size;
    EFI_GUID global_guid = EFI_GLOBAL_VARIABLE_GUID;

    status = SystemTable->RuntimeServices->GetVariable(
        L"KernelCommandLine",
        &global_guid,
        NULL,
        &data_size,
        cmdline
    );

    if (status == EFI_NOT_FOUND) {
        // ʹ��Ĭ�Ͽ�������
        StrnCpyS(cmdline, size / sizeof(CHAR16), L"", 1);
        return EFI_SUCCESS;
    }

    return status;
}

// �����ں�ջ��64KB��
EFI_STATUS setup_kernel_stack(EFI_SYSTEM_TABLE* SystemTable, EFI_PHYSICAL_ADDRESS* stack_top) {
    EFI_STATUS status;
    EFI_PHYSICAL_ADDRESS stack_base = 0;
    UINTN stack_pages = 16; // 16ҳ = 64KB������4KBҳ��

    status = SystemTable->BootServices->AllocatePages(
        AllocateAnyPages,
        EfiKernelData,
        stack_pages,
        &stack_base
    );

    if (EFI_ERROR(status)) {
        return status;
    }

    // ջ����������ջ��Ϊ���������ĩβ
    *stack_top = stack_base + stack_pages * EFI_PAGE_SIZE;
    return EFI_SUCCESS;
}

// UEFIӦ�ó������
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

    // ��ʼ��EFI��
    InitializeLib(ImageHandle, SystemTable);

    // ���������������Ϣ
    if (SystemTable->ConOut != NULL) {
        SystemTable->ConOut->ClearScreen(SystemTable->ConOut);
        SafePrint(SystemTable, L"Starting UEFI Bootloader...\n");
    }

    // ��ʼ��ͼ��ģʽ
    status = init_graphics(ImageHandle, SystemTable, &gfx_info);
    if (EFI_ERROR(status)) {
        SafePrint(SystemTable, L"Failed to initialize graphics: %r\n", status);
        gfx_info = (graphics_info_t){ 0 }; // ����Ϊ��Ч״̬
    }
    else {
        SafePrint(SystemTable, L"Graphics initialized: %dx%d\n", gfx_info.width, gfx_info.height);
    }

    // �����ں�
    status = load_kernel(ImageHandle, SystemTable, &kernel_entry);
    if (EFI_ERROR(status)) {
        SafePrint(SystemTable, L"Failed to load kernel: %r\n", status);
        return status;
    }

    // ��֤�ں���ڵ���Ч��
    if (kernel_entry == NULL) {
        SafePrint(SystemTable, L"Kernel entry point is NULL\n");
        return EFI_LOAD_ERROR;
    }

    // �������������ڴ�
    status = SystemTable->BootServices->AllocatePool(
        EfiRuntimeServicesData,
        sizeof(boot_params_t),
        (VOID**)&boot_params
    );
    if (EFI_ERROR(status)) {
        SafePrint(SystemTable, L"Failed to allocate boot params: %r\n", status);
        return status;
    }

    // ��ʼ����������
    boot_params->graphics = gfx_info;
    boot_params->acpi_rsdp = NULL;
    boot_params->cmdline[0] = L'\0';
    boot_params->crc32 = 0;

    // ��ȡACPI����Ϣ
    status = get_acpi_tables(SystemTable, &boot_params->acpi_rsdp);
    if (EFI_ERROR(status)) {
        SafePrint(SystemTable, L"Warning: Failed to get ACPI tables: %r\n", status);
    }
    else {
        SafePrint(SystemTable, L"ACPI tables found at 0x%llx\n", boot_params->acpi_rsdp);
    }

    // ��ȡ�ں�������
    status = get_kernel_command_line(SystemTable, boot_params->cmdline, sizeof(boot_params->cmdline));
    if (EFI_ERROR(status)) {
        SafePrint(SystemTable, L"Warning: Failed to get kernel command line: %r\n", status);
    }
    else {
        SafePrint(SystemTable, L"Kernel command line: %s\n", boot_params->cmdline);
    }

    // ��ȡ�ڴ�ӳ���С
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

    // �����ڴ�ӳ�仺����������Ԥ��2���������ռ��ֹ��̬������
    UINTN alloc_size = memory_map_size + 2 * descriptor_size;
    status = SystemTable->BootServices->AllocatePool(
        EfiRuntimeServicesData,
        alloc_size,
        (VOID**)&memory_map
    );
    if (EFI_ERROR(status)) {
        SafePrint(SystemTable, L"Failed to allocate memory for memory map: %r\n", status);
        SystemTable->BootServices->FreePool(boot_params);
        return status;
    }

    // ��ȡ�����ڴ�ӳ��
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

    // ��֤�ڴ�ӳ��Ϸ���
    status = validate_memory_map(memory_map, memory_map_size, descriptor_size);
    if (EFI_ERROR(status)) {
        SafePrint(SystemTable, L"Invalid memory map detected: %r\n", status);
        SystemTable->BootServices->FreePool(memory_map);
        SystemTable->BootServices->FreePool(boot_params);
        return status;
    }

    // ����ڴ�ӳ�䵽��������
    boot_params->memory_map.memory_map = memory_map;
    boot_params->memory_map.memory_map_size = memory_map_size;
    boot_params->memory_map.descriptor_size = descriptor_size;
    boot_params->memory_map.descriptor_version = descriptor_version;
    boot_params->memory_map.map_key = map_key;

    // �����ں�ջ
    status = setup_kernel_stack(SystemTable, &kernel_stack);
    if (EFI_ERROR(status)) {
        SafePrint(SystemTable, L"Warning: Failed to setup kernel stack: %r (using bootloader stack)\n", status);
    }
    else {
        SafePrint(SystemTable, L"Kernel stack initialized at 0x%llx\n", kernel_stack);
    }

    // ������������CRCУ���
    boot_params->crc32 = calculate_boot_params_crc(boot_params);

    // �˳���������
    SafePrint(SystemTable, L"Exiting boot services, jumping to kernel...\n");
    UINTN retry_count = 3;
    while (retry_count-- > 0) {
        status = SystemTable->BootServices->ExitBootServices(ImageHandle, map_key);
        if (!EFI_ERROR(status)) break;

        SafePrint(SystemTable, L"ExitBootServices failed: %r, retrying...\n", status);
        SystemTable->BootServices->Stall(100000); // �ȴ�100ms

        // �ͷž��ڴ�ӳ�䲢���»�ȡ
        if (memory_map) SystemTable->BootServices->FreePool(memory_map);
        status = SystemTable->BootServices->GetMemoryMap(&memory_map_size, NULL, &map_key, &descriptor_size, &descriptor_version);
        if (status != EFI_BUFFER_TOO_SMALL) {
            SafePrint(SystemTable, L"Failed to get memory map size during retry: %r\n", status);
            break;
        }

        alloc_size = memory_map_size + 2 * descriptor_size;
        status = SystemTable->BootServices->AllocatePool(EfiRuntimeServicesData, alloc_size, (VOID**)&memory_map);
        if (EFI_ERROR(status)) {
            SafePrint(SystemTable, L"Failed to allocate memory map during retry: %r\n", status);
            break;
        }

        status = SystemTable->BootServices->GetMemoryMap(&memory_map_size, memory_map, &map_key, &descriptor_size, &descriptor_version);
        if (EFI_ERROR(status)) {
            SafePrint(SystemTable, L"Failed to get memory map during retry: %r\n", status);
            break;
        }

        // �������������е��ڴ�ӳ��
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

    // �л����ں�ջ����ת���ںˣ���ջ��ʼ���ɹ���
    typedef void (*kernel_entry_t)(boot_params_t*);
    kernel_entry_t kernel_start = (kernel_entry_t)kernel_entry;

    if (kernel_stack != 0) {
        // ��������л�ջ�������ںˣ�x86_64��
        __asm__ volatile (
            "mov %0, %%rsp\n"    // ������ջ��
            "jmp *%1"            // ��ת���ں����
            : : "r"(kernel_stack), "r"(kernel_start) : "memory"
            );
    }
    else {
        // ʹ���������س����ջ
        kernel_start(boot_params);
    }

    // �ں˲�Ӧ���أ������������ͣ��ѭ��
    while (1) {
        __asm__("hlt");
    }

    return EFI_LOAD_ERROR;
}