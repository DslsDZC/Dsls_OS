#include "uefi.h"

// UEFIӦ�ó�����ڵ�
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

    // ��ʼ��EFI��
    InitializeLib(ImageHandle, SystemTable);

    // ������̨����ӿ���Ч��
    if (SystemTable->ConOut != NULL) {
        SystemTable->ConOut->ClearScreen(SystemTable->ConOut);
        Print(L"Starting UEFI Bootloader...\n");
    }

    // ��ʼ��ͼ��ģʽ
    status = init_graphics(ImageHandle, SystemTable, &gfx_info);
    if (EFI_ERROR(status)) {
        Print(L"Failed to initialize graphics: %r\n", status);
        // ����ͼ����Ϣ�������ں�ʹ����Чֵ
        gfx_info = (graphics_info_t){ 0 };
    }
    else {
        Print(L"Graphics initialized: %dx%d\n", gfx_info.width, gfx_info.height);
    }

    // �����ں�
    status = load_kernel(ImageHandle, SystemTable, &kernel_entry);
    if (EFI_ERROR(status)) {
        Print(L"Failed to load kernel: %r\n", status);
        return status;
    }

    // ��ʽ����ں���ڵ���Ч��
    if (kernel_entry == NULL) {
        Print(L"Kernel entry point is NULL\n");
        return EFI_LOAD_ERROR;
    }

    // ��������ʱ�־��ڴ�洢��������
    status = SystemTable->BootServices->AllocatePool(
        EfiRuntimeServicesData,
        sizeof(boot_params_t),
        (VOID**)&boot_params
    );

    if (EFI_ERROR(status)) {
        Print(L"Failed to allocate boot params: %r\n", status);
        return status;
    }

    // ��ʼ����������
    boot_params->graphics = gfx_info;

    // �˳��������񣬲���ʹ��UEFI����

    // ��ȡ��ǰ�ڴ�ӳ���С
    status = SystemTable->BootServices->GetMemoryMap(
        &memory_map_size,
        memory_map,
        &map_key,
        &descriptor_size,
        &descriptor_version
    );

    if (status != EFI_BUFFER_TOO_SMALL) {
        Print(L"Failed to get memory map size: %r\n", status);
        SystemTable->BootServices->FreePool(boot_params);
        return status;
    }

    // �������2����������С�Ŀռ䣬��ֹ�ڴ�ӳ���ڻ�ȡ�����ж�̬����
    UINTN alloc_size = memory_map_size + 2 * descriptor_size;
    status = SystemTable->BootServices->AllocatePool(
        EfiRuntimeServicesData,  // ʹ������ʱ���ݣ�ȷ���˳�������Ч
        alloc_size,
        (VOID**)&memory_map
    );

    if (EFI_ERROR(status)) {
        Print(L"Failed to allocate memory for memory map: %r\n", status);
        SystemTable->BootServices->FreePool(boot_params);
        return status;
    }

    // ��ȡ�������ڴ�ӳ��
    status = SystemTable->BootServices->GetMemoryMap(
        &memory_map_size,
        memory_map,
        &map_key,
        &descriptor_size,
        &descriptor_version
    );

    if (EFI_ERROR(status)) {
        Print(L"Failed to get memory map: %r\n", status);
        SystemTable->BootServices->FreePool(memory_map);
        SystemTable->BootServices->FreePool(boot_params);
        return status;
    }

    // ����ڴ�ӳ����Ϣ����������
    boot_params->memory_map.memory_map = memory_map;
    boot_params->memory_map.memory_map_size = memory_map_size;
    boot_params->memory_map.descriptor_size = descriptor_size;
    boot_params->memory_map.descriptor_version = descriptor_version;
    boot_params->memory_map.map_key = map_key;

    // ���˳���������ǰ��ӡ������Ϣ
    Print(L"Exiting boot services, jumping to kernel...\n");

    // ���ExitBootServices���Ի���
    UINTN retry_count = 3;
    while (retry_count-- > 0) {
        status = SystemTable->BootServices->ExitBootServices(ImageHandle, map_key);
        if (!EFI_ERROR(status)) {
            break;
        }

        Print(L"ExitBootServices failed: %r, retrying...\n", status);

        // �ͷžɻ�����
        if (memory_map != NULL) {
            SystemTable->BootServices->FreePool(memory_map);
            memory_map = NULL;
        }

        // ���»�ȡ�����С
        status = SystemTable->BootServices->GetMemoryMap(
            &memory_map_size,
            NULL,
            &map_key,
            &descriptor_size,
            &descriptor_version
        );

        if (status != EFI_BUFFER_TOO_SMALL) {
            Print(L"Failed to get memory map size during retry: %r\n", status);
            break;
        }

        // ���·��仺�������������ࣩ
        alloc_size = memory_map_size + 2 * descriptor_size;
        status = SystemTable->BootServices->AllocatePool(
            EfiRuntimeServicesData,
            alloc_size,
            (VOID**)&memory_map
        );

        if (EFI_ERROR(status)) {
            Print(L"Failed to allocate memory map during retry: %r\n", status);
            break;
        }

        // ���»�ȡ����ӳ��
        status = SystemTable->BootServices->GetMemoryMap(
            &memory_map_size,
            memory_map,
            &map_key,
            &descriptor_size,
            &descriptor_version
        );

        if (EFI_ERROR(status)) {
            Print(L"Failed to get memory map during retry: %r\n", status);
            break;
        }

        // �����ڴ�ӳ��ָ��
        boot_params->memory_map.memory_map = memory_map;
        boot_params->memory_map.memory_map_size = memory_map_size;
        boot_params->memory_map.descriptor_size = descriptor_size;
        boot_params->memory_map.descriptor_version = descriptor_version;
        boot_params->memory_map.map_key = map_key;
    }

    if (EFI_ERROR(status)) {
        Print(L"Failed to exit boot services after retries: %r\n", status);
        SystemTable->BootServices->FreePool(memory_map);
        SystemTable->BootServices->FreePool(boot_params);
        return status;
    }

    // ע�⣺�����￪ʼ��������ʹ���κ�UEFI Boot Services����

    // �����ں���ڵ㺯������
    typedef void (*kernel_entry_t)(boot_params_t*);
    kernel_entry_t kernel_start = (kernel_entry_t)kernel_entry;

    // �����ں���ڵ㣬������������
    kernel_start(boot_params);

    // �ں˲�Ӧ���أ����������ѭ��
    while (1) {
        __asm__("hlt");
    }

    return EFI_LOAD_ERROR;
}