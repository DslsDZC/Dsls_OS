#include "uefi.h"

// �����ں�ӳ��
// ע�⣺�˺������� InitializeLib ��ʼ�������÷���ȷ���ѵ��� InitializeLib
EFI_STATUS load_kernel(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE* SystemTable, VOID** kernel_entry_point) {
    EFI_STATUS status = EFI_SUCCESS;
    EFI_LOADED_IMAGE_PROTOCOL* loaded_image = NULL;
    EFI_GUID loaded_image_guid = EFI_LOADED_IMAGE_PROTOCOL_GUID;
    EFI_FILE_IO_INTERFACE* volume = NULL;
    EFI_FILE_HANDLE volume_root = NULL;
    EFI_FILE_HANDLE kernel_file = NULL;
    EFI_FILE_INFO* file_info = NULL;
    UINTN info_size = 0;
    UINTN kernel_size = 0;
    UINTN read_size = 0;
    EFI_PHYSICAL_ADDRESS kernel_address = 0;
    UINT64 kernel_end = 0;

    // ��ʼ���������
    *kernel_entry_point = NULL;

    // ��ȡ�Ѽ��ؾ���Э��
    status = SystemTable->BootServices->HandleProtocol(
        ImageHandle,
        &loaded_image_guid,
        (VOID**)&loaded_image
    );

    if (EFI_ERROR(status)) {
        Print(L"Failed to get loaded image protocol: %r\n", status);
        goto cleanup;
    }

    // ��ȡ���豸Э��
    EFI_GUID simple_fs_guid = EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID;
    status = SystemTable->BootServices->HandleProtocol(
        loaded_image->DeviceHandle,
        &simple_fs_guid,
        (VOID**)&volume
    );

    if (EFI_ERROR(status)) {
        Print(L"Failed to get volume protocol: %r\n", status);
        goto cleanup;
    }

    // �򿪾��Ŀ¼
    status = volume->OpenVolume(volume, &volume_root);
    if (EFI_ERROR(status)) {
        Print(L"Failed to open volume: %r\n", status);
        goto cleanup;
    }

    // ���ں��ļ� (�����ں���Ϊkernel.elf)
    status = volume_root->Open(
        volume_root,
        &kernel_file,
        L"kernel.elf",
        EFI_FILE_MODE_READ,
        EFI_FILE_READ_ONLY
    );

    if (EFI_ERROR(status)) {
        Print(L"Failed to open kernel file: %r\n", status);
        goto cleanup;
    }

    // ��ȡ�ļ���Ϣ
    status = kernel_file->GetInfo(
        kernel_file,
        &gEfiFileInfoGuid,
        &info_size,
        NULL
    );

    if (status != EFI_BUFFER_TOO_SMALL) {
        Print(L"Failed to get file info size: %r\n", status);
        goto cleanup;
    }

    status = SystemTable->BootServices->AllocatePool(
        EfiLoaderData,
        info_size,
        (VOID**)&file_info
    );

    if (EFI_ERROR(status)) {
        Print(L"Failed to allocate memory for file info: %r\n", status);
        goto cleanup;
    }

    status = kernel_file->GetInfo(
        kernel_file,
        &gEfiFileInfoGuid,
        &info_size,
        file_info
    );

    if (EFI_ERROR(status)) {
        Print(L"Failed to get file info: %r\n", status);
        goto cleanup;
    }

    kernel_size = file_info->FileSize;
    SystemTable->BootServices->FreePool(file_info);
    file_info = NULL;

    Print(L"Kernel size: %llu bytes\n", kernel_size);

    // ��֤�ļ���С����������ELFͷ��
    if (kernel_size < sizeof(Elf64_Ehdr)) {
        Print(L"Kernel file too small for ELF header: %u bytes (needs at least %u)\n",
            kernel_size, (UINTN)sizeof(Elf64_Ehdr));
        status = EFI_LOAD_ERROR;
        goto cleanup;
    }

    // �����Զ������ڴ�
    status = SystemTable->BootServices->AllocatePages(
        AllocateAnyPages,  // �Զ�����
        EfiLoaderCode,     // ʹ��EfiLoaderCode���ʹ�Ŵ���
        EFI_SIZE_TO_PAGES(kernel_size),
        &kernel_address
    );

    // ���Զ�����ʧ�ܣ�����1MB��ַ
    if (EFI_ERROR(status)) {
        Print(L"Auto allocation failed: %r, trying fixed address 0x100000\n", status);
        kernel_address = 0x100000;
        status = SystemTable->BootServices->AllocatePages(
            AllocateAddress,
            EfiLoaderCode,
            EFI_SIZE_TO_PAGES(kernel_size),
            &kernel_address
        );

        if (EFI_ERROR(status)) {
            Print(L"Fixed address allocation also failed: %r\n", status);
            goto cleanup;
        }
    }

    Print(L"Kernel allocated at 0x%llx\n", kernel_address);

    // ����֤������ڴ������Ƿ�Ϊ�����ڴ�
    // ע�⣺����һ���򻯵���֤��ʵ��ʵ�ֿ�����Ҫ�����ӵ��ڴ���������ѯ
    if (kernel_address == 0) {
        Print(L"Invalid kernel address: 0x0\n");
        SystemTable->BootServices->FreePages(kernel_address, EFI_SIZE_TO_PAGES(kernel_size));
        status = EFI_LOAD_ERROR;
        goto cleanup;
    }

    // ��ȡ�ں��ļ����ڴ�
    read_size = kernel_size;
    status = kernel_file->Read(
        kernel_file,
        &read_size,
        (VOID*)kernel_address
    );

    // ����ȡ�Ƿ�����
    if (EFI_ERROR(status)) {
        Print(L"Failed to read kernel: %r\n", status);
        SystemTable->BootServices->FreePages(kernel_address, EFI_SIZE_TO_PAGES(kernel_size));
        goto cleanup;
    }

    if (read_size != kernel_size) {
        Print(L"Failed to read full kernel: read %u/%u bytes\n", read_size, kernel_size);
        SystemTable->BootServices->FreePages(kernel_address, EFI_SIZE_TO_PAGES(kernel_size));
        status = EFI_LOAD_ERROR;
        goto cleanup;
    }

    // ��ELF��������ȡ��ڵ�
    Elf64_Ehdr* elf_header = (Elf64_Ehdr*)kernel_address;

    // ��֤ELFħ��
    if (elf_header->e_ident[EI_MAG0] != ELFMAG0 ||
        elf_header->e_ident[EI_MAG1] != ELFMAG1 ||
        elf_header->e_ident[EI_MAG2] != ELFMAG2 ||
        elf_header->e_ident[EI_MAG3] != ELFMAG3) {
        Print(L"Invalid ELF format\n");
        SystemTable->BootServices->FreePages(kernel_address, EFI_SIZE_TO_PAGES(kernel_size));
        status = EFI_LOAD_ERROR;
        goto cleanup;
    }

    // ��֤e_ident�����������
    if (kernel_size < EI_NIDENT) {
        Print(L"Kernel file too small for ELF ident: %u bytes (needs at least %u)\n",
            kernel_size, EI_NIDENT);
        SystemTable->BootServices->FreePages(kernel_address, EFI_SIZE_TO_PAGES(kernel_size));
        status = EFI_LOAD_ERROR;
        goto cleanup;
    }

    // ��֤ELF���64λ��
    if (elf_header->e_ident[EI_CLASS] != ELFCLASS64) {
        Print(L"Unsupported ELF class: expected 64-bit (ELFCLASS64), got %u\n", elf_header->e_ident[EI_CLASS]);
        SystemTable->BootServices->FreePages(kernel_address, EFI_SIZE_TO_PAGES(kernel_size));
        status = EFI_LOAD_ERROR;
        goto cleanup;
    }

    // ��֤�ܹ���x86_64��
    if (elf_header->e_machine != EM_X86_64) {
        Print(L"Unsupported architecture: expected EM_X86_64 (%u), got %u\n", EM_X86_64, elf_header->e_machine);
        SystemTable->BootServices->FreePages(kernel_address, EFI_SIZE_TO_PAGES(kernel_size));
        status = EFI_LOAD_ERROR;
        goto cleanup;
    }

    // ��֤�ļ����ͣ������ǿ�ִ���ļ���
    if (elf_header->e_type != ET_EXEC) {
        Print(L"Invalid ELF type: expected executable (ET_EXEC), got %u\n", elf_header->e_type);
        SystemTable->BootServices->FreePages(kernel_address, EFI_SIZE_TO_PAGES(kernel_size));
        status = EFI_LOAD_ERROR;
        goto cleanup;
    }

    // ��֤��ڵ��Ƿ��ںϷ���Χ��
    kernel_end = kernel_address + kernel_size;
    if (elf_header->e_entry < kernel_address || elf_header->e_entry >= kernel_end) {
        Print(L"Invalid ELF entry point: 0x%llx (not in kernel memory 0x%llx-0x%llx)\n",
            elf_header->e_entry, kernel_address, kernel_end);
        SystemTable->BootServices->FreePages(kernel_address, EFI_SIZE_TO_PAGES(kernel_size));
        status = EFI_LOAD_ERROR;
        goto cleanup;
    }

    // ��ȡ��ڵ��ַ
    *kernel_entry_point = (VOID*)(elf_header->e_entry);

    Print(L"Kernel entry point: 0x%llx\n", elf_header->e_entry);
    Print(L"Kernel loaded successfully\n");

    status = EFI_SUCCESS;

cleanup:
    // ͳһ��Դ����
    if (kernel_file != NULL) {
        kernel_file->Close(kernel_file);
    }
    if (volume_root != NULL) {
        volume_root->Close(volume_root);
    }
    if (file_info != NULL) {
        SystemTable->BootServices->FreePool(file_info);
    }

    return status;
}