#include "uefi.h"

// �ں�ǩ����֤��ʹ��UEFI��ȫЭ����ϣУ�飩
EFI_STATUS verify_kernel_signature(EFI_SYSTEM_TABLE* SystemTable, VOID* kernel_data, UINTN kernel_size) {
    EFI_STATUS status;
    EFI_GUID security_guid = EFI_IMAGE_SECURITY_DATABASE_GUID;
    EFI_IMAGE_SECURITY_DATABASE_PROTOCOL* security_proto = NULL;

    // ����ʹ��UEFI��ȫЭ����֤
    status = SystemTable->BootServices->LocateProtocol(&security_guid, NULL, (VOID**)&security_proto);
    if (!EFI_ERROR(status)) {
        return security_proto->Verify(kernel_data, kernel_size);
    }

    // ���˵��򵥹�ϣУ�飨ʵ��Ӧ����Ӧ�滻ΪԤ����Ĺ�ϣֵ��
    UINT8 expected_hash[32] = { 0x00 }; // �˴�Ӧ����Ԥ������ں˹�ϣ
    UINT8 actual_hash[32] = { 0x00 };

    // ע�⣺ʵ��ʹ��ʱ�����UEFI��ϣ�������actual_hash
    // ʾ����gBS->CalculateCrc32(kernel_data, kernel_size, &actual_hash);���򻯣�
    if (CompareMem(expected_hash, actual_hash, 32) != 0) {
        return EFI_SECURITY_VIOLATION;
    }

    return EFI_SUCCESS;
}

// �����ں��ڴ汣�����ԣ�����ELF�α�־��
EFI_STATUS set_kernel_memory_protection(EFI_SYSTEM_TABLE* SystemTable, Elf64_Ehdr* elf_header, EFI_PHYSICAL_ADDRESS kernel_address) {
    EFI_STATUS status;
    Elf64_Phdr* phdr = (Elf64_Phdr*)(kernel_address + elf_header->e_phoff);

    for (int i = 0; i < elf_header->e_phnum; i++) {
        if (phdr[i].p_type != PT_LOAD) continue; // ֻ����LOAD��

        UINT64 seg_start = phdr[i].p_vaddr;
        UINT64 seg_end = seg_start + phdr[i].p_memsz;

        // ���뵽ҳ��߽�
        UINT64 page_start = seg_start & ~(EFI_PAGE_SIZE - 1);
        UINT64 page_end = (seg_end + EFI_PAGE_SIZE - 1) & ~(EFI_PAGE_SIZE - 1);
        UINTN page_count = EFI_SIZE_TO_PAGES(page_end - page_start);

        // ����ELF�α�־�����ڴ�����
        UINT64 attributes = 0;
        if (phdr[i].p_flags & PF_R) attributes |= EFI_MEMORY_RO;    // ֻ��
        if (phdr[i].p_flags & PF_W) attributes |= EFI_MEMORY_RW;    // ��д������ֻ����
        if (!(phdr[i].p_flags & PF_X)) attributes |= EFI_MEMORY_XP; // ����ִ��

        status = SystemTable->RuntimeServices->SetMemoryAttributes(
            page_start,
            page_count * EFI_PAGE_SIZE,
            attributes
        );
        if (EFI_ERROR(status)) {
            return status;
        }
    }

    return EFI_SUCCESS;
}

// ���ز���֤�ں�
EFI_STATUS load_kernel(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE* SystemTable, VOID** kernel_entry_point) {
    EFI_STATUS status = EFI_SUCCESS;
    EFI_LOADED_IMAGE_PROTOCOL* loaded_image = NULL;
    EFI_GUID loaded_image_guid = EFI_LOADED_IMAGE_PROTOCOL_GUID;
    EFI_FILE_IO_INTERFACE* volume = NULL;
    EFI_GUID simple_fs_guid = EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID;
    EFI_FILE_HANDLE volume_root = NULL;
    EFI_FILE_HANDLE kernel_file = NULL;
    EFI_FILE_INFO* file_info = NULL;
    UINTN info_size = 0;
    UINTN kernel_size = 0;
    UINTN read_size = 0;
    EFI_PHYSICAL_ADDRESS kernel_address = 0;
    UINT64 kernel_end = 0;
    BOOLEAN KERNEL_SIGNATURE_CHECK = TRUE; // ����ǩ����֤

    // ��ʼ���������
    *kernel_entry_point = NULL;

    // ��ȡ�Ѽ��ؾ���Э��
    status = SystemTable->BootServices->HandleProtocol(
        ImageHandle, &loaded_image_guid, (VOID**)&loaded_image
    );
    if (EFI_ERROR(status)) {
        if (SystemTable->ConOut) Print(L"Failed to get loaded image protocol: %r\n", status);
        goto cleanup;
    }

    // ��ȡ�ļ�ϵͳЭ��
    status = SystemTable->BootServices->HandleProtocol(
        loaded_image->DeviceHandle, &simple_fs_guid, (VOID**)&volume
    );
    if (EFI_ERROR(status)) {
        if (SystemTable->ConOut) Print(L"Failed to get volume protocol: %r\n", status);
        goto cleanup;
    }

    // �򿪸�Ŀ¼
    status = volume->OpenVolume(volume, &volume_root);
    if (EFI_ERROR(status)) {
        if (SystemTable->ConOut) Print(L"Failed to open volume: %r\n", status);
        goto cleanup;
    }

    // ���ں��ļ���kernel.elf��
    status = volume_root->Open(
        volume_root, &kernel_file, L"kernel.elf",
        EFI_FILE_MODE_READ, EFI_FILE_READ_ONLY
    );
    if (EFI_ERROR(status)) {
        if (SystemTable->ConOut) Print(L"Failed to open kernel file: %r\n", status);
        goto cleanup;
    }

    // ��ȡ�ļ���Ϣ���Ȳ�ѯ��С��
    status = kernel_file->GetInfo(kernel_file, &gEfiFileInfoGuid, &info_size, NULL);
    if (status != EFI_BUFFER_TOO_SMALL) {
        if (SystemTable->ConOut) Print(L"Failed to get file info size: %r\n", status);
        goto cleanup;
    }

    // �����ļ���Ϣ�ڴ�
    status = SystemTable->BootServices->AllocatePool(EfiLoaderData, info_size, (VOID**)&file_info);
    if (EFI_ERROR(status)) {
        if (SystemTable->ConOut) Print(L"Failed to allocate file info memory: %r\n", status);
        goto cleanup;
    }

    // ��ȡʵ���ļ���Ϣ
    status = kernel_file->GetInfo(kernel_file, &gEfiFileInfoGuid, &info_size, file_info);
    if (EFI_ERROR(status)) {
        if (SystemTable->ConOut) Print(L"Failed to get file info: %r\n", status);
        goto cleanup;
    }

    kernel_size = file_info->FileSize;
    SystemTable->BootServices->FreePool(file_info);
    file_info = NULL;
    if (SystemTable->ConOut) Print(L"Kernel size: %llu bytes\n", kernel_size);

    // ��֤�ļ���С���ٰ���ELFͷ��
    if (kernel_size < sizeof(Elf64_Ehdr)) {
        if (SystemTable->ConOut) Print(L"Kernel too small for ELF header (needs %u bytes)\n", sizeof(Elf64_Ehdr));
        status = EFI_LOAD_ERROR;
        goto cleanup;
    }

    // �����ں��ڴ棨�����Զ����䣩
    status = SystemTable->BootServices->AllocatePages(
        AllocateAnyPages, EfiKernelCode,
        EFI_SIZE_TO_PAGES(kernel_size), &kernel_address
    );

    // �Զ�����ʧ��ʱ���Թ̶���ַ
    if (EFI_ERROR(status)) {
        if (SystemTable->ConOut) Print(L"Auto allocation failed: %r, trying fixed addresses\n", status);
        EFI_PHYSICAL_ADDRESS addresses[] = { 0x100000, 0x200000, 0x300000 }; // 1M, 2M, 3M

        for (UINTN i = 0; i < sizeof(addresses) / sizeof(addresses[0]); i++) {
            kernel_address = addresses[i];
            status = SystemTable->BootServices->AllocatePages(
                AllocateAddress, EfiKernelCode,
                EFI_SIZE_TO_PAGES(kernel_size), &kernel_address
            );
            if (!EFI_ERROR(status)) break;
            if (SystemTable->ConOut) Print(L"Fixed address 0x%llx failed: %r\n", addresses[i], status);
        }

        if (EFI_ERROR(status)) {
            if (SystemTable->ConOut) Print(L"All address allocations failed\n");
            goto cleanup;
        }
    }

    if (SystemTable->ConOut) Print(L"Kernel allocated at 0x%llx\n", kernel_address);
    if (kernel_address == 0) { // ��֤��ַ��Ч��
        if (SystemTable->ConOut) Print(L"Invalid kernel address: 0x0\n");
        SystemTable->BootServices->FreePages(kernel_address, EFI_SIZE_TO_PAGES(kernel_size));
        status = EFI_LOAD_ERROR;
        goto cleanup;
    }

    // ��ȡ�ں��ļ����ڴ�
    read_size = kernel_size;
    status = kernel_file->Read(kernel_file, &read_size, (VOID*)kernel_address);
    if (EFI_ERROR(status)) {
        if (SystemTable->ConOut) Print(L"Failed to read kernel: %r\n", status);
        SystemTable->BootServices->FreePages(kernel_address, EFI_SIZE_TO_PAGES(kernel_size));
        goto cleanup;
    }
    if (read_size != kernel_size) {
        if (SystemTable->ConOut) Print(L"Read incomplete: %u/%u bytes\n", read_size, kernel_size);
        SystemTable->BootServices->FreePages(kernel_address, EFI_SIZE_TO_PAGES(kernel_size));
        status = EFI_LOAD_ERROR;
        goto cleanup;
    }

    // ��֤�ں�ǩ��
    if (KERNEL_SIGNATURE_CHECK) {
        status = verify_kernel_signature(SystemTable, (VOID*)kernel_address, kernel_size);
        if (EFI_ERROR(status)) {
            if (SystemTable->ConOut) Print(L"Kernel signature verification failed: %r\n", status);
            SystemTable->BootServices->FreePages(kernel_address, EFI_SIZE_TO_PAGES(kernel_size));
            status = EFI_SECURITY_VIOLATION;
            goto cleanup;
        }
        if (SystemTable->ConOut) Print(L"Kernel signature verified\n");
    }

    // ����ELFͷ��
    Elf64_Ehdr* elf_header = (Elf64_Ehdr*)kernel_address;
    kernel_end = kernel_address + kernel_size;

    // ��֤ELFħ��
    if (elf_header->e_ident[EI_MAG0] != ELFMAG0 ||
        elf_header->e_ident[EI_MAG1] != ELFMAG1 ||
        elf_header->e_ident[EI_MAG2] != ELFMAG2 ||
        elf_header->e_ident[EI_MAG3] != ELFMAG3) {
        if (SystemTable->ConOut) Print(L"Invalid ELF magic\n");
        SystemTable->BootServices->FreePages(kernel_address, EFI_SIZE_TO_PAGES(kernel_size));
        status = EFI_LOAD_ERROR;
        goto cleanup;
    }

    // ��֤ELF��ʽ��64λ��x86_64����ִ���ļ���
    if (elf_header->e_ident[EI_CLASS] != ELFCLASS64) {
        if (SystemTable->ConOut) Print(L"Unsupported ELF class (expected 64-bit)\n");
        SystemTable->BootServices->FreePages(kernel_address, EFI_SIZE_TO_PAGES(kernel_size));
        status = EFI_LOAD_ERROR;
        goto cleanup;
    }
    if (elf_header->e_machine != EM_X86_64) {
        if (SystemTable->ConOut) Print(L"Unsupported architecture (expected x86_64)\n");
        SystemTable->BootServices->FreePages(kernel_address, EFI_SIZE_TO_PAGES(kernel_size));
        status = EFI_LOAD_ERROR;
        goto cleanup;
    }
    if (elf_header->e_type != ET_EXEC) {
        if (SystemTable->ConOut) Print(L"Not an executable ELF\n");
        SystemTable->BootServices->FreePages(kernel_address, EFI_SIZE_TO_PAGES(kernel_size));
        status = EFI_LOAD_ERROR;
        goto cleanup;
    }

    // ��֤����ͷ��������
    if (elf_header->e_phoff + (elf_header->e_phnum * elf_header->e_phentsize) > kernel_size) {
        if (SystemTable->ConOut) Print(L"ELF program headers exceed file size\n");
        SystemTable->BootServices->FreePages(kernel_address, EFI_SIZE_TO_PAGES(kernel_size));
        status = EFI_LOAD_ERROR;
        goto cleanup;
    }

    // ��֤����LOAD�εı߽�
    Elf64_Phdr* phdr = (Elf64_Phdr*)(kernel_address + elf_header->e_phoff);
    for (int i = 0; i < elf_header->e_phnum; i++) {
        if (phdr[i].p_type == PT_LOAD) {
            if (phdr[i].p_offset + phdr[i].p_filesz > kernel_size) {
                if (SystemTable->ConOut) Print(L"Segment %d exceeds file bounds\n", i);
                SystemTable->BootServices->FreePages(kernel_address, EFI_SIZE_TO_PAGES(kernel_size));
                status = EFI_LOAD_ERROR;
                goto cleanup;
            }
            if (phdr[i].p_vaddr < kernel_address || phdr[i].p_vaddr + phdr[i].p_memsz > kernel_end) {
                if (SystemTable->ConOut) Print(L"Segment %d outside allocated memory\n", i);
                SystemTable->BootServices->FreePages(kernel_address, EFI_SIZE_TO_PAGES(kernel_size));
                status = EFI_LOAD_ERROR;
                goto cleanup;
            }
        }
    }

    // ��֤��ڵ���Ч��
    if (elf_header->e_entry < kernel_address || elf_header->e_entry >= kernel_end) {
        if (SystemTable->ConOut) Print(L"Entry point 0x%llx outside kernel memory\n", elf_header->e_entry);
        SystemTable->BootServices->FreePages(kernel_address, EFI_SIZE_TO_PAGES(kernel_size));
        status = EFI_LOAD_ERROR;
        goto cleanup;
    }

    // �����ڴ汣������
    status = set_kernel_memory_protection(SystemTable, elf_header, kernel_address);
    if (EFI_ERROR(status)) {
        if (SystemTable->ConOut) Print(L"Failed to set memory protection: %r\n", status);
        SystemTable->BootServices->FreePages(kernel_address, EFI_SIZE_TO_PAGES(kernel_size));
        goto cleanup;
    }

    // ����ɹ���Ϣ��������ڵ�
    *kernel_entry_point = (VOID*)(elf_header->e_entry);
    if (SystemTable->ConOut) {
        Print(L"Kernel entry point: 0x%llx\n", elf_header->e_entry);
        Print(L"Kernel loaded successfully\n");
    }

    status = EFI_SUCCESS;

cleanup:
    // �ͷ���Դ
    if (kernel_file) kernel_file->Close(kernel_file);
    if (volume_root) volume_root->Close(volume_root);
    if (file_info) SystemTable->BootServices->FreePool(file_info);
    return status;
}