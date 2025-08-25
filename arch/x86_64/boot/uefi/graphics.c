#include "uefi.h"

// ��ʼ��ͼ��ģʽ����������ȫ�ֱ���ST
EFI_STATUS init_graphics(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE* SystemTable, graphics_info_t* gfx_info) {
    EFI_STATUS status = EFI_SUCCESS;
    EFI_GRAPHICS_OUTPUT_PROTOCOL* gop = NULL;
    EFI_GUID gop_guid = EFI_GRAPHICS_OUTPUT_PROTOCOL_GUID;

    // ��λGraphics Output Protocol
    status = SystemTable->BootServices->LocateProtocol(
        &gop_guid,
        NULL,
        (VOID**)&gop
    );

    if (EFI_ERROR(status)) {
        if (SystemTable->ConOut) Print(L"Failed to locate GOP: %r\n", status);
        return status;
    }

    // ���GOPģʽ�Ƿ��ѳ�ʼ��
    if (gop->Mode == NULL) {
        if (SystemTable->ConOut) Print(L"GOP mode is not initialized\n");
        return EFI_DEVICE_ERROR;
    }

    // ����Ƿ��п���ģʽ
    if (gop->Mode->MaxMode == 0) {
        if (SystemTable->ConOut) Print(L"No graphics modes available (MaxMode = 0)\n");
        return EFI_NOT_FOUND;
    }

    // ��ѯ��ǰģʽ��Ϣ
    EFI_GRAPHICS_OUTPUT_MODE_INFORMATION* info = NULL;
    UINTN size_of_info = 0;

    status = gop->QueryMode(
        gop,
        gop->Mode->Mode,
        &size_of_info,
        &info
    );

    if (status == EFI_NOT_STARTED) {
        // ���û������ģʽ��������Ĭ��ģʽ
        status = gop->SetMode(gop, 0);
        if (EFI_ERROR(status)) {
            if (SystemTable->ConOut) Print(L"Failed to set default mode: %r\n", status);
            return status;
        }

        // ���²�ѯģʽ��Ϣ�����״̬
        status = gop->QueryMode(gop, 0, &size_of_info, &info);
        if (EFI_ERROR(status)) {
            if (SystemTable->ConOut) Print(L"Failed to query mode 0 after setting: %r\n", status);
            return status;
        }

        // �ͷ�QueryMode������ڴ�
        SystemTable->BootServices->FreePool(info);
        info = NULL;
    }
    else if (EFI_ERROR(status)) {
        if (SystemTable->ConOut) Print(L"Failed to query current mode: %r\n", status);
        return status;
    }
    else {
        // �ͷ�QueryMode������ڴ�
        SystemTable->BootServices->FreePool(info);
        info = NULL;
    }

    // ��������Ϊ���ģʽ (1024x768)
    UINT32 desired_mode = 0;
    BOOLEAN mode_found = FALSE;
    UINT32 best_width = 0, best_height = 0;
    UINT32 best_mode = 0;

    if (SystemTable->ConOut) Print(L"Available graphics modes:\n");

    // �������п���ģʽ
    for (UINT32 i = 0; i < gop->Mode->MaxMode; i++) {
        status = gop->QueryMode(gop, i, &size_of_info, &info);
        if (EFI_ERROR(status)) {
            if (SystemTable->ConOut) Print(L"Failed to query mode %u: %r\n", i, status);
            continue;
        }

        if (SystemTable->ConOut) Print(L"Mode %u: %dx%d (pixel format: %u)\n",
            i, info->HorizontalResolution, info->VerticalResolution, info->PixelFormat);

        // ����Ƿ�Ϊ1024x768ģʽ
        if (info->HorizontalResolution == 1024 && info->VerticalResolution == 768) {
            desired_mode = i;
            mode_found = TRUE;
            best_width = 1024;
            best_height = 768;
            SystemTable->BootServices->FreePool(info);
            info = NULL;
            break;
        }

        // ��¼��߷ֱ���ģʽ��Ϊ��ѡ
        if (info->HorizontalResolution * info->VerticalResolution > best_width * best_height) {
            best_mode = i;
            best_width = info->HorizontalResolution;
            best_height = info->VerticalResolution;
        }

        // �ͷŵ�ǰģʽ��Ϣ���ڴ�
        SystemTable->BootServices->FreePool(info);
        info = NULL;
    }

    // ���û���ҵ�1024x768ģʽ����ʹ����߷ֱ���ģʽ
    if (!mode_found) {
        if (best_width > 0 && best_height > 0) {
            if (SystemTable->ConOut) Print(L"1024x768 mode not found, using highest resolution mode: %dx%d\n", best_width, best_height);
            desired_mode = best_mode;
            mode_found = TRUE;
        }
        else {
            // �������ģʽ��ѯ��ʧ�ܣ�����ʹ�õ�ǰģʽ
            if (SystemTable->ConOut) Print(L"All mode queries failed, trying current mode\n");
            desired_mode = gop->Mode->Mode;
            mode_found = TRUE;
        }
    }

    // ����ѡ���ģʽ
    if (mode_found) {
        status = gop->SetMode(gop, desired_mode);
        if (EFI_ERROR(status)) {
            if (SystemTable->ConOut) Print(L"Failed to set graphics mode %u: %r\n", desired_mode, status);
            return status;
        }

        // ��֤ģʽ�Ƿ��л��ɹ�
        if (gop->Mode->Mode != desired_mode) {
            // ���ģʽ��һ�£�ʹ��ʵ��ģʽ���²�ѯ
            if (SystemTable->ConOut) Print(L"Warning: SetMode succeeded but mode not switched, using actual mode %u\n", gop->Mode->Mode);
            desired_mode = gop->Mode->Mode;
        }

        // ��ȡ���ú��ģʽ��Ϣ
        status = gop->QueryMode(gop, desired_mode, &size_of_info, &info);
        if (EFI_ERROR(status)) {
            if (SystemTable->ConOut) Print(L"Failed to query set mode %u: %r\n", desired_mode, status);
            return status;
        }

        // ���ͼ����Ϣ�ṹ
        gfx_info->width = info->HorizontalResolution;
        gfx_info->height = info->VerticalResolution;
        gfx_info->pixels_per_scanline = info->PixelsPerScanLine;
        gfx_info->pixel_format = info->PixelFormat;
        gfx_info->framebuffer_base = gop->Mode->FrameBufferBase;
        gfx_info->framebuffer_size = gop->Mode->FrameBufferSize;

        // ��֤֡��������Ч��
        if (gfx_info->framebuffer_base == 0 || gfx_info->framebuffer_size == 0) {
            if (SystemTable->ConOut) Print(L"Invalid framebuffer: base=0x%llx, size=%llu\n",
                gfx_info->framebuffer_base, gfx_info->framebuffer_size);
            SystemTable->BootServices->FreePool(info);
            return EFI_DEVICE_ERROR;
        }

        // �ͷ�ģʽ��Ϣ�ڴ�
        SystemTable->BootServices->FreePool(info);
        info = NULL;

        // ��ӡ�ɹ���Ϣ
        if (SystemTable->ConOut) Print(L"Graphics mode set successfully: %dx%d\n", gfx_info->width, gfx_info->height);
    }
    else {
        if (SystemTable->ConOut) Print(L"No suitable graphics mode found\n");
        return EFI_NOT_FOUND;
    }

    return EFI_SUCCESS;
}