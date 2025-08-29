// graphics.c - ��ǿ��ͼ�γ�ʼ��
#include "uefi.h"

// ��ʼ��ͼ��ģʽ
EFI_STATUS init_graphics(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE* SystemTable, graphics_info_t* gfx_info) {
    EFI_STATUS status = EFI_SUCCESS;
    EFI_GRAPHICS_OUTPUT_PROTOCOL* gop = NULL;
    EFI_GUID gop_guid = EFI_GRAPHICS_OUTPUT_PROTOCOL_GUID;
    EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL* text_out = NULL;

    // ��ʼ��ͼ����Ϣ�ṹ
    ZeroMem(gfx_info, sizeof(graphics_info_t));

    // ����ȷ���ı��������
    text_out = SystemTable->ConOut;
    if (text_out == NULL) {
        return EFI_DEVICE_ERROR;
    }

    // ��λGraphics Output Protocol
    status = SystemTable->BootServices->LocateProtocol(&gop_guid, NULL, (VOID**)&gop);
    if (EFI_ERROR(status)) {
        log_message(SystemTable, LOG_LEVEL_WARNING, L"Failed to locate GOP: %r\n", status);
        return status;
    }

    // ���GOPģʽ�Ƿ��ѳ�ʼ��
    if (gop->Mode == NULL) {
        log_message(SystemTable, LOG_LEVEL_WARNING, L"GOP mode is not initialized\n");
        return EFI_DEVICE_ERROR;
    }

    // ����Ƿ��п���ģʽ
    if (gop->Mode->MaxMode == 0) {
        log_message(SystemTable, LOG_LEVEL_WARNING, L"No graphics modes available\n");
        return EFI_NOT_FOUND;
    }

    // ��ѯ��ǰģʽ��Ϣ
    EFI_GRAPHICS_OUTPUT_MODE_INFORMATION* info = NULL;
    UINTN size_of_info = 0;

    status = gop->QueryMode(gop, gop->Mode->Mode, &size_of_info, &info);
    if (status == EFI_NOT_STARTED) {
        // ���û������ģʽ��������Ĭ��ģʽ
        status = gop->SetMode(gop, 0);
        if (EFI_ERROR(status)) {
            log_message(SystemTable, LOG_LEVEL_WARNING, L"Failed to set default mode: %r\n", status);
            return status;
        }

        // ���²�ѯģʽ��Ϣ
        status = gop->QueryMode(gop, 0, &size_of_info, &info);
        if (EFI_ERROR(status)) {
            log_message(SystemTable, LOG_LEVEL_WARNING, L"Failed to query mode 0: %r\n", status);
            return status;
        }

        SystemTable->BootServices->FreePool(info);
        info = NULL;
    }
    else if (EFI_ERROR(status)) {
        log_message(SystemTable, LOG_LEVEL_WARNING, L"Failed to query current mode: %r\n", status);
        return status;
    }
    else {
        SystemTable->BootServices->FreePool(info);
        info = NULL;
    }

    // Ѱ�����ͼ��ģʽ
    UINT32 desired_mode = 0;
    BOOLEAN mode_found = FALSE;
    UINT32 best_width = 0, best_height = 0;
    UINT32 best_mode = 0;
    UINT32 preferred_resolutions[][2] = {
        {1024, 768},   // XGA
        {1280, 720},   // HD
        {1920, 1080},  // Full HD
        {800, 600},    // SVGA
        {640, 480}     // VGA
    };

    log_message(SystemTable, LOG_LEVEL_INFO, L"Available graphics modes:\n");

    // �������п���ģʽ
    for (UINT32 i = 0; i < gop->Mode->MaxMode; i++) {
        status = gop->QueryMode(gop, i, &size_of_info, &info);
        if (EFI_ERROR(status)) {
            log_message(SystemTable, LOG_LEVEL_WARNING, L"Failed to query mode %u: %r\n", i);
            continue;
        }

        log_message(SystemTable, LOG_LEVEL_INFO, L"Mode %u: %dx%d (pixel format: %u)\n",
            i, info->HorizontalResolution, info->VerticalResolution, info->PixelFormat);

        // ����Ƿ�Ϊ��ѡ�ֱ���
        for (UINTN j = 0; j < ARRAY_SIZE(preferred_resolutions); j++) {
            if (info->HorizontalResolution == preferred_resolutions[j][0] &&
                info->VerticalResolution == preferred_resolutions[j][1]) {
                desired_mode = i;
                mode_found = TRUE;
                best_width = info->HorizontalResolution;
                best_height = info->VerticalResolution;
                break;
            }
        }

        if (mode_found) {
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

        SystemTable->BootServices->FreePool(info);
        info = NULL;
    }

    // ���û���ҵ���ѡģʽ����ʹ����߷ֱ���ģʽ
    if (!mode_found) {
        if (best_width > 0 && best_height > 0) {
            log_message(SystemTable, LOG_LEVEL_INFO, L"Using highest resolution mode: %dx%d\n", best_width, best_height);
            desired_mode = best_mode;
            mode_found = TRUE;
        }
        else {
            // �������ģʽ��ѯ��ʧ�ܣ�����ʹ�õ�ǰģʽ
            log_message(SystemTable, LOG_LEVEL_INFO, L"Using current mode\n");
            desired_mode = gop->Mode->Mode;
            mode_found = TRUE;
        }
    }

    // ����ѡ���ģʽ
    if (mode_found) {
        status = gop->SetMode(gop, desired_mode);
        if (EFI_ERROR(status)) {
            log_message(SystemTable, LOG_LEVEL_WARNING, L"Failed to set graphics mode %u: %r\n", desired_mode, status);
            return status;
        }

        // ��ȡ���ú��ģʽ��Ϣ
        status = gop->QueryMode(gop, desired_mode, &size_of_info, &info);
        if (EFI_ERROR(status)) {
            log_message(SystemTable, LOG_LEVEL_WARNING, L"Failed to query set mode %u: %r\n", desired_mode, status);
            return status;
        }

        // ���ͼ����Ϣ�ṹ
        gfx_info->width = info->HorizontalResolution;
        gfx_info->height = info->VerticalResolution;
        gfx_info->pixels_per_scanline = info->PixelsPerScanLine;
        gfx_info->pixel_format = info->PixelFormat;
        gfx_info->framebuffer_base = gop->Mode->FrameBufferBase;
        gfx_info->framebuffer_size = gop->Mode->FrameBufferSize;
        gfx_info->initialized = TRUE;

        // ��֤֡��������Ч��
        if (gfx_info->framebuffer_base == 0 || gfx_info->framebuffer_size == 0) {
            log_message(SystemTable, LOG_LEVEL_WARNING, L"Invalid framebuffer\n");
            SystemTable->BootServices->FreePool(info);
            return EFI_DEVICE_ERROR;
        }

        SystemTable->BootServices->FreePool(info);
        info = NULL;

        log_message(SystemTable, LOG_LEVEL_INFO, L"Graphics mode set successfully: %dx%d\n",
            gfx_info->width, gfx_info->height);
    }
    else {
        log_message(SystemTable, LOG_LEVEL_WARNING, L"No suitable graphics mode found\n");
        return EFI_NOT_FOUND;
    }

    return EFI_SUCCESS;
}
}