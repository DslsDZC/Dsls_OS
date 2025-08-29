// graphics.c - 增强版图形初始化
#include "uefi.h"

// 初始化图形模式
EFI_STATUS init_graphics(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE* SystemTable, graphics_info_t* gfx_info) {
    EFI_STATUS status = EFI_SUCCESS;
    EFI_GRAPHICS_OUTPUT_PROTOCOL* gop = NULL;
    EFI_GUID gop_guid = EFI_GRAPHICS_OUTPUT_PROTOCOL_GUID;
    EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL* text_out = NULL;

    // 初始化图形信息结构
    ZeroMem(gfx_info, sizeof(graphics_info_t));

    // 首先确保文本输出可用
    text_out = SystemTable->ConOut;
    if (text_out == NULL) {
        return EFI_DEVICE_ERROR;
    }

    // 定位Graphics Output Protocol
    status = SystemTable->BootServices->LocateProtocol(&gop_guid, NULL, (VOID**)&gop);
    if (EFI_ERROR(status)) {
        log_message(SystemTable, LOG_LEVEL_WARNING, L"Failed to locate GOP: %r\n", status);
        return status;
    }

    // 检查GOP模式是否已初始化
    if (gop->Mode == NULL) {
        log_message(SystemTable, LOG_LEVEL_WARNING, L"GOP mode is not initialized\n");
        return EFI_DEVICE_ERROR;
    }

    // 检查是否有可用模式
    if (gop->Mode->MaxMode == 0) {
        log_message(SystemTable, LOG_LEVEL_WARNING, L"No graphics modes available\n");
        return EFI_NOT_FOUND;
    }

    // 查询当前模式信息
    EFI_GRAPHICS_OUTPUT_MODE_INFORMATION* info = NULL;
    UINTN size_of_info = 0;

    status = gop->QueryMode(gop, gop->Mode->Mode, &size_of_info, &info);
    if (status == EFI_NOT_STARTED) {
        // 如果没有设置模式，则设置默认模式
        status = gop->SetMode(gop, 0);
        if (EFI_ERROR(status)) {
            log_message(SystemTable, LOG_LEVEL_WARNING, L"Failed to set default mode: %r\n", status);
            return status;
        }

        // 重新查询模式信息
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

    // 寻找最佳图形模式
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

    // 遍历所有可用模式
    for (UINT32 i = 0; i < gop->Mode->MaxMode; i++) {
        status = gop->QueryMode(gop, i, &size_of_info, &info);
        if (EFI_ERROR(status)) {
            log_message(SystemTable, LOG_LEVEL_WARNING, L"Failed to query mode %u: %r\n", i);
            continue;
        }

        log_message(SystemTable, LOG_LEVEL_INFO, L"Mode %u: %dx%d (pixel format: %u)\n",
            i, info->HorizontalResolution, info->VerticalResolution, info->PixelFormat);

        // 检查是否为首选分辨率
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

        // 记录最高分辨率模式作为备选
        if (info->HorizontalResolution * info->VerticalResolution > best_width * best_height) {
            best_mode = i;
            best_width = info->HorizontalResolution;
            best_height = info->VerticalResolution;
        }

        SystemTable->BootServices->FreePool(info);
        info = NULL;
    }

    // 如果没有找到首选模式，则使用最高分辨率模式
    if (!mode_found) {
        if (best_width > 0 && best_height > 0) {
            log_message(SystemTable, LOG_LEVEL_INFO, L"Using highest resolution mode: %dx%d\n", best_width, best_height);
            desired_mode = best_mode;
            mode_found = TRUE;
        }
        else {
            // 如果所有模式查询都失败，尝试使用当前模式
            log_message(SystemTable, LOG_LEVEL_INFO, L"Using current mode\n");
            desired_mode = gop->Mode->Mode;
            mode_found = TRUE;
        }
    }

    // 设置选择的模式
    if (mode_found) {
        status = gop->SetMode(gop, desired_mode);
        if (EFI_ERROR(status)) {
            log_message(SystemTable, LOG_LEVEL_WARNING, L"Failed to set graphics mode %u: %r\n", desired_mode, status);
            return status;
        }

        // 获取设置后的模式信息
        status = gop->QueryMode(gop, desired_mode, &size_of_info, &info);
        if (EFI_ERROR(status)) {
            log_message(SystemTable, LOG_LEVEL_WARNING, L"Failed to query set mode %u: %r\n", desired_mode, status);
            return status;
        }

        // 填充图形信息结构
        gfx_info->width = info->HorizontalResolution;
        gfx_info->height = info->VerticalResolution;
        gfx_info->pixels_per_scanline = info->PixelsPerScanLine;
        gfx_info->pixel_format = info->PixelFormat;
        gfx_info->framebuffer_base = gop->Mode->FrameBufferBase;
        gfx_info->framebuffer_size = gop->Mode->FrameBufferSize;
        gfx_info->initialized = TRUE;

        // 验证帧缓冲区有效性
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