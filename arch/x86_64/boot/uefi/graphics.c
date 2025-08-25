#include "uefi.h"

// 初始化图形模式，不再依赖全局变量ST
EFI_STATUS init_graphics(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE* SystemTable, graphics_info_t* gfx_info) {
    EFI_STATUS status = EFI_SUCCESS;
    EFI_GRAPHICS_OUTPUT_PROTOCOL* gop = NULL;
    EFI_GUID gop_guid = EFI_GRAPHICS_OUTPUT_PROTOCOL_GUID;

    // 定位Graphics Output Protocol
    status = SystemTable->BootServices->LocateProtocol(
        &gop_guid,
        NULL,
        (VOID**)&gop
    );

    if (EFI_ERROR(status)) {
        if (SystemTable->ConOut) Print(L"Failed to locate GOP: %r\n", status);
        return status;
    }

    // 检查GOP模式是否已初始化
    if (gop->Mode == NULL) {
        if (SystemTable->ConOut) Print(L"GOP mode is not initialized\n");
        return EFI_DEVICE_ERROR;
    }

    // 检查是否有可用模式
    if (gop->Mode->MaxMode == 0) {
        if (SystemTable->ConOut) Print(L"No graphics modes available (MaxMode = 0)\n");
        return EFI_NOT_FOUND;
    }

    // 查询当前模式信息
    EFI_GRAPHICS_OUTPUT_MODE_INFORMATION* info = NULL;
    UINTN size_of_info = 0;

    status = gop->QueryMode(
        gop,
        gop->Mode->Mode,
        &size_of_info,
        &info
    );

    if (status == EFI_NOT_STARTED) {
        // 如果没有设置模式，则设置默认模式
        status = gop->SetMode(gop, 0);
        if (EFI_ERROR(status)) {
            if (SystemTable->ConOut) Print(L"Failed to set default mode: %r\n", status);
            return status;
        }

        // 重新查询模式信息并检查状态
        status = gop->QueryMode(gop, 0, &size_of_info, &info);
        if (EFI_ERROR(status)) {
            if (SystemTable->ConOut) Print(L"Failed to query mode 0 after setting: %r\n", status);
            return status;
        }

        // 释放QueryMode分配的内存
        SystemTable->BootServices->FreePool(info);
        info = NULL;
    }
    else if (EFI_ERROR(status)) {
        if (SystemTable->ConOut) Print(L"Failed to query current mode: %r\n", status);
        return status;
    }
    else {
        // 释放QueryMode分配的内存
        SystemTable->BootServices->FreePool(info);
        info = NULL;
    }

    // 尝试设置为最佳模式 (1024x768)
    UINT32 desired_mode = 0;
    BOOLEAN mode_found = FALSE;
    UINT32 best_width = 0, best_height = 0;
    UINT32 best_mode = 0;

    if (SystemTable->ConOut) Print(L"Available graphics modes:\n");

    // 遍历所有可用模式
    for (UINT32 i = 0; i < gop->Mode->MaxMode; i++) {
        status = gop->QueryMode(gop, i, &size_of_info, &info);
        if (EFI_ERROR(status)) {
            if (SystemTable->ConOut) Print(L"Failed to query mode %u: %r\n", i, status);
            continue;
        }

        if (SystemTable->ConOut) Print(L"Mode %u: %dx%d (pixel format: %u)\n",
            i, info->HorizontalResolution, info->VerticalResolution, info->PixelFormat);

        // 检查是否为1024x768模式
        if (info->HorizontalResolution == 1024 && info->VerticalResolution == 768) {
            desired_mode = i;
            mode_found = TRUE;
            best_width = 1024;
            best_height = 768;
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

        // 释放当前模式信息的内存
        SystemTable->BootServices->FreePool(info);
        info = NULL;
    }

    // 如果没有找到1024x768模式，则使用最高分辨率模式
    if (!mode_found) {
        if (best_width > 0 && best_height > 0) {
            if (SystemTable->ConOut) Print(L"1024x768 mode not found, using highest resolution mode: %dx%d\n", best_width, best_height);
            desired_mode = best_mode;
            mode_found = TRUE;
        }
        else {
            // 如果所有模式查询都失败，尝试使用当前模式
            if (SystemTable->ConOut) Print(L"All mode queries failed, trying current mode\n");
            desired_mode = gop->Mode->Mode;
            mode_found = TRUE;
        }
    }

    // 设置选择的模式
    if (mode_found) {
        status = gop->SetMode(gop, desired_mode);
        if (EFI_ERROR(status)) {
            if (SystemTable->ConOut) Print(L"Failed to set graphics mode %u: %r\n", desired_mode, status);
            return status;
        }

        // 验证模式是否切换成功
        if (gop->Mode->Mode != desired_mode) {
            // 如果模式不一致，使用实际模式重新查询
            if (SystemTable->ConOut) Print(L"Warning: SetMode succeeded but mode not switched, using actual mode %u\n", gop->Mode->Mode);
            desired_mode = gop->Mode->Mode;
        }

        // 获取设置后的模式信息
        status = gop->QueryMode(gop, desired_mode, &size_of_info, &info);
        if (EFI_ERROR(status)) {
            if (SystemTable->ConOut) Print(L"Failed to query set mode %u: %r\n", desired_mode, status);
            return status;
        }

        // 填充图形信息结构
        gfx_info->width = info->HorizontalResolution;
        gfx_info->height = info->VerticalResolution;
        gfx_info->pixels_per_scanline = info->PixelsPerScanLine;
        gfx_info->pixel_format = info->PixelFormat;
        gfx_info->framebuffer_base = gop->Mode->FrameBufferBase;
        gfx_info->framebuffer_size = gop->Mode->FrameBufferSize;

        // 验证帧缓冲区有效性
        if (gfx_info->framebuffer_base == 0 || gfx_info->framebuffer_size == 0) {
            if (SystemTable->ConOut) Print(L"Invalid framebuffer: base=0x%llx, size=%llu\n",
                gfx_info->framebuffer_base, gfx_info->framebuffer_size);
            SystemTable->BootServices->FreePool(info);
            return EFI_DEVICE_ERROR;
        }

        // 释放模式信息内存
        SystemTable->BootServices->FreePool(info);
        info = NULL;

        // 打印成功信息
        if (SystemTable->ConOut) Print(L"Graphics mode set successfully: %dx%d\n", gfx_info->width, gfx_info->height);
    }
    else {
        if (SystemTable->ConOut) Print(L"No suitable graphics mode found\n");
        return EFI_NOT_FOUND;
    }

    return EFI_SUCCESS;
}