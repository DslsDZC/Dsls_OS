#include <uefi.h>

EFI_GRAPHICS_OUTPUT_PROTOCOL *GraphicsOutput = NULL;
FrameBuffer fb;

EFI_STATUS InitGraphics() {
    EFI_STATUS status;
    EFI_GUID gopGuid = EFI_GRAPHICS_OUTPUT_PROTOCOL_GUID;
    
    status = uefi_call_wrapper(BS->LocateProtocol, 3, &gopGuid, NULL, (VOID**)&GraphicsOutput);
    if (EFI_ERROR(status)) {
        Print(L"Error locating GOP: %r\n", status);
        return status;
    }

    UINTN bestMode = 0;
    UINTN bestPixels = 0;
    
    for (UINTN i = 0; i < GraphicsOutput->Mode->MaxMode; i++) {
        EFI_GRAPHICS_OUTPUT_MODE_INFORMATION *info;
        UINTN size;
        
        status = uefi_call_wrapper(GraphicsOutput->QueryMode, 4, GraphicsOutput, i, &size, &info);
        if (EFI_ERROR(status)) continue;
        
        UINTN pixels = info->HorizontalResolution * info->VerticalResolution;
        if (pixels > bestPixels && info->PixelFormat == PixelBlueGreenRedReserved8BitPerColor) {
            bestPixels = pixels;
            bestMode = i;
        }
    }
    
    status = uefi_call_wrapper(GraphicsOutput->SetMode, 2, GraphicsOutput, bestMode);
    if (EFI_ERROR(status)) {
        Print(L"Error setting video mode: %r\n", status);
        return status;
    }
    
    fb.Base = (UINT32*)GraphicsOutput->Mode->FrameBufferBase;
    fb.Width = GraphicsOutput->Mode->Info->HorizontalResolution;
    fb.Height = GraphicsOutput->Mode->Info->VerticalResolution;
    
    return EFI_SUCCESS;
}

VOID ClearScreen(UINT32 color) {
    for (UINTN y = 0; y < fb.Height; y++) {
        for (UINTN x = 0; x < fb.Width; x++) {
            fb.Base[y * fb.Width + x] = color;
        }
    }
}
