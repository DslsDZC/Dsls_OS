#include "uefi.h"

EFI_PHYSICAL_ADDRESS KernelEntryPoint = KERNEL_LOAD_ADDRESS;
UINTN KernelSize = 0;

EFI_STATUS LoadKernel(EFI_HANDLE ImageHandle) {
    EFI_STATUS status;
    EFI_LOADED_IMAGE_PROTOCOL *LoadedImage;
    EFI_GUID lipGuid = EFI_LOADED_IMAGE_PROTOCOL_GUID;
    
    status = uefi_call_wrapper(BS->HandleProtocol, 3, ImageHandle, &lipGuid, (VOID**)&LoadedImage);
    if (EFI_ERROR(status)) {
        Print(L"Error getting loaded image protocol: %r\n", status);
        return status;
    }
    
    EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *Fs;
    EFI_GUID fsGuid = EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID;
    status = uefi_call_wrapper(BS->HandleProtocol, 3, LoadedImage->DeviceHandle, &fsGuid, (VOID**)&Fs);
    if (EFI_ERROR(status)) {
        Print(L"Error getting file system protocol: %r\n", status);
        return status;
    }
    
    EFI_FILE_PROTOCOL *Root;
    status = uefi_call_wrapper(Fs->OpenVolume, 2, Fs, &Root);
    if (EFI_ERROR(status)) {
        Print(L"Error opening volume: %r\n", status);
        return status;
    }
    
    EFI_FILE_PROTOCOL *KernelFile;
    status = uefi_call_wrapper(Root->Open, 5, Root, &KernelFile, L"kernel.elf", 
                              EFI_FILE_MODE_READ, EFI_FILE_READ_ONLY);
    if (EFI_ERROR(status)) {
        Print(L"Error opening kernel file: %r\n", status);
        Root->Close(Root);
        return status;
    }
    
    EFI_FILE_INFO *FileInfo;
    UINTN InfoSize = 0;
    status = uefi_call_wrapper(KernelFile->GetInfo, 4, KernelFile, &gEfiFileInfoGuid, &InfoSize, NULL);
    if (status != EFI_BUFFER_TOO_SMALL) {
        Print(L"Error getting file info size: %r\n", status);
        KernelFile->Close(KernelFile);
        Root->Close(Root);
        return status;
    }
    
    status = uefi_call_wrapper(BS->AllocatePool, 3, EfiLoaderData, InfoSize, (VOID**)&FileInfo);
    if (EFI_ERROR(status)) {
        Print(L"Error allocating memory for file info: %r\n", status);
        KernelFile->Close(KernelFile);
        Root->Close(Root);
        return status;
    }
    
    status = uefi_call_wrapper(KernelFile->GetInfo, 4, KernelFile, &gEfiFileInfoGuid, &InfoSize, FileInfo);
    if (EFI_ERROR(status)) {
        Print(L"Error getting file info: %r\n", status);
        BS->FreePool(FileInfo);
        KernelFile->Close(KernelFile);
        Root->Close(Root);
        return status;
    }
    
    KernelSize = FileInfo->FileSize;
    BS->FreePool(FileInfo);
    
    status = uefi_call_wrapper(BS->AllocatePages, 4, AllocateAddress, EfiLoaderData, 
                              EFI_SIZE_TO_PAGES(KernelSize), &KernelEntryPoint);
    if (EFI_ERROR(status)) {
        Print(L"Error allocating kernel memory: %r\n", status);
        KernelFile->Close(KernelFile);
        Root->Close(Root);
        return status;
    }
    
    status = uefi_call_wrapper(KernelFile->Read, 3, KernelFile, &KernelSize, (VOID*)KernelEntryPoint);
    if (EFI_ERROR(status)) {
        Print(L"Error reading kernel file: %r\n", status);
        BS->FreePages(KernelEntryPoint, EFI_SIZE_TO_PAGES(KernelSize));
        KernelFile->Close(KernelFile);
        Root->Close(Root);
        return status;
    }
    
    KernelFile->Close(KernelFile);
    Root->Close(Root);
    
    return EFI_SUCCESS;
}

EFI_STATUS GetMemoryMap(MemoryMapInfo *mmap) {
    EFI_STATUS status;
    status = uefi_call_wrapper(BS->GetMemoryMap, 5, &mmap->Size, NULL, 
                              &mmap->MapKey, &mmap->DescriptorSize, &mmap->DescriptorVersion);
    if (status != EFI_BUFFER_TOO_SMALL) {
        return status;
    }
    
    mmap->Size += 2 * mmap->DescriptorSize;
    status = uefi_call_wrapper(BS->AllocatePool, 3, EfiLoaderData, mmap->Size, (VOID**)&mmap->Map);
    if (EFI_ERROR(status)) {
        return status;
    }
    
    status = uefi_call_wrapper(BS->GetMemoryMap, 5, &mmap->Size, mmap->Map, 
                              &mmap->MapKey, &mmap->DescriptorSize, &mmap->DescriptorVersion);
    return status;
}

EFI_STATUS ExitBootServices(EFI_HANDLE ImageHandle, MemoryMapInfo *mmap) {
    return uefi_call_wrapper(BS->ExitBootServices, 2, ImageHandle, mmap->MapKey);
}
