[bits 32]

load_second_stage:
    mov edi, 0x7E00
    mov ecx, 1
    mov al, 1
    call read_disk
    ret

read_disk:
    mov dx, 0x1F2
    out dx, al
    
    inc dx
    mov al, cl
    out dx, al
    
    inc dx
    shr ecx, 8
    mov al, cl
    out dx, al
    
    inc dx
    shr ecx, 8
    mov al, cl
    out dx, al
    
    inc dx
    shr ecx, 8
    or al, 0xE0
    out dx, al
    
    inc dx
    mov al, 0x20
    out dx, al
    
    .wait:
        in al, dx
        test al, 0x8
        jz .wait
    
    mov ecx, 256
    mov dx, 0x1F0
    rep insw
    ret
