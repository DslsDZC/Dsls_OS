[bits 32]
[org 0x7E00]

start:
    mov esi, msg
    call print_string
    call load_kernel
    jmp 0x08:0x100000

print_string:
    mov edx, 0xB8000
    .loop:
        lodsb
        or al, al
        jz .done
        mov [edx], al
        inc edx
        mov byte [edx], 0x0F
        inc edx
        jmp .loop
    .done:
        ret

load_kernel:
    mov edi, 0x100000
    mov ecx, 2
    mov al, 64
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
    .read_sector:
        push ecx
        mov ecx, 256
        rep insw
        pop ecx
        loop .read_sector
    ret

msg db "Loading DSLS_OS...", 0

times 512 - ($ - $$) db 0
