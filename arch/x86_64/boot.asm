[bits 16]
[org 0x7C00]

start:
    cli
    lgdt [gdt_desc]
    mov eax, cr0
    or al, 1
    mov cr0, eax
    jmp 0x08:protected_mode

[bits 32]
protected_mode:
    mov ax, 0x10
    mov ds, ax
    mov ss, ax
    mov esp, 0x90000
    jmp kernel_main

gdt:
    dq 0x0
    dw 0xFFFF, 0x0
    db 0x0, 0x9A, 0xCF, 0x0
    dw 0xFFFF, 0x0
    db 0x0, 0x92, 0xCF, 0x0
gdt_desc:
    dw $ - gdt - 1
    dd gdt

times 510 - ($ - $$) db 0
dw 0xAA55