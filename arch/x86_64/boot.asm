[bits 16]
[org 0x7C00]

start:
    cli
    in al, 0x92
    or al, 2
    out 0x92, al
    
    lgdt [gdt_desc]
    mov eax, cr0
    or al, 1
    mov cr0, eax
    jmp 0x08:protected_mode

[bits 32]
protected_mode:
    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    mov ss, ax
    mov esp, 0x7A00
    lidt [idt_desc]
    mov byte [0xB8000], 'A'
    mov byte [0xB8001], 0x0F
    jmp kernel_main
    cli
    hlt
    jmp $

gdt:
    dq 0x0
    dw 0xFFFF
    dw 0x0000
    db 0x00
    db 0x9A
    db 0xCF
    db 0x00
    dw 0xFFFF
    dw 0x0000
    db 0x00
    db 0x92
    db 0xCF
    db 0x00

gdt_desc:
    dw $ - gdt - 1
    dd gdt

idt_desc:
    dw 0
    dd 0

times 510 - ($ - $$) db 0
dw 0xAA55
