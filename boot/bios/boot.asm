[bits 16]
[org 0x7C00]

start:
    cli
    call enable_a20
    lgdt [gdt_descriptor]
    mov eax, cr0
    or al, 1
    mov cr0, eax
    jmp 0x08:pm_entry

enable_a20:
    mov ax, 0x2401
    int 0x15
    ret

[bits 32]
pm_entry:
    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    mov ss, ax
    mov esp, 0x7C00
    call load_second_stage
    jmp 0x08:0x7E00

gdt_start:
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

gdt_descriptor:
    dw gdt_end - gdt_start - 1
    dd gdt_start

gdt_end:

times 510 - ($ - $$) db 0
dw 0xAA55
