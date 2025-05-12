[bits 16]
[org 0x7C00]

start:
    cli
    in al, 0x92
    or al, 2
    out 0x92, al
    lgdt [gdt_descriptor]
    mov eax, cr0
    or eax, 0x1
    mov cr0, eax
    jmp 0x08:pm_entry

[bits 32]
pm_entry:
    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    mov ss, ax
    mov esp, 0x7A00
    jmp kernel_main

gdt_start:
    dq 0x0
    dw 0xFFFF     ; 段限长 0-15
    dw 0x0000     ; 基地址 0-15
    db 0x00       ; 基地址 16-23
    db 0x9A       ; P=1, DPL=0, 代码段, 可读
    db 0xCF       ; G=1, D/B=1, 限长 16-19=0xF
    db 0x00       ; 基地址 24-31
    dw 0xFFFF     ; 段限长
    dw 0x0000    ; 基地址
    db 0x00       ; 基地址
    db 0x92       ; P=1, DPL=0, 数据段, 可写
    db 0xCF       ; G=1, D/B=1
    db 0x00       ; 基地址

gdt_descriptor:
    dw gdt_end - gdt_start - 1
    dd gdt_start

gdt_end:

times 510 - ($ - $$) db 0
dw 0xAA55
