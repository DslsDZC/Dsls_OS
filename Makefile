CC = clang
LD = ld.lld
CFLAGS = -target x86_64-unknown-none -nostdlib -ffreestanding -mno-red-zone -I/path/to/cross-compiler/include

SRCS = arch/x86_64/boot.asm \
       kernel/main.c \
       mm/page.c \
       kernel/sched.c \
       fs/fat32.c \
       user/shell.c

OBJS = $(patsubst %.asm,%.o,$(patsubst %.c,%.o,$(SRCS)))

all: os.iso

%.o: %.asm
    nasm -f elf64 $< -o $@

%.o: %.c
    $(CC) $(CFLAGS) -c $< -o $@

os.elf: $(OBJS)
    $(LD) -T linker.ld -o $@ $^

os.iso: os.elf
    objcopy -O binary os.elf os.bin
    mkdir -p iso/EFI/BOOT
    cp os.bin iso/EFI/BOOT/BOOTX64.EFI
    xorriso -as mkisofs -o $@ iso

clean:
    rm -f $(OBJS) os.*