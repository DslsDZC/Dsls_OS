BUILD_MODE ?= uefi
QEMU := qemu-system-x86_64
OVMF_PATH ?= /usr/share/ovmf/OVMF.fd
BUILD_DIR := build
ISO_DIR := $(BUILD_DIR)/iso
KERNEL := $(BUILD_DIR)/kernel.elf

BIOS_ASM := nasm
BIOS_LD := ld.lld
BIOS_DIR := boot/bios

UEFI_CC := x86_64-w64-mingw32-gcc
UEFI_LD := x86_64-w64-mingw32-ld
UEFI_OBJCOPY := objcopy
UEFI_DIR := boot/uefi
GNUEB_DIR ?= /usr/local/gnuefi

.PHONY: all clean run bios uefi kernel

all: $(BUILD_MODE)

bios: $(BUILD_DIR)/bios.img

uefi: $(BUILD_DIR)/uefi.iso

kernel: $(KERNEL)

BIOS_OBJS := \
    $(BUILD_DIR)/bios/boot.o \
    $(BUILD_DIR)/bios/loader.o

$(BUILD_DIR)/bios/%.o: $(BIOS_DIR)/%.asm
    @mkdir -p $(@D)
    $(BIOS_ASM) -f bin $< -o $@

$(BUILD_DIR)/bios.bin: $(BIOS_OBJS)
    cat $^ > $@
    truncate -s 512 $@

$(BUILD_DIR)/bios.img: $(BUILD_DIR)/bios.bin $(KERNEL)
    dd if=/dev/zero of=$@ bs=1M count=64
    dd if=$< of=$@ conv=notrunc
    dd if=$(KERNEL) of=$@ bs=1M seek=1 conv=notrunc

UEFI_SRCS := \
    $(UEFI_DIR)/boot.c \
    $(UEFI_DIR)/graphics.c \
    $(UEFI_DIR)/loader.c

UEFI_OBJS := $(addprefix $(BUILD_DIR)/uefi/,$(notdir $(UEFI_SRCS:.c=.o)))
EFI_TARGET := $(ISO_DIR)/EFI/BOOT/BOOTX64.EFI

$(BUILD_DIR)/uefi/%.o: $(UEFI_DIR)/%.c
    @mkdir -p $(@D)
    $(UEFI_CC) -Wall -Wextra -e efi_main -nostdinc -nostdlib -fno-builtin -fno-stack-protector \
        -I$(GNUEB_DIR)/inc -I$(GNUEB_DIR)/inc/x86_64 -c $< -o $@

$(BUILD_DIR)/uefi/BOOTX64.EFI: $(UEFI_OBJS)
    $(UEFI_LD) -T $(GNUEB_DIR)/lib/elf_x86_64_efi.lds -shared -Bsymbolic \
        -L$(GNUEB_DIR)/lib $(GNUEB_DIR)/lib/crt0-efi-x86_64.o \
        -o $@ $^ -lgnuefi -lefi
    $(UEFI_OBJCOPY) -j .text -j .sdata -j .data -j .dynamic -j .dynsym -j .rel \
        -j .rela -j .reloc --target=efi-app-x86_64 $@

$(BUILD_DIR)/uefi.iso: $(BUILD_DIR)/uefi/BOOTX64.EFI $(KERNEL)
    @mkdir -p $(ISO_DIR)/EFI/BOOT
    @cp $< $(EFI_TARGET)
    @cp $(KERNEL) $(ISO_DIR)
    xorriso -as mkisofs -R -J -o $@ $(ISO_DIR)

KERNEL_SRCS := kernel/kernel.c
KERNEL_CC := clang
KERNEL_LD := ld.lld

$(BUILD_DIR)/kernel.o: $(KERNEL_SRCS)
    @mkdir -p $(@D)
    $(KERNEL_CC) -target x86_64-unknown-none -nostdlib -ffreestanding \
        -mno-red-zone -c $< -o $@

$(KERNEL): $(BUILD_DIR)/kernel.o
    $(KERNEL_LD) -T linker.ld -nostdlib -z max-page-size=0x1000 -o $@ $^

clean:
    rm -rf $(BUILD_DIR)

run-bios: bios
    $(QEMU) -drive format=raw,file=$(BUILD_DIR)/bios.img -serial stdio

run-uefi: uefi
    $(QEMU) -bios $(OVMF_PATH) -cdrom $(BUILD_DIR)/uefi.iso -net none -serial stdio

run:
ifeq ($(BUILD_MODE),bios)
    $(MAKE) run-bios
else
    $(MAKE) run-uefi
endif
