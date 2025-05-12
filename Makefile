CC := clang
LD := ld.lld
ASM := nasm
OBJCOPY := objcopy

CROSS_COMPILE_INC ?= /path/to/cross-compiler/include
BUILD_DIR := build
ISO_DIR := iso
EFI_DIR := $(ISO_DIR)/EFI/BOOT

TARGET_ELF := os.elf
TARGET_ISO := os.iso
EFI_TARGET := $(EFI_DIR)/BOOTX64.EFI

SRCS := \
    arch/x86_64/boot.asm \
    kernel/main.c \
    mm/page.c \
    kernel/sched.c \
    fs/fat32.c \
    user/shell.c

DEBUG ?= 0
OPTIMIZATION ?= -O2

OBJS := $(addprefix $(BUILD_DIR)/,$(SRCS))
OBJS := $(OBJS:.asm=.o)
OBJS := $(OBJS:.c=.o)
DEPS := $(OBJS:.o=.d)

ASFLAGS := -f elf64

CFLAGS := \
    -target x86_64-unknown-none \
    -nostdlib \
    -ffreestanding \
    -mno-red-zone \
    -I$(CROSS_COMPILE_INC) \
    -Wall \
    -Wextra \
    -Werror \
    -Wno-unused-parameter \
    $(OPTIMIZATION) \
    -MMD -MP

LDFLAGS := -T linker.ld -nostdlib -z max-page-size=0x1000

ifeq ($(DEBUG),1)
CFLAGS += -g -gdwarf-4
ASFLAGS += -F dwarf
endif

.PHONY: all clean run

all: $(TARGET_ISO)

$(BUILD_DIR)/%.o: %.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/%.o: %.asm
	@mkdir -p $(@D)
	$(ASM) $(ASFLAGS) $< -o $@

$(TARGET_ELF): $(OBJS)
	$(LD) $(LDFLAGS) -o $@ $^
	@echo "[LD] Linked ELF: $@"

$(TARGET_ISO): $(TARGET_ELF)
	@mkdir -p $(EFI_DIR)
	$(OBJCOPY) -O binary $< $(EFI_TARGET).bin
	@cp $< $(EFI_TARGET)
	@xorriso -as mkisofs -quiet -o $@ $(ISO_DIR)

clean:
	@rm -rf $(BUILD_DIR) $(ISO_DIR) $(TARGET_ELF) $(TARGET_ISO)

-include $(DEPS)

QEMU := qemu-system-x86_64
OVMF_PATH ?= /usr/share/ovmf/OVMF.fd

run: $(TARGET_ISO)
	@$(QEMU) \
		-bios $(OVMF_PATH) \
		-cdrom $(TARGET_ISO) \
		-net none \
		-smp 4 \
		-m 2G \
		-machine q35 \
		-serial stdio
