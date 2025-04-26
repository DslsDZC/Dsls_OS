# Dsls_OS

[![Build Status](https://img.shields.io/github/actions/workflow/status/yourusername/Dsls_OS/ci.yml?branch=main)](https://github.com/yourusername/Dsls_OS/actions)

A self-developed modern OS kernel supporting x86_64 architecture:

## 🚀 Core Architecture
![](https://mermaid.ink/svg/eyJjb2RlIjoiZ3JhcGggVERcbiAgICBLZXJuZWwtLT5WTVgvS1ZNXG4gICAgS2VybmVsLS0-TXVsdGljb3JlW1NNUCBQb29saW5nXVxuICAgIEtlcm5lbC0tPk1lbU1ncltTTEFCIEFsbG9jYXRvcl1cbiAgICBLZXJuZWwtLT5TY2hlZFtNTEdRIFNjaGVkdWxlcl1cbiAgICBWaXJ0SU8tLT5FSDEwMDB8UENJIEV0aGVybmV0XVxuICAgIFZpcnRJT0J1cy0tPkZhdDMyL0V4dDJ8QmxvY2sgRGV2aWNlXG4gICAgIiwibWVybWFpZCI6eyJ0aGVtZSI6ImRlZmF1bHQifSwidXBkYXRlRWRpdG9yIjpmYWxzZX0)

## 🛠️ Technical Features
| Module         | Implementation Details                                                |
|----------------|-----------------------------------------------------------------------|
| Memory Mgmt     | SLAB allocator + Page Table Isolation (see `mm/slab.c`)               |
| Process Sched   | Multilevel Feedback Queue (kernel/sched.c)                            |
| Virtualization  | Intel VMX support (arch/x86_64/vmx.c)                               |
| Storage System  | AHCI driver + Ext2/FAT32 dual FS (drivers/ahci.c, fs/ext2.c)          |
| Network Stack   | e1000 driver + TCP/IP stack (drivers/e1000.c)                         |

## 📦 Build Guide
```bash
# Install toolchain
sudo apt install clang-15 lld qemu-system-x86

# Build kernel
make ARCH=x86_64

# Create boot image
make image

# Start QEMU
make run
```
## 🌐 Sample Output
```txt
[  OK  ] Initialized SMP (4 CPUs)
[  OK  ] Memory: 1024MB @ 0x100000
[  OK  ] AHCI Controller: 2 Ports Initialized
[  OK  ] EXT2 FS: Mounted rootfs at /dev/sda1
```
## 🤝 Contribution
1.Fork the repository
2.Create feature branch (git checkout -b feat/new-feature)
3.Commit changes (git commit -m 'Add amazing feature')
4.Push to branch (git push origin feat/new-feature)
5.Open Pull Request

## 📝 License
Apache 2.0 © 2025 Dsls Development Team

## Recommended File Structure
```text
/os
├── Makefile            # Build automation
├── arch
│   └── x86_64
│       ├── boot.asm    # Bootloader
│       ├── smp.c       # Multi-core support
│       └── vmx.c       # Virtualization
├── drivers
│   ├── pci.c          # PCI driver
│   ├── ahci.c         # SATA driver
│   └── e1000.c        # NIC driver
├── fs
│   ├── vfs.c          # Virtual File System
│   ├── ext2.c         # EXT2 implementation
│   └── fat32.c        # FAT32 implementation
├── kernel
│   ├── main.c         # Kernel entry
│   ├── task.c         # Process management
│   ├── sched.c        # Scheduler
│   └── syscall.c      # System calls
├── lib
│   ├── string.c       # String utilities
│   ├── elf.c          # ELF loader
│   └── list.c         # Linked list
├── mm
│   ├── page.c         # Page tables
│   ├── slab.c         # Memory allocation
│   └── vma.c          # Virtual Memory Areas
├── net
│   ├── ip.c           # IP protocol
│   ├── tcp.c          # TCP protocol
│   └── socket.c       # Socket API
└── user
    ├── init.c         # User init
    └── shell.c        # Shell implementation
```
