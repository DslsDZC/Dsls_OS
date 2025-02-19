# Dsls_OS
Chinese netizens develop their own operating system
# Current file structure

/os/n├── Makefile            # 自动化构建/n├── arch/n│   └── x86_64/n│       ├── boot.asm    # 引导程序/n│       ├── smp.c       # 多核支持/n│       └── vmx.c       # 虚拟化/n├── drivers/n│   ├── pci.c          # PCI驱动/n│   ├── ahci.c         # SATA驱动/n│   └── e1000.c        # 网卡驱动/n├── fs/n│   ├── vfs.c          # 虚拟文件系统/n│   ├── ext2.c         # EXT2实现/n│   └── fat32.c        # FAT32实现/n├── kernel/n│   ├── main.c         # 内核入口/n│   ├── task.c         # 进程管理/n│   ├── sched.c        # 调度器/n│   └── syscall.c      # 系统调用/n├── lib/n│   ├── string.c       # 字符串处理/n│   ├── elf.c          # ELF加载器/n│   └── list.c         # 链表实现/n├── mm/n│   ├── page.c         # 页表管理/n│   ├── slab.c         # 内存分配/n│   └── vma.c          # 虚拟内存区域/n├── net/n│   ├── ip.c           # IP协议/n│   ├── tcp.c          # TCP协议/n│   └── socket.c       # 套接字接口/n└── user/n    ├── init.c         # 用户初始化/n    └── shell.c        # Shell实现