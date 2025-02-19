# Dsls_OS
Chinese netizens develop their own operating system
# Current file structure

/os
├── Makefile            # 自动化构建
├── arch
│   └── x86_64
│       ├── boot.asm    # 引导程序
│       ├── smp.c       # 多核支持
│       └── vmx.c       # 虚拟化
├── drivers
│   ├── pci.c          # PCI驱动
│   ├── ahci.c         # SATA驱动
│   └── e1000.c        # 网卡驱动
├── fs
│   ├── vfs.c          # 虚拟文件系统
│   ├── ext2.c         # EXT2实现
│   └── fat32.c        # FAT32实现
├── kernel
│   ├── main.c         # 内核入口
│   ├── task.c         # 进程管理
│   ├── sched.c        # 调度器
│   └── syscall.c      # 系统调用
├── lib
│   ├── string.c       # 字符串处理
│   ├── elf.c          # ELF加载器
│   └── list.c         # 链表实现
├── mm
│   ├── page.c         # 页表管理
│   ├── slab.c         # 内存分配
│   └── vma.c          # 虚拟内存区域
├── net
│   ├── ip.c           # IP协议
│   ├── tcp.c          # TCP协议
│   └── socket.c       # 套接字接口
└── user
    ├── init.c         # 用户初始化
    └── shell.c        # Shell实现