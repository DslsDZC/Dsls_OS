# Dsls_OS

[![License](https://img.shields.io/badge/License-BSD_3--Clause-blue.svg)](https://opensource.org/licenses/BSD-3-Clause)
[![Build Status](https://img.shields.io/github/actions/workflow/status/yourusername/Dsls_OS/ci.yml?branch=main)](https://github.com/yourusername/Dsls_OS/actions)

自研现代操作系统内核，支持x86_64架构：

## 🚀 核心架构
![](https://mermaid.ink/svg/eyJjb2RlIjoiZ3JhcGggVERcbiAgICBLZXJuZWwtLT5WTVgvS1ZNXG4gICAgS2VybmVsLS0-TXVsdGljb3JlW1NNUCBQb29saW5nXVxuICAgIEtlcm5lbC0tPk1lbU1ncltTTEFCIEFsbG9jYXRvcl1cbiAgICBLZXJuZWwtLT5TY2hlZFtNTEdRIFNjaGVkdWxlcl1cbiAgICBWaXJ0SU8tLT5FSDEwMDB8UENJIEV0aGVybmV0XVxuICAgIFZpcnRJT0J1cy0tPkZhdDMyL0V4dDJ8QmxvY2sgRGV2aWNlXG4gICAgIiwibWVybWFpZCI6eyJ0aGVtZSI6ImRlZmF1bHQifSwidXBkYXRlRWRpdG9yIjpmYWxzZX0)

## 🛠️ 技术特性
| 模块          | 实现细节                                                                 |
|---------------|--------------------------------------------------------------------------|
| 内存管理       | SLAB分配器 + 页表隔离 (见`mm/slab.c`)                                    |
| 进程调度       | 多级反馈队列 (kernel/sched.c)                                            |
| 虚拟化        | Intel VMX支持 (arch/x86_64/vmx.c)                                      |
| 存储系统       | AHCI驱动 + Ext2/FAT32双文件系统 (drivers/ahci.c, fs/ext2.c)              |
| 网络协议栈     | e1000网卡驱动 + TCP/IP协议栈 (drivers/e1000.c)                           |

## 📦 编译指南
```bash
# 安装工具链
sudo apt install clang-15 lld qemu-system-x86

# 编译内核
make ARCH=x86_64

# 生成启动镜像
make image

# 启动QEMU
make run
```

## 🌐 示例输出
```txt
[  OK  ] Initialized SMP (4 CPUs)
[  OK  ] Memory: 1024MB @ 0x100000
[  OK  ] AHCI Controller: 2 Ports Initialized
[  OK  ] EXT2 FS: Mounted rootfs at /dev/sda1
```
## 🤝 贡献流程
1.Fork项目仓库
2.创建特性分支 (git checkout -b feat/new-feature)
3.提交修改 (git commit -m 'Add amazing feature')
4.推送到远程分支 (git push origin feat/new-feature)
5.创建Pull Request

## 📄 许可证
BSD 3-Clause License © 2024 DSLS Development Team

##实际文件结构建议按以下方式组织：
```text
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

    