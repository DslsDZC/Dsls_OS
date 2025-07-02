[English](#en) | [Español](#es) | [Français](#fr) | [Deutsch](#de) | [中文](#zh)
# Dsls_OS

[](https://github.com/DslsDZC/Dsls_OS)

一个自研的现代操作系统内核，支持 x86_64 架构。

## 🚀 核心架构

无

## 🛠️ 技术特性

| 模块           | 实现细节                                                     |
|----------------|-----------------------------------------------------------------------|
| 内存管理       | SLAB 分配器 + 页表隔离 (见 mm/slab.c)                                 |
| 进程调度       | 多级反馈队列 (kernel/sched.c)                                        |
| 虚拟化         | Intel VMX 支持 (arch/x86_64/vmx.c)                                   |
| 存储系统       | AHCI 驱动 + Ext2/FAT32 双文件系统 (drivers/ahci.c, fs/ext2.c)         |
| 网络栈         | e1000 驱动 + TCP/IP 协议栈 (drivers/e1000.c)                            |

## 📦 构建指南

以下是构建指南：

```
# 安装工具链
sudo apt install clang-15 lld qemu-system-x86
# 构建内核
make ARCH=x86_64
# 创建启动镜像
make image
# 启动 QEMU
make run
```

## 🌐 输出示例

以下是输出示例：

```
[ OK ] Initialized SMP (4 CPUs)
[ OK ] Memory: 1024MB @ 0x100000
[ OK ] AHCI Controller: 2 Ports Initialized
[ OK ] EXT2 FS: Mounted rootfs at /dev/sda1
```

## 🤝 贡献

1.  Fork 本仓库
2.  创建特性分支 (git checkout -b feat/new-feature)
3.  提交更改 (git commit -m 'Add amazing feature')
4.  推送至分支 (git push origin feat/new-feature)
5.  开启 Pull Request

## 📝 许可证

Apache 2.0 © 2025 Dsls 开发团队

## 📂 推荐文件结构

以下是推荐的文件结构：

```
/os
├── Makefile            # 自动化构建
├── boot
│   ├── bios
│   │   └── boot.asm    # 传统 BIOS 引导程序
│   └── uefi
│       ├── boot.c      # UEFI 主引导程序
│       ├── graphics.c  # UEFI 图形处理
│       ├── loader.c    # UEFI 内核加载
│       └── uefi.h      # UEFI 公共头文件
├── dsls
│   └── x86_64
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
```

---

## 🐛 问题追踪器

**版本：** 1.2
**项目：** DSLS_OS
**日期：** 2023-10-15

### [类别 "未解决的遗留问题"]

**问题编号：** BUG-004
**文件：** kernel/sched.c
**代码行范围：** 50-55
**严重性：** ⚠️ 严重
**类型：** 逻辑错误
**描述：** `schedule()` 函数中不正确的优先级衰减算法
**代码片段：**

```
p->counter = (p->counter >> 2) + p->priority;
```

**分析：** 右移 2 位导致时间片衰减比设计快，建议右移 1 位
**相关文件：** `include/sched.h kernel/task.c`

**问题编号：** BUG-005
**文件：** drivers/ahci.c
**代码行：** 27
**严重性：** ⚠️ 严重
**类型：** 资源泄漏
**描述：** `cl_base` 已分配但未释放
**代码片段：**

```
cl_base = alloc_phys_pages(1);
```

**详情：** 每个端口初始化时泄漏 4KB 物理内存，在 `port->cmd` 禁用后添加 `free_phys_pages`

### [类别 "新发现的关键问题"]

**问题编号：** BUG-006
**文件：** kernel/main.asm
**代码行：** 29
**严重性：** 🔥 致命
**类型：** 链接器错误
**描述：** 未定义的符号 `kernel_main`
**代码片段：**

```
    jmp kernel_main
```

**解决方案：**

1.  在 `linker.ld` 中显式定义入口点
2.  确保 `kernel_main` 的 extern 声明

**问题编号：** BUG-007
**文件：** mm/slab.c
**代码行：** 55
**严重性：** ⚠️ 严重
**类型：** 并发缺陷
**描述：** 自旋锁中缺少内存屏障
**代码片段：**

```
#define spin_unlock(lock) __sync_lock_release(lock)
```

**复现步骤：** 在对称多处理器（SMP）中，缓存不一致可能导致锁状态错误
**修复：**

```
#define spin_unlock(lock) \
    __asm__ __volatile__("" ::: "memory"); \
    __sync_lock_release(lock);
```

### [验证]

**校验和：** 89A3F2C1
**状态：** 未解决
**优先级顺序：** `BUG-006 > BUG-007 > BUG-004 > BUG-005`

## 代码缺陷修复列表 (完整版)

1.  AHCI 驱动程序内存泄漏
    * 文件：drivers/ahci.c 代码行：18-19
    * 症状：cl_base/fis_base 变量重复分配但未释放
    * 修复：移除重复的声明语句，建立全局内存管理链表以跟踪物理页分配

2.  缺少 PCI 桥设备枚举
    * 文件：drivers/pci.c 代码行：68-73
    * 症状：未递归扫描 PCI-PCI 桥的次级总线设备
    * 修复：检测到桥设备时，读取次级总线号并递归调用枚举函数

3.  网卡驱动程序状态竞争
    * 文件：drivers/e1000.c 代码行：45
    * 症状："=while" 语法错误导致寄存器状态检测失败
    * 修复：移除多余的等号，添加 DMA 缓冲环形索引回绕处理

4.  调度器竞争条件
    * 文件：kernel/sched.c 代码行：50
    * 症状：多核环境下任务计数器更新缺少锁保护
    * 修复：在计数器修改前后添加本地中断禁用/启用操作

5.  缺少系统调用存根函数
    * 文件：kernel/syscall.c 代码行：13-14
    * 症状：mmput/vfs_close 函数未实现，导致链接器错误
    * 修复：添加弱符号存根函数以实现基本的内存/文件释放操作

6.  引导加载程序段寄存器错误
    * 文件：arch/x86_64/boot.asm 代码行：21-25
    * 症状：保护模式段选择器设置不完整
    * 修复：补充 fs/gs/ss 段寄存器初始化，修正 GDT 描述符界限长度

7.  SLAB 缓存伪共享
    * 文件：mm/slab.c 代码行：15
    * 症状：多核 CPU 访问同一缓存行导致性能下降
    * 修复：在 slab_cache 结构中添加 64 字节对齐填充

8.  大页面释放异常
    * 文件：mm/page.c 代码行：93
    * 症状：大于 1 页的物理内存释放地址未对齐
    * 修复：计算物理地址基址时执行 PAGE_SIZE 对齐掩码操作

9.  FAT32 长文件名截断
    * 文件：fs/fat32.c 代码行：127-135
    * 症状：VFAT 条目校验和未验证，导致文件名乱码
    * 修复：添加校验和比较逻辑，丢弃校验和失败的长名称条目

10. Ext2 目录遍历缺陷
    * 文件：fs/ext2.c 代码行：88
    * 症状：已删除的文件仍出现在目录列表中
    * 修复：为 inode 号为 0 或未知文件类型的条目添加过滤

11. 交叉编译路径错误
    * 文件：Makefile 代码行：5
    * 症状：内核头文件目录指向不正确
    * 修复：将 "-I/path/to/cross-compiler/include" 更改为 "-I./lib"

12. 汇编指令缺失
    * 文件：arch/x86_64/smp.c 代码行：42
    * 症状：TLB 未刷新，导致虚拟地址映射失效
    * 修复：在 APIC 初始化后插入 "invlpg" 指令序列

13. 缺少 UEFI 内存描述符
    * 文件：kernel/main.c 代码行：34
    * 症状：未定义 EFI_MEMORY_DESCRIPTOR 结构
    * 修复：添加结构定义，包括 Type/PhysAddr/NumPages 字段

14. 虚拟化支持异常
    * 文件：lib/vmx.h 代码行：28-30
    * 症状：未处理 VMXON 区域对齐要求
    * 修复：分配 4KB 对齐的 VMXON 区域并添加 CR0/CR4 掩码验证
