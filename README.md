# Dsls_OS

[![License](https://img.shields.io/badge/License-BSD_3--Clause-blue.svg)](https://opensource.org/licenses/BSD-3-Clause)
[![Arch](https://img.shields.io/badge/arch-x86__64%20%7C%20ARMv8-brightgreen)](https://en.wikipedia.org/wiki/X86-64)

Modern OS kernel research project led by Chinese developers, featuring:

## ✨ Core Features
- **Hybrid Architecture**: Native x86_64 support with ARMv8 compatibility
- **Advanced Virtualization**: Intel VMX-based hardware virtualization
- **Dual FS Support**: Integrated Ext2/FAT32 drivers with block device abstraction
- **Smart Scheduling**: MLFQ algorithm with SMP load balancing
- **Security Design**: User/Kernel isolation with NX bit & ASLR
- **Dev-Friendly**: POSIX-compatible syscalls + GDB stub

## 🛠️ Tech Stack
- **Languages**: C11/C++17 (core) + Rust (driver framework)
- **Toolchain**: LLVM 15 + UEFI Toolchain
- **Build System**: CMake + Ninja
- **Testing**: GoogleTest + QEMU testbed

## 📚 Documentation
```text
docs/
├── ARCH.md          # Architecture Design
├── PORTING_GUIDE.md # Platform Porting Guide
├── DRIVER_DEV.md    # Driver Development
└── SECURITY.md      # Security Spec
## 🚀 Quick Start
Prerequisites
GCC 12+ or Clang 15+
QEMU 7.2+ with virtualization
UEFI dev environment (EDK II recommended)
Build Steps