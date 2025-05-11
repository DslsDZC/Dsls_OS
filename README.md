[English](#en) | [Spanish](#es) | [French](#fr) | [German](#de) | [Chinese](#zh)

# Dsls_OS

[](https://github.com/DslsDZC/Dsls_OS)

A self-developed modern OS kernel supporting x86_64 architecture.

## 🚀 Core Architecture

(This section should contain a detailed description of the core architecture of Dsls_OS, such as: monolithic kernel, microkernel, or other architectural models, and the interaction of key subsystems.)

## 🛠️ Technical Features

| Module           | Implementation Details                                                |
|----------------|-----------------------------------------------------------------------|
| Memory Mgmt     | SLAB allocator + Page Table Isolation (see mm/slab.c)               |
| Process Sched   | Multilevel Feedback Queue (kernel/sched.c)                            |
| Virtualization  | Intel VMX support (arch/x86_64/vmx.c)                               |
| Storage System  | AHCI driver + Ext2/FAT32 dual FS (drivers/ahci.c, fs/ext2.c)          |
| Network Stack   | e1000 driver + TCP/IP stack (drivers/e1000.c)                         |

## 📦 Build Guide

Here is the build guide:

```bash
# Install toolchain sudo apt install clang-15 lld qemu-system-x86 # Build kernel make ARCH=x86_64 # Create boot image make image # Start QEMU make run
```

## 🌐 Sample Output

Here is the sample output:

```text
[ OK ] Initialized SMP (4 CPUs) [ OK ] Memory: 1024MB @ 0x100000 [ OK ] AHCI Controller: 2 Ports Initialized [ OK ] EXT2 FS: Mounted rootfs at /dev/sda1
```

## 🤝 Contribution

1.  Fork the repository
2.  Create feature branch (git checkout -b feat/new-feature)
3.  Commit changes (git commit -m 'Add amazing feature')
4.  Push to branch (git push origin feat/new-feature)
5.  Open Pull Request

## 📝 License

Apache 2.0 © 2025 Dsls Development Team

## 📂 Recommended File Structure

Here is the recommended file structure:

```text
/os ├── Makefile # Build automation ├── arch │ └── x86_64 │ ├── boot.asm # Bootloader │ ├── smp.c # Multi-core support │ └── vmx.c # Virtualization ├── drivers │ ├── pci.c # PCI driver │ ├── ahci.c # SATA driver │ └── e1000.c # NIC driver ├── fs │ ├── vfs.c # Virtual File System │ ├── ext2.c # EXT2 implementation │ └── fat32.c # FAT32 implementation ├── kernel │ ├── main.c # Kernel entry │ ├── task.c # Process management │ ├── sched.c # Scheduler │ └── syscall.c # System calls ├── lib │ ├── string.c # String utilities │ ├── elf.c # ELF loader │ └── list.c # Linked list ├── mm │ ├── page.c # Page tables │ ├── slab.c # Memory allocation │ └── vma.c # Virtual Memory Areas ├── net │ ├── ip.c # IP protocol │ ├── tcp.c # TCP protocol │ └── socket.c # Socket API └── user ├── init.c # User init └── shell.c # Shell implementation
```

---

## 🐛 Issue Tracker

**VERSION:** 1.2
**PROJECT:** DSLS_OS
**DATE:** 2023-10-15

### [CATEGORY "Unresolved Legacy Issues"]

**ISSUE:** BUG-004
**FILE:** kernel/sched.c
**LINE_RANGE:** 50-55
**SEVERITY:** ⚠️ CRITICAL
**TYPE:** Logic Error
**DESC:** Incorrect priority decay algorithm in `schedule()`
**CODE_SNIPPET:**

```c
p->counter = (p->counter >> 2) + p->priority;
```

**ANALYSIS:** Right shift by 2 bits causes faster timeslice decay than designed, recommend shift by 1 bit
**RELATED_FILES:** `include/sched.h kernel/task.c`

**ISSUE:** BUG-005
**FILE:** drivers/ahci.c
**LINE:** 27
**SEVERITY:** ⚠️ CRITICAL
**TYPE:** Resource Leak
**DESC:** `cl_base` allocated but not released
**CODE_SNIPPET:**

```c
cl_base = alloc_phys_pages(1);
```

**DETAILS:** 4KB physical memory leak per port init, add `free_phys_pages` after `port->cmd` disabled

### [CATEGORY "New Critical Findings"]

**ISSUE:** BUG-006
**FILE:** kernel/main.asm
**LINE:** 29
**SEVERITY:** 🔥 FATAL
**TYPE:** Linker Error
**DESC:** Undefined symbol `kernel_main`
**CODE_SNIPPET:**

```assembly
    jmp kernel_main
```

**SOLUTION:**

1.  Explicitly define entry point in `linker.ld`
2.  Ensure extern declaration for `kernel_main`

**ISSUE:** BUG-007
**FILE:** mm/slab.c
**LINE:** 55
**SEVERITY:** ⚠️ CRITICAL
**TYPE:** Concurrency Defect
**DESC:** Missing memory barrier in spinlock
**CODE_SNIPPET:**

```c
#define spin_unlock(lock) __sync_lock_release(lock)
```

**REPRODUCE:** Cache incoherency may cause lock state errors in SMP
**FIX:**

```c
#define spin_unlock(lock) \
    __asm__ __volatile__("" ::: "memory"); \
    __sync_lock_release(lock);
```

### [VALIDATION]

**CHECKSUM:** 89A3F2C1
**STATUS:** UNRESOLVED
**PRIORITY_ORDER:** `BUG-006 > BUG-007 > BUG-004 > BUG-005`

### [CATEGORY "Code Defect Fix List (Full Version)"]


###Driver Module Fixes             =


1. AHCI driver memory leak
- File: drivers/ahci.c Lines 18-19
- Symptom: cl_base/fis_base variables repeatedly allocated but not freed
- Fix: Remove duplicate declaration statements, establish a global memory management linked list to track physical page allocation

2. Missing PCI bridge device enumeration
- File: drivers/pci.c Lines 68-73
- Symptom: Secondary bus devices of PCI-PCI bridge are not recursively scanned
- Fix: When a bridge device is detected, read the secondary bus number and recursively call the enumeration function

3. Network card driver state race
- File: drivers/e1000.c Line 45
- Symptom: "=while" syntax error causes register state detection to fail
- Fix: Remove redundant equals sign, add DMA buffer ring index wrap-around handling


###Kernel Core Fixes


4. Scheduler race condition
- File: kernel/sched.c Line 50
- Symptom: Task counter update lacks lock protection in multi-core environment
- Fix: Add local interrupt disable/enable operations before and after the counter modification

5. Missing system call stub functions
- File: kernel/syscall.c Lines 13-14
- Symptom: mmput/vfs_close functions are not implemented, causing linker errors
- Fix: Add weak symbol stub functions to implement basic memory/file release operations

6. Bootloader segment register error
- File: arch/x86_64/boot.asm Lines 21-25
- Symptom: Protected mode segment selector settings are incomplete
- Fix: Supplement fs/gs/ss segment register initialization, correct GDT descriptor limit length


###Memory Management Fixes


7. SLAB cache false sharing
- File: mm/slab.c Line 15
- Symptom: Multi-core CPUs accessing the same cache line leads to performance degradation
- Fix: Add 64-byte alignment padding in the slab_cache structure

8. Large page release exception
- File: mm/page.c Line 93
- Symptom: Physical memory release address larger than 1 page is not aligned
- Fix: Perform PAGE_SIZE alignment mask operation when calculating the physical address base


###File System Fixes


9. FAT32 long filename truncation
- File: fs/fat32.c Lines 127-135
- Symptom: VFAT entry checksum is not validated, causing garbled filenames
- Fix: Add checksum comparison logic, discard long name entries with failed checksums

10. Ext2 directory traversal defect
- File: fs/ext2.c Line 88
- Symptom: Deleted files still appear in the directory list
- Fix: Add filtering for entries with inode number 0 or unknown file type


###Toolchain Configuration Fixes


11. Cross-compilation path error
- File: Makefile Line 5
- Symptom: Kernel header directory is not correctly pointed to
- Fix: Change "-I/path/to/cross-compiler/include" to "-I./lib"

12. Assembler instruction missing
- File: arch/x86_64/smp.c Line 42
- Symptom: TLB is not flushed, causing virtual address mapping to become invalid
- Fix: Insert "invlpg" instruction sequence after APIC initialization

###Hardware Abstraction Layer Fixes

13. Missing UEFI memory descriptor
- File: kernel/main.c Line 34
- Symptom: EFI_MEMORY_DESCRIPTOR structure is not defined
- Fix: Add structure definition including Type/PhysAddr/NumPages fields

14. Virtualization support exception
- File: lib/vmx.h Lines 28-30
- Symptom: VMXON region alignment requirements are not handled
- Fix: Allocate 4KB aligned VMXON region and add CR0/CR4 mask validation
