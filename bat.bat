@echo off
echo 正在创建操作系统项目结构...

echo 创建目录结构...
mkdir .vscode 2>nul
mkdir build\x86_64 2>nul
mkdir build\arm64 2>nul
mkdir build\riscv64 2>nul

mkdir arch\x86_64\boot\bios 2>nul
mkdir arch\x86_64\boot\uefi 2>nul
mkdir arch\x86_64\drivers 2>nul
mkdir arch\x86_64\mm 2>nul
mkdir arch\x86_64\power 2>nul
mkdir arch\x86_64\dsls 2>nul

mkdir arch\arm64\boot\uefi 2>nul
mkdir arch\arm64\drivers 2>nul
mkdir arch\arm64\mm 2>nul
mkdir arch\arm64\power 2>nul

mkdir arch\riscv64\boot 2>nul
mkdir arch\riscv64\drivers 2>nul
mkdir arch\riscv64\mm 2>nul
mkdir arch\riscv64\power 2>nul

mkdir drivers\storage 2>nul
mkdir drivers\network 2>nul
mkdir drivers\bus 2>nul
mkdir drivers\input 2>nul
mkdir drivers\video 2>nul
mkdir drivers\irq 2>nul

mkdir kernel\core 2>nul
mkdir kernel\process 2>nul
mkdir kernel\sched 2>nul
mkdir kernel\sched\algorithms 2>nul
mkdir kernel\sync 2>nul
mkdir kernel\mm 2>nul
mkdir kernel\mm\allocators 2>nul
mkdir kernel\fs 2>nul
mkdir kernel\net 2>nul
mkdir kernel\net\ip 2>nul
mkdir kernel\net\tcp 2>nul
mkdir kernel\net\udp 2>nul
mkdir kernel\net\protocols 2>nul
mkdir kernel\init 2>nul
mkdir kernel\debug 2>nul
mkdir kernel\security 2>nul

mkdir lib\libc\stdio 2>nul
mkdir lib\libc\stdlib 2>nul
mkdir lib\libc\math 2>nul
mkdir lib\libc\unistd 2>nul
mkdir lib\data_structures 2>nul
mkdir lib\elf 2>nul

mkdir user\init 2>nul
mkdir user\shell 2>nul
mkdir user\utils 2>nul
mkdir user\lib 2>nul

mkdir include\arch\x86_64 2>nul
mkdir include\arch\arm64 2>nul
mkdir include\arch\common 2>nul
mkdir include\kernel 2>nul
mkdir include\drivers 2>nul
mkdir include\fs 2>nul
mkdir include\net 2>nul
mkdir include\mm 2>nul
mkdir include\lib 2>nul
mkdir include\lib\libc 2>nul
mkdir include\user 2>nul

mkdir scripts\toolchain 2>nul
mkdir scripts\build 2>nul
mkdir scripts\image 2>nul
mkdir scripts\test 2>nul

mkdir docs\design 2>nul
mkdir docs\api 2>nul
mkdir docs\porting 2>nul

mkdir tests\unit\kernel 2>nul
mkdir tests\unit\drivers 2>nul
mkdir tests\unit\fs 2>nul
mkdir tests\unit\net 2>nul
mkdir tests\unit\lib 2>nul
mkdir tests\integration\boot 2>nul
mkdir tests\integration\filesystem 2>nul
mkdir tests\integration\networking 2>nul
mkdir tests\integration\multitasking 2>nul
mkdir tests\benchmarks\memory 2>nul
mkdir tests\benchmarks\fs 2>nul
mkdir tests\benchmarks\network 2>nul
mkdir tests\benchmarks\sched 2>nul

:: 创建 .vscode 目录文件
echo Creating .vscode files...
type nul > .vscode\c_cpp_properties.json
type nul > .vscode\launch.json
type nul > .vscode\settings.json

:: 创建 arch/x86_64 文件
echo Creating x86_64 files...
type nul > arch\x86_64\boot\bios\boot.asm
type nul > arch\x86_64\boot\bios\loader.asm
type nul > arch\x86_64\boot\bios\second_stage.asm
type nul > arch\x86_64\boot\uefi\boot.c
type nul > arch\x86_64\boot\uefi\graphics.c
type nul > arch\x86_64\boot\uefi\loader.c
type nul > arch\x86_64\boot\uefi\uefi.h
type nul > arch\x86_64\drivers\apic.c
type nul > arch\x86_64\drivers\io.c
type nul > arch\x86_64\drivers\msr.c
type nul > arch\x86_64\mm\page_tables.c
type nul > arch\x86_64\power\cpu.c
type nul > arch\x86_64\power\pm.c
type nul > arch\x86_64\dsls\smp.c
type nul > arch\x86_64\dsls\vmx.c

:: 创建 arch/arm64 文件
echo Creating arm64 files...
type nul > arch\arm64\boot\uefi\boot.c
type nul > arch\arm64\boot\uefi\graphics.c
type nul > arch\arm64\boot\uefi\loader.c
type nul > arch\arm64\boot\uefi\uefi.h
type nul > arch\arm64\drivers\gic.c
type nul > arch\arm64\drivers\mmio.c
type nul > arch\arm64\mm\page_tables.c
type nul > arch\arm64\power\cpu.c
type nul > arch\arm64\power\pm.c

:: 创建 drivers 文件
echo Creating driver files...
type nul > drivers\storage\ahci.c
type nul > drivers\storage\nvme.c
type nul > drivers\network\e1000.c
type nul > drivers\network\virtio_net.c
type nul > drivers\bus\pci.c
type nul > drivers\bus\acpi.c
type nul > drivers\input\keyboard.c
type nul > drivers\input\mouse.c
type nul > drivers\video\vga.c
type nul > drivers\video\framebuffer.c
type nul > drivers\irq\pic.c
type nul > drivers\irq\gic.c

:: 创建 kernel 文件
echo Creating kernel files...
type nul > kernel\core\main.c
type nul > kernel\core\irq.c
type nul > kernel\core\syscall.c
type nul > kernel\core\time.c
type nul > kernel\core\timer.c
type nul > kernel\core\module.c
type nul > kernel\process\process.c
type nul > kernel\process\thread.c
type nul > kernel\process\context_switch.asm
type nul > kernel\process\pid.c
type nul > kernel\sched\sched.c
type nul > kernel\sched\algorithms\cfs.c
type nul > kernel\sched\algorithms\round_robin.c
type nul > kernel\sync\spinlock.c
type nul > kernel\sync\mutex.c
type nul > kernel\sync\semaphore.c
type nul > kernel\sync\rwlock.c
type nul > kernel\mm\page.c
type nul > kernel\mm\slab.c
type nul > kernel\mm\vma.c
type nul > kernel\mm\kmalloc.c
type nul > kernel\mm\vmalloc.c
type nul > kernel\mm\allocators\buddy.c
type nul > kernel\mm\allocators\slab_alloc.c
type nul > kernel\fs\vfs.c
type nul > kernel\fs\inode.c
type nul > kernel\fs\dentry.c
type nul > kernel\fs\file.c
type nul > kernel\fs\ext2.c
type nul > kernel\fs\fat32.c
type nul > kernel\fs\devfs.c
type nul > kernel\net\ip\ipv4.c
type nul > kernel\net\ip\ipv6.c
type nul > kernel\net\tcp\tcp.c
type nul > kernel\net\tcp\tcp_timer.c
type nul > kernel\net\udp\udp.c
type nul > kernel\net\socket.c
type nul > kernel\net\protocols\arp.c
type nul > kernel\net\protocols\icmp.c
type nul > kernel\net\protocols\dhcp.c
type nul > kernel\init\early_init.c
type nul > kernel\init\mm_init.c
type nul > kernel\init\driver_init.c
type nul > kernel\init\fs_init.c
type nul > kernel\init\late_init.c
type nul > kernel\debug\kprintf.c
type nul > kernel\debug\panic.c
type nul > kernel\debug\backtrace.c
type nul > kernel\debug\kassert.c
type nul > kernel\debug\logging.c
type nul > kernel\security\capability.c
type nul > kernel\security\access_control.c

:: 创建 lib 文件
echo Creating lib files...
type nul > lib\libc\stdio\printf.c
type nul > lib\libc\stdio\scanf.c
type nul > lib\libc\stdio\file.c
type nul > lib\libc\stdlib\malloc.c
type nul > lib\libc\stdlib\string.c
type nul > lib\libc\stdlib\ctype.c
type nul > lib\libc\math\math.c
type nul > lib\libc\math\rand.c
type nul > lib\libc\unistd\fork.c
type nul > lib\libc\unistd\exec.c
type nul > lib\libc\unistd\io.c
type nul > lib\data_structures\list.c
type nul > lib\data_structures\tree.c
type nul > lib\data_structures\hashmap.c
type nul > lib\data_structures\ringbuffer.c
type nul > lib\elf\elf.c
type nul > lib\elf\elf_loader.c

:: 创建 user 文件
echo Creating user files...
type nul > user\init\init.c
type nul > user\shell\shell.c
type nul > user\shell\builtins.c
type nul > user\shell\parser.c
type nul > user\utils\ls.c
type nul > user\utils\cat.c
type nul > user\utils\echo.c
type nul > user\utils\ps.c
type nul > user\lib\crt0.c
type nul > user\lib\syscall.c

:: 创建 include 文件
echo Creating include files...
type nul > include\config.h
type nul > include\features.h
type nul > include\types.h
type nul > include\compiler.h
type nul > include\arch\x86_64\io.h
type nul > include\arch\x86_64\msr.h
type nul > include\arch\x86_64\apic.h
type nul > include\arch\x86_64\cpuid.h
type nul > include\arch\x86_64\smp.h
type nul > include\arch\x86_64\vmx.h
type nul > include\arch\x86_64\boot.h
type nul > include\arch\x86_64\uefi.h
type nul > include\arch\arm64\mmio.h
type nul > include\arch\arm64\gic.h
type nul > include\arch\arm64\boot.h
type nul > include\arch\common\atomic.h
type nul > include\arch\common\bitops.h
type nul > include\arch\common\byteorder.h
type nul > include\kernel\kernel.h
type nul > include\kernel\sched.h
type nul > include\kernel\task.h
type nul > include\kernel\syscall.h
type nul > include\kernel\irq.h
type nul > include\kernel\time.h
type nul > include\kernel\timer.h
type nul > include\kernel\module.h
type nul > include\kernel\panic.h
type nul > include\kernel\printf.h
type nul > include\kernel\system.h
type nul > include\kernel\process.h
type nul > include\kernel\sync.h
type nul > include\kernel\mm.h
type nul > include\drivers\pci.h
type nul > include\drivers\irq.h
type nul > include\drivers\ahci.h
type nul > include\drivers\e1000.h
type nul > include\drivers\disk.h
type nul > include\drivers\input.h
type nul > include\drivers\video.h
type nul > include\drivers\bus.h
type nul > include\fs\vfs.h
type nul > include\fs\ext2.h
type nul > include\fs\fat32.h
type nul > include\fs\devfs.h
type nul > include\net\ip.h
type nul > include\net\tcp.h
type nul > include\net\udp.h
type nul > include\net\socket.h
type nul > include\net\ethernet.h
type nul > include\mm\page.h
type nul > include\mm\slab.h
type nul > include\mm\vma.h
type nul > include\mm\heap.h
type nul > include\mm\allocator.h
type nul > include\lib\libc\stdio.h
type nul > include\lib\libc\stdlib.h
type nul > include\lib\libc\string.h
type nul > include\lib\libc\math.h
type nul > include\lib\libc\unistd.h
type nul > include\lib\list.h
type nul > include\lib\tree.h
type nul > include\lib\hashmap.h
type nul > include\lib\ringbuffer.h
type nul > include\lib\elf.h
type nul > include\user\user.h
type nul > include\user\syscall.h

:: 创建 scripts 文件
echo Creating script files...
type nul > scripts\toolchain\x86_64.sh
type nul > scripts\toolchain\arm64.sh
type nul > scripts\toolchain\riscv64.sh
type nul > scripts\build\config.sh
type nul > scripts\build\kernel.sh
type nul > scripts\build\drivers.sh
type nul > scripts\build\fs.sh
type nul > scripts\build\net.sh
type nul > scripts\build\lib.sh
type nul > scripts\build\user.sh
type nul > scripts\image\mkinitrd.sh
type nul > scripts\image\geniso.sh
type nul > scripts\image\create_disk.sh
type nul > scripts\test\run_unit_tests.sh
type nul > scripts\test\run_integration_tests.sh
type nul > scripts\test\code_coverage.sh

:: 创建 docs 文件
echo Creating documentation files...
type nul > docs\design\architecture.md
type nul > docs\design\boot_process.md
type nul > docs\design\memory_management.md
type nul > docs\design\filesystem.md
type nul > docs\design\networking.md
type nul > docs\design\driver_model.md
type nul > docs\api\kernel_api.md
type nul > docs\api\driver_api.md
type nul > docs\api\libc_api.md
type nul > docs\api\syscall_api.md
type nul > docs\porting\porting_to_x86_64.md
type nul > docs\porting\porting_to_arm64.md
type nul > docs\porting\porting_to_riscv64.md

:: 创建 tools 文件
echo Creating tools files...
type nul > tools\debug\trace.c
type nul > tools\debug\profiler.c
type nul > tools\codegen\syscall_generator.py
type nul > tools\codegen\irq_generator.py
type nul > tools\codegen\protocol_generator.py

:: 创建根目录文件
echo Creating root files...
type nul > LICENSE
type nul > Makefile
type nul > README.md
type nul > README_CH.md
type nul > README_DE.md
type nul > README_ES.md
type nul > README_FR.md
type nul > rfs.txt

echo.
echo 项目结构创建完成!
echo 所有文件已被创建。

pause