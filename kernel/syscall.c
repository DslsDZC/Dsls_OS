#include <stdint.h>
#include <stddef.h>
#include <system.h>
#include <msr.h>
#include <errno.h>

#define MAX_FILES 1024
#define unreachable() do { \
    asm volatile("ud2");   \
    __builtin_unreachable(); \
} while (0)

// 临时桩函数防止链接错误
__attribute__((weak)) void mmput(void* mm) {}
__attribute__((weak)) void vfs_close(void* file) {}

enum {
    SYS_GETPID = 0,
    SYS_FORK,
    SYS_EXIT,
    SYS_READ,
    SYS_WRITE,
    SYS_OPEN,
    SYS_CLOSE,
    SYSCALL_MAX
};

static void *syscall_table[SYSCALL_MAX] = {
    [SYS_GETPID] = syscall_getpid,
    [SYS_FORK]   = syscall_fork,
    [SYS_EXIT]   = syscall_exit,
    [SYS_READ]   = syscall_read,
    [SYS_WRITE]  = syscall_write,
    [SYS_OPEN]   = syscall_open,
    [SYS_CLOSE]  = syscall_close,
};

long syscall_exit(long status, long unused1, long unused2)
{
    (void)unused1; (void)unused2;
    struct task_struct *task = current;
    unsigned long flags;

    raw_spin_lock_irqsave(&task->lock, flags);
    task->state = TASK_ZOMBIE;
    task->exit_code = status;
    smp_mb();

    if (!list_empty(&task->children)) {
        struct task_struct *child, *tmp;
        list_for_each_entry_safe(child, tmp, &task->children, sibling) {
            raw_spin_lock(&child->lock);
            child->parent = init_task;
            raw_spin_unlock(&child->lock);
        }
    }
    raw_spin_unlock_irqrestore(&task->lock, flags);

    if (task->mm) {
        mmput(task->mm);
        task->mm = NULL;
    }

    for (int i = 0; i < MAX_FILES; i++) {
        if (task->files[i]) {
            vfs_close(task->files[i]);
            task->files[i] = NULL;
        }
    }

    list_del(&task->run_list);
    printk("<6>Process %d exited with status %ld\n", task->pid, status);
    schedule();
    unreachable();
}

long syscall_fork(long a1, long a2, long a3)
{
    (void)a1; (void)a2; (void)a3;
    struct task_struct *child = kmalloc(sizeof(*current));
    if (!child) return -ENOMEM;

    memcpy(child, current, sizeof(*current));
    child->kernel_stack = (unsigned long)kmalloc(4096);
    if (!child->kernel_stack) {
        kfree(child);
        return -ENOMEM;
    }
    child->kernel_stack += 4096;
    memcpy((void*)(child->kernel_stack - 4096),
          (void*)(current->kernel_stack - 4096), 4096);

    struct pt_regs *child_regs = (struct pt_regs *)child->kernel_stack;
    child_regs->rax = 0;

    if (child->mm) mmget(child->mm);
    for (int i = 0; i < MAX_FILES; i++)
        if (child->files[i]) vfs_get(child->files[i]);

    task_add(child);
    return child->pid;
}

long syscall_handler(long nr, long a1, long a2, long a3)
{
    if (nr >= SYSCALL_MAX || !syscall_table[nr]) {
        printk("Invalid syscall: %ld\n", nr);
        return -ENOSYS;
    }
    return ((long (*)(long, long, long))syscall_table[nr])(a1, a2, a3);
}
