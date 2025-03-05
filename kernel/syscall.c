#include <stdint.h>
#include <stddef.h>
#include <system.h>
#include <msr.h>

#define unreachable() do { \
    asm volatile("ud2");   \
    __builtin_unreachable(); \
} while (0)

/* 系统调用号定义 */
#define SYS_GETPID    0
#define SYS_FORK      1
#define SYS_EXIT      2
#define SYS_READ      3
#define SYS_WRITE     4
#define SYS_OPEN      5
#define SYS_CLOSE     6

/* 系统调用前置声明 */
long syscall_getpid(long, long, long);
long syscall_fork(long, long, long);
long syscall_exit(long, long, long);
long syscall_read(long, long, long);
long syscall_write(long, long, long);
long syscall_open(long, long, long);
long syscall_close(long, long, long);

extern struct task_struct *init_task;
struct list_head children;
struct list_head sibling;

/* 系统调用表 */
static void *syscall_table[] = {
    [SYS_GETPID] = syscall_getpid,
    [SYS_FORK]   = syscall_fork,
    [SYS_EXIT]   = syscall_exit,
    [SYS_READ]   = syscall_read,
    [SYS_WRITE]  = syscall_write,
    [SYS_OPEN]   = syscall_open,
    [SYS_CLOSE]  = syscall_close,
    [7] = NULL
};

    /* 补充在系统调用实现区域 */
long syscall_exit(long status, long unused1, long unused2)
{
(void)unused1; (void)unused2;  // 显式忽略多余参数
struct task_struct *task = current;

// 1. 设置进程状态和退出码
task->state = TASK_ZOMBIE;
task->exit_code = status;

// 2. 资源回收逻辑
if (task->mm) {
    mmput(task->mm);    // 释放内存管理结构
    task->mm = NULL;
}

// 3. 文件描述符清理
for (int i = 0; i < MAX_FILES; i++) {
    if (task->files[i]) {
        vfs_close(task->files[i]);
        task->files[i] = NULL;
    }
}

// 4. 子进程处理（防止僵尸进程残留）
if (!list_empty(&task->children)) {
    struct task_struct *child;
    list_for_each_entry(child, &task->children, struct task_struct, sibling) {
        child->parent = init_task;
    }
}

// 5. 从调度队列移除
list_del(&task->run_list);

// 6. 调度前日志记录（调试用）
printk("<6>Process %d exited with status %ld\n", task->pid, status);

// 7. 触发调度（永不返回）
schedule();

// 编译器优化提示和防护措施
unreachable();

// 安全防护循环（可选）
while (1) {
    // 关闭中断并挂起CPU
    arch_local_irq_disable();
    cpu_relax();
}
}
/* 系统调用入口处理 */
__attribute__((naked)) void syscall_entry(void)
{
    asm volatile(
        "swapgs\n"              // 切换内核GS寄存器
        "movq %%rsp, %gs:0\n"   // 保存用户栈到percpu区域
        "movq %gs:8, %%rsp\n"   // 加载内核栈
        
        // 保存用户态上下文
        "pushq $0x1b\n"         // 用户态SS
        "pushq %gs:0\n"         // 用户态RSP
        "pushq %%r11\n"         // RFLAGS
        "pushq $0x23\n"         // 用户态CS
        "pushq %%rcx\n"         // 用户态RIP
        
        // 调用处理函数
        "movq %%rax, %%rdi\n"   // 系统调用号
        "movq %%rbx, %%rsi\n"   // 参数1
        "movq %%rcx, %%rdx\n"   // 参数2
        "movq %%rdx, %%rcx\n"   // 参数3
        "call syscall_handler\n"
        
        // 恢复上下文
        "popq %%rcx\n"
        "popq %%r11\n"
        "popq %%rsp\n"
        "swapgs\n"
        "sysretq\n"
    );
}

/* 系统调用分发函数优化 */
long syscall_handler(long nr, long a1, long a2, long a3)
{
    if(nr >= sizeof(syscall_table)/sizeof(void*) || !syscall_table[nr]) {
        printk("Invalid syscall: %ld\n", nr);
        return -ENOSYS;
    }
    
    return ((long (*)(long, long, long))syscall_table[nr])(a1, a2, a3);
}

/* 具体系统调用实现 */
long syscall_getpid(long a1, long a2, long a3)
{
    (void)a1; (void)a2; (void)a3; // 显式忽略未用参数
    return current->pid;
}
long syscall_fork(long a1, long a2, long a3)
{
    (void)a1; (void)a2; (void)a3; // 显式忽略参数
    struct task_struct *child = kmalloc(sizeof(*current));
    memcpy(child, current, sizeof(*current));
    
    // 复制内核栈
    child->kernel_stack = (unsigned long)kmalloc(4096) + 4096;
    memcpy((void*)child->kernel_stack, (void*)current->kernel_stack, 4096);
    
    // 设置返回值为0（子进程）
    ((long*)child->kernel_stack)[3] = 0; 
    
    // 添加任务到调度队列
    task_add(child);
    return child->pid;
}

/* 初始化系统调用 */
void syscall_init(void)
{
    // 设置MSR寄存器（需要arch/x86_64/msr.h）
    wrmsr(IA32_LSTAR, (uint64_t)syscall_entry);
    wrmsr(IA32_STAR,  (uint64_t)((8ULL << 32) | (16ULL << 48)));
    wrmsr(IA32_FMASK, X86_EFLAGS_DF | X86_EFLAGS_IF);
}
