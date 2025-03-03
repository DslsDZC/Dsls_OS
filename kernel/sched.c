/* 
 * sched.c - 核心调度程序
 * 实现进程切换、时间片轮转调度
 */

#include <type.h>
#include <sched.h>
#include <system.h>

// 定义最大进程数
#define NR_TASKS 64

// 任务状态定义
#define TASK_RUNNING     0
#define TASK_INTERRUPTIBLE 1
#define TASK_UNINTERRUPTIBLE 2
#define TASK_ZOMBIE      3
#define TASK_STOPPED     4

// 任务数据结构
struct task_struct {
    long state;         // 任务状态
    long counter;       // 时间片剩余
    long priority;      // 初始优先级
    struct task_struct *next; // 链表指针
    unsigned long kernel_stack; // 内核栈指针
    // ... 可扩展其他字段
};

// 任务数组和当前任务指针
struct task_struct *current = &init_task;
struct task_struct *task[NR_TASKS] = {&init_task, };
static struct task_struct init_task = {TASK_RUNNING, 15, 15, NULL, 0};

// 系统时钟计数器
volatile unsigned long jiffies = 0;

// 汇编实现的上下文切换
extern void switch_to(struct task_struct *next);

/* 
 * 核心调度函数 
 * 选择counter值最大的就绪任务
 */
void schedule(void)
{
    struct task_struct *next, *p;
    int c;

    while (1) {
        c = -1;
        next = NULL;
        
        // 遍历任务数组
        for (p = &init_task; p; p = p->next) {
            if (p->state == TASK_RUNNING && p->counter > c) {
                c = p->counter;
                next = p;
            }
        }
        
        // 找到可运行任务或重置时间片
        if (c) break;
        
        // 重置所有任务的时间片
        for (p = &init_task; p; p = p->next) {
            p->counter = (p->counter >> 1) + p->priority;
        }
    }
    
    // 执行任务切换
    switch_to(next);
}

/*
 * 系统时钟中断处理
 * 每个时钟节拍递减当前任务的时间片
 */
void do_timer(void)
{
    if (--current->counter > 0) return;
    current->counter = 0;
    schedule();
}

/*
 * 完整的上下文切换汇编实现
 */
#define switch_to(n) do { \
    __asm__ __volatile__( \
        "pushl %%ebp\n\t"       /* 保存当前EBP */ \
        "movl %%esp, %0\n\t"    /* 保存当前ESP到当前任务 */ \
        "movl %1, %%esp\n\t"    /* 加载新任务的ESP */ \
        "movl $1f, %0\n\t"      /* 保存返回地址 */ \
        "pushl %1\n\t"          /* 压入新任务的EIP */ \
        "jmp __switch_to\n"     /* 跳转到切换函数 */ \
        "1:\t" \
        "popl %%ebp\n\t"        /* 恢复EBP */ \
        : "=m" (current->kernel_stack) \
        : "r" (n->kernel_stack), "d" (n) \
        : "memory" \
    ); \
} while (0)

/* 
 * 进程切换核心函数（由汇编调用）
 * prev在EDX寄存器，next在ECX寄存器
 */
void __switch_to(struct task_struct *prev, struct task_struct *next)
{
    // 更新当前任务指针
    current = next;
    // 这里可以添加TLB刷新等架构相关操作
}

/* 
 * 创建新任务（示例实现）
 */
int kernel_thread(int (*fn)(void *), void *arg)
{
    struct task_struct *p;
    
    // 分配任务结构体（简化实现）
    for (p = task[0]; p < &task[NR_TASKS]; p++) {
        if (!p->state) break;
    }
    
    // 初始化任务字段
    p->state = TASK_RUNNING;
    p->counter = p->priority = 15;
    p->kernel_stack = (unsigned long)kmalloc(4096) + 4096;
    
    // 设置初始执行上下文
    unsigned long *stack = (unsigned long *)p->kernel_stack;
    *(--stack) = (unsigned long)arg;
    *(--stack) = (unsigned long)fn;
    *(--stack) = 0x0202;    // EFLAGS
    *(--stack) = 0x10;      // CS
    *(--stack) = (unsigned long)thread_start; // EIP
    
    return 0; // 返回PID（简化）
}

/* 
 * 线程启动包装函数
 */
void thread_start(int (*fn)(void *), void *arg)
{
    fn(arg);
    // 线程结束后进入终止状态
    current->state = TASK_ZOMBIE;
    schedule();
}