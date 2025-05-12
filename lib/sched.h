// sched.h
#ifndef _SCHED_H
#define _SCHED_H

#include <type.h>
#define NR_TASKS 64

/* 任务状态定义 */
#define TASK_RUNNING      0
#define TASK_INTERRUPTIBLE 1
#define TASK_UNINTERRUPTIBLE 2
#define TASK_ZOMBIE       3
#define TASK_STOPPED      4

/* 任务结构体前向声明 */
struct task_struct;

/* 调度函数声明 */
extern void schedule(void);
extern void do_timer(void);
extern int kernel_thread(int (*fn)(void *), void *arg);

/* 系统调用包装函数 */
static inline void yield(void) {
    schedule();
}

/* 任务控制相关 */
#define NR_TASKS 64
extern struct task_struct *current;
extern struct task_struct *task[NR_TASKS];

/* 上下文切换汇编宏 */
#define switch_to(n) extern void __switch_to(struct task_struct *prev, struct task_struct *next)

/* 内核栈初始大小 */
#define KERNEL_STACK_SIZE 4096

/* 任务属性获取 */
#define current_get_counter() (current->counter)
#define current_set_priority(pri) do { current->priority = (pri); } while(0)

#endif /* _SCHED_H */