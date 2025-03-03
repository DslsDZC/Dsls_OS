// task.h
#ifndef _TASK_H
#define _TASK_H

#include <stdint.h>

#define MAX_TASKS 64
#define STACK_SIZE 4096

// 任务状态枚举
enum task_state {
    TASK_RUNNING,
    TASK_READY,
    TASK_BLOCKED
};

// 任务上下文结构（用于保存寄存器状态）
struct context {
    uint32_t esp;
    uint32_t ebp;
    uint32_t ebx;
    uint32_t esi;
    uint32_t edi;
    uint32_t eflags;
};

// 任务控制块
struct task {
    uint32_t id;                // 任务ID
    enum task_state state;      // 任务状态
    void (*entry)(void);        // 入口函数
    uint8_t stack[STACK_SIZE];  // 任务栈
    struct context ctx;         // 上下文
    struct task *next;          // 链表指针
    
    // 可扩展字段
    uint32_t priority;          // 调度优先级
    uint64_t runtime;           // 累计运行时间
};

// 核心调度函数声明
extern void schedule(void);
extern void switch_to(struct task *next);
extern struct task *idle_task(void);

// 任务管理接口
struct task *task_create(void (*entry)(void));
void task_destroy(struct task *task);
void task_yield(void);

#endif // _TASK_H