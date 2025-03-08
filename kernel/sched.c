#include <type.h>
#include <sched.h>
#include <stddef.h>
#include <system.h>

enum task_state {
    TASK_RUNNING,
    TASK_INTERRUPTIBLE,
    TASK_UNINTERRUPTIBLE,
    TASK_ZOMBIE,
    TASK_STOPPED
};

struct task_struct {
    long state;
    long counter;
    long priority;
    struct task_struct *next;
    unsigned long kernel_stack;
    long exit_code;
};

volatile int int_enabled;
struct task_struct *current = &init_task;
struct task_struct *task[NR_TASKS] = {&init_task, };
static struct task_struct init_task = {TASK_RUNNING, 15, 15, NULL, 0};

#define switch_to(n) do { \
    __asm__ __volatile__( 
        "pushl %%ebp\n\t"       \
        "pushl %%ebx\n\t"       \
        "pushl %%esi\n\t"       \
        "pushl %%edi\n\t"       \
        "movl %%esp, %0\n\t"    \
        "movl %1, %%esp\n\t"    \
        "movl $1f, %0\n\t"      \
        "pushl %1\n\t"          \
        "jmp __switch_to\n"     \
        "1:\t"                  \
        "popl %%edi\n\t"        \
        "popl %%esi\n\t"        \
        "popl %%ebx\n\t"        \
        "popl %%ebp\n\t"        \
        : "=m" (current->kernel_stack) \
        : "r" (n->kernel_stack), "d" (n) \
        : "memory"               \
    );                           \
} while (0)

void schedule(void)
{
    struct task_struct *next, *p;
    int c, saved_int = int_enabled;
    
    __asm__ __volatile__("cli");
    while (1) {
        c = -1;
        next = NULL;
        
        for (p = &init_task; p; p = p->next) {
            if (p->state == TASK_RUNNING && p->counter > c) {
                c = p->counter;
                next = p;
            }
        }
        
        if (c) break;
        
        for (p = &init_task; p; p = p->next) {
            p->counter = (p->counter >> 1) + p->priority;
        }
    }
    
    switch_to(next);
    if (saved_int) __asm__ __volatile__("sti");
}

void do_timer(void)
{
    int saved_int = int_enabled;
    __asm__ __volatile__("cli");
    
    if (--current->counter > 0) {
        if (saved_int) __asm__ __volatile__("sti");
        return;
    }
    
    current->counter = 0;
    schedule();
    if (saved_int) __asm__ __volatile__("sti");
}

void __switch_to(struct task_struct *prev, struct task_struct *next)
{
    current = next;
}

int kernel_thread(int (*fn)(void *), void *arg)
{
    struct task_struct *p;
    int i;
    
    for (i = 0; i < NR_TASKS; i++) {
        if (task[i] && task[i]->state == 0) {
            p = task[i];
            break;
        }
    }
    if (i >= NR_TASKS) return -1;
    
    unsigned long stack = (unsigned long)kmalloc(4096);
    if (!stack) return -1;
    p->kernel_stack = stack + 4096;
    
    unsigned long *stk = (unsigned long *)p->kernel_stack;
    *(--stk) = (unsigned long)arg;
    *(--stk) = (unsigned long)fn;
    *(--stk) = 0x0202;
    *(--stk) = 0x10;
    *(--stk) = (unsigned long)thread_start;
    
    return 0;
}

void thread_start(int (*fn)(void *), void *arg)
{
    fn(arg);
    current->state = TASK_ZOMBIE;
    schedule();
}

void sched_init(void) {
    init_task.state = TASK_RUNNING;
    init_task.counter = 15;
    init_task.priority = 15;
    task[0] = &init_task;
    current = task[0];
}

pid_t getpid(void) {
    return (pid_t)(current - task[0]);
}

void task_exit(int exit_code) {
    current->state = TASK_ZOMBIE;
    current->exit_code = exit_code;
    schedule();
}
