#ifndef SYSTEM_H
#define SYSTEM_H
#define TASK_RUNNING     0
#define TASK_INTERRUPTIBLE 1
#define MAX_FILES 16
#define RLIM_NLIMITS 16
#define NR_CPUS 64
#define _NSIG 64
#include <stdint.h>
typedef uint64_t u64;

/* 基础类型定义 */
typedef int pid_t;
typedef unsigned int size_t;
typedef unsigned long sigset_t;
typedef unsigned int sigset_t;
typedef unsigned long pgd_t;
typedef unsigned int uid_t;
typedef unsigned long sigset_t;
typedef int64_t     ktime_t;    // 纳秒级时间（内核时间）
typedef uint64_t    time64_t;   // 64位时间戳
typedef uint32_t    time_t;     // 传统时间类型

struct tty_struct;
struct hrtimer;
struct taskstats;

enum task_state {
    TASK_RUNNING = 0,
    TASK_INTERRUPTIBLE,
    TASK_UNINTERRUPTIBLE,
    TASK_ZOMBIE,    // 僵尸状态
    TASK_STOPPED
};

struct rb_node {
    unsigned long  __rb_parent_color;
    struct rb_node *rb_right;
    struct rb_node *rb_left;
} __attribute__((aligned(sizeof(long))));
    
struct timerqueue_node {
    struct rb_node node;  // 红黑树节点基础结构
    ktime_t expires;      // 到期时间
};

struct hrtimer {
    struct timerqueue_node      node;
    ktime_t                     _softexpires;
    enum hrtimer_restart        (*function)(struct hrtimer *);
    unsigned long               state;
    int                         start_pid;
    void                        *start_site;
    char                        start_comm[16];
    };

struct timer_list {
    struct list_head entry;
    unsigned long expires;
    void (*function)(unsigned long);
    unsigned long data
};

typedef struct {
    int counter;
} atomic_t;

struct sigaction {
    void (*sa_handler)(int);
    sigset_t sa_mask;
    int sa_flags;
    void (*sa_restorer)(void);
};

struct kernel_siginfo {
    int si_signo;             // 信号编号
    int si_errno;             // 错误码
    int si_code;              // 信号来源代码
    pid_t si_pid;             // 发送者PID
    uid_t si_uid;             // 发送者UID
    void *si_addr;            // 触发地址（如SIGSEGV）
    int si_status;            // 退出状态（SIGCHLD）
    long si_band;             // 带外事件（SIGPOLL）
    };
    

typedef struct audit_context audit_context_t;
    
 
struct signal_struct {
    atomic_t count;
    struct sigaction action[_NSIG];
    struct list_head list;
    sigset_t blocked;
    sigset_t real_blocked;
    int sigcnt;
    int group_exit_code;
    struct tty_struct *tty;
    pid_t leader;
    struct rlimit rlim[RLIM_NLIMITS];
    struct kernel_siginfo last_siginfo;
    struct sigqueue *sigqueue;
    unsigned long flags;
    struct timer_list real_timer;
    struct hrtimer cpu_timer[3];
    struct taskstats *stats;
    audit_context_t *audit_context;
};

/* 信号处理结构体 */
struct signal_struct {
    atomic_t count;            // 引用计数（共享该结构的进程数）
    struct sigaction action[_NSIG]; // 信号处理函数数组
    struct list_head list;     // 共享信号结构的进程链表头
    sigset_t blocked;          // 全局阻塞信号掩码
    sigset_t real_blocked;     // 临时阻塞信号掩码
    int sigcnt;                // 使用该结构的线程数统计
    int group_exit_code;       // 进程组退出状态码
    struct tty_struct *tty;    // 关联的控制终端
    pid_t leader;              // 会话领导进程PID
    struct rlimit rlim[RLIM_NLIMITS]; // 进程资源限制
    struct kernel_siginfo last_siginfo; // 最近接收的信号信息
    struct sigqueue *sigqueue; // 待处理信号队列头
    unsigned long flags;       // 信号处理标志位
    struct timer_list real_timer; // ITIMER_REAL定时器
    struct hrtimer cpu_timer[3]; // CPU时间定时器（虚拟/概况/轮询）
    struct taskstats *stats;   // 进程统计信息指针
    audit_context_t *audit_context; // 审计上下文
};

/* 内存管理 */
void* kmalloc(size_t size);
void kfree(void *ptr);

/* 字符串操作 */
void* memcpy(void* dest, const void* src, size_t n);
void* memset(void* s, int c, size_t n);
char* strncpy(char* dest, const char* src, size_t n);
char* strcat(char* dest, const char* src);

/* 任务调度相关 */
struct task_struct;
void schedule(void);
void sched_init(void);
void do_timer(void);

/* 系统全局变量 */
extern volatile unsigned long jiffies;
extern struct task_struct *current;

/* 上下文切换汇编接口 */
#define switch_to(n) _switch_to(n)
extern void _switch_to(struct task_struct *next);

/* 进程管理 */
pid_t getpid(void);
void task_exit(int exit_code);

/* 内核线程 */
int kernel_thread(int (*fn)(void *), void *arg);

/* 架构相关 */
static inline void cli(void) { asm volatile("cli"); }  // 关中断
static inline void sti(void) { asm volatile("sti"); }  // 开中断


struct list_head {
    struct list_head *next, *prev;
};

    struct sigpending {
    struct list_head list;       // 信号队列链表头
    sigset_t signal;             // 待处理信号位图
};

/* 新增CPU状态结构定义 */
struct thread_struct {
    unsigned long rsp;     // 栈指针
    unsigned long rip;     // 指令指针
    unsigned long cr3;     // 页表基址
};

    
struct rlimit {
    unsigned long rlim_cur;  // 当前限制
    unsigned long rlim_max;  // 最大限制
};

typedef struct {
    unsigned long bits[(NR_CPUS + 8*sizeof(unsigned long) - 1)/(8*sizeof(unsigned long))];
} cpumask_t;

struct perf_event_context;

struct task_struct {
    /* 基础标识 */
    pid_t pid;                  // 进程ID
    pid_t tgid;                 // 线程组ID
    long state;                 // 进程状态
    long exit_code;             // 退出状态码
    struct sigpending pending;
    struct thread_struct thread;
    
    /* 调度相关 */
    unsigned int policy;        // 调度策略（SCHED_NORMAL等）
    int static_prio;            // 静态优先级
    int dynamic_prio;           // 动态优先级
    unsigned int time_slice;    // 剩余时间片
    struct list_head run_list;  // 运行队列链表节点
    
    /* 内存管理 */
    struct mm_struct *mm;       // 内存描述符
    
    /* 文件系统 */
    struct file *files[MAX_FILES];  // 打开文件表
    struct fs_struct *fs;       // 文件系统信息
    struct dentry *pwd;         // 当前工作目录
    
    /* 进程关系 */
    struct task_struct *parent; // 父进程
    struct list_head children;  // 子进程链表头
    struct list_head sibling;   // 兄弟进程链表节点
    
    /* 信号处理 */
    struct signal_struct *signal;   // 信号处理结构体
    sigset_t blocked;          // 阻塞信号集
    struct sigpending pending; // 待处理信号
    
    /* 时间统计 */
    u64 start_time;            // 进程创建时间
    u64 utime, stime;          // 用户/内核态CPU时间
    
    /* 内核栈 */
    void *stack;               // 内核栈指针
    
    /* 硬件上下文 */
    struct thread_struct thread; // CPU特定状态
    
    /* 调试相关 */
    unsigned int ptrace;       // 调试标志位
    struct audit_context *audit_context; // 审计上下文
    
    /* 扩展属性 */
    void *security;            // 安全模块指针
    cpumask_t cpus_allowed;    // CPU亲和性掩码
    
    /* 同步机制 */
    struct completion *vfork_done; // vfork完成通知
    
    /* 资源限制 */
    struct rlimit rlim[RLIM_NLIMITS]; // 资源限制数组
    
    /* 性能计数器 */
    struct perf_event_context *perf_event_ctxp;
};

typedef struct {
    unsigned long pgd_val;
} pgd_t;

/* 内存描述符（简化版） */
struct mm_struct {
    pgd_t *pgd;                // 页全局目录
    struct vm_area_struct *mmap; // 虚拟内存区域链表
    // ...其他内存管理字段...
};

/* 信号处理结构体 */
struct signal_struct {
    atomic_t count;            // 引用计数
    struct sigaction action[_NSIG]; // 信号处理函数数组
    // ...其他信号相关字段...
};

#endif // SYSTEM_H
