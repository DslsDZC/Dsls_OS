#include <stdint.h>
#include <stddef.h>
#include "apic.h"
#include "task.h"
#include "slab.h"

#define MAX_CPUS 16
#define AP_BOOT_ADDR 0x8  // 0x8000物理地址对应的4KB页号（0x8000 >> 12）

// 每个 CPU 核心的状态
struct cpu_state {
    uint32_t apic_id;          // APIC ID
    struct task* current_task; // 当前运行的任务
    struct task* runqueue;     // 任务队列（链表）
    uint8_t lock;              // 简单的自旋锁
} __attribute__((aligned(64)));

static struct cpu_state cpus[MAX_CPUS];
static uint32_t num_cpus = 0;

// 简单的自旋锁实现
static void spin_lock(uint8_t* lock) {
    while (__sync_lock_test_and_set(lock, 1)) {
        __asm__ volatile("pause");
    }
}

static void spin_unlock(uint8_t* lock) {
    __sync_lock_release(lock);
}

// 获取当前 CPU 核心的 APIC ID
static uint32_t get_apic_id() {
    uint32_t eax, ebx, ecx, edx;
    __asm__ volatile("cpuid"
        : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
        : "a"(1));
    return (ebx >> 24) & 0xFF;
}

// 初始化 CPU 核心
static void init_cpu(uint32_t cpu_id) {
    struct cpu_state* cpu = &cpus[cpu_id];
    cpu->apic_id = get_apic_id();
    cpu->current_task = NULL;
    cpu->runqueue = NULL;
    cpu->lock = 0;
}

// 启动从处理器（AP）
static void start_ap(uint32_t cpu_id) {
    // 发送 INIT IPI
    apic_send_init(cpu_id);

    // 发送 STARTUP IPI
    apic_send_startup(cpu_id, AP_BOOT_ADDR);

    // 等待 AP 完成初始化
    while (!cpus[cpu_id].current_task);
}

// 从处理器的入口函数
void ap_entry() {
    uint32_t cpu_id = get_apic_id() & 0xFF;
    init_cpu(cpu_id);

    // 设置当前任务为空闲任务
    cpus[cpu_id].current_task = idle_task();

    // 进入调度循环
    while (1) {
        schedule();
        __asm__ volatile("hlt");
    }
}

// 初始化多核支持
void smp_init() {
    // 初始化 BSP（主处理器）
    init_cpu(0);
    num_cpus = 1;

    // 检测并启动其他 CPU 核心
    for (uint32_t i = 1; i < MAX_CPUS; i++) {
        if (apic_is_cpu_present(i)) {
            start_ap(i);
            num_cpus++;
        }
    }

    printf("SMP: %d CPUs initialized\n", num_cpus);
}

// 调度器：选择下一个任务
void smp_schedule() {
    uint32_t cpu_id = get_apic_id() & 0xFF;
    struct cpu_state* cpu = &cpus[cpu_id];

    spin_lock(&cpu->lock);

    // 从任务队列中选择下一个任务
    if (cpu->runqueue) {
        struct task* next = cpu->runqueue;
        cpu->runqueue = next->next;

        if (cpu->current_task) {
            cpu->current_task->next = cpu->runqueue;
            cpu->runqueue = cpu->current_task;
        }

        cpu->current_task = next;
        switch_to(next);
    }

    spin_unlock(&cpu->lock);
}

// 将任务添加到指定 CPU 的任务队列
void smp_add_task(struct task* task, uint32_t cpu_id) {
    if (cpu_id >= num_cpus) return;

    struct cpu_state* cpu = &cpus[cpu_id];
    spin_lock(&cpu->lock);

    task->next = cpu->runqueue;
    cpu->runqueue = task;

    spin_unlock(&cpu->lock);
}
