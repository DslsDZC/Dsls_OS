#include <smp.h>
#include <intrin.h>

#pragma pack(push, 1)
struct cpu_state cpus[MAX_CPUS];
#pragma pack(pop)
__declspec(align(64)) struct cpu_state;

uint32_t num_cpus;

static inline void spin_lock(volatile uint8_t* lock) {
    while (_InterlockedExchange8((volatile char*)lock, 1) != 0) {
        _mm_pause();
    }
}

static inline void spin_unlock(volatile uint8_t* lock) {
    _ReadWriteBarrier();
    *lock = 0;
}

static uint32_t get_apic_id() {
    int cpu_info[4];
    __cpuid(cpu_info, 1);
    return (cpu_info[1] >> 24) & 0xFF;
}

static void init_cpu(uint32_t cpu_id) {
    struct cpu_state* cpu = &cpus[cpu_id];
    cpu->apic_id = get_apic_id();
    cpu->lock = 0;
    cpu->current_task = NULL;
    cpu->runqueue = NULL;
}

static void start_ap(uint32_t cpu_id) {
    apic_send_init(cpu_id);
    apic_send_startup(cpu_id, AP_BOOT_ADDR);
    while (!cpus[cpu_id].current_task);
}

void ap_entry() {
    uint32_t cpu_id;
    cpu_id = get_apic_id() & 0xFF;
    init_cpu(cpu_id);
    cpus[cpu_id].current_task = idle_task();

    for (;;) {
         __asm__ __volatile__("hlt");
    }
}

void smp_init() {
    init_cpu(0);
    num_cpus = 1;

    for (uint32_t i = 1; i < MAX_CPUS; ++i) {
        if (apic_is_cpu_present(i)) {
            start_ap(i);
            ++num_cpus;
        }
    }
    debug_printf("SMP: %d CPUs initialized\n", num_cpus);
}

void smp_schedule() {
    uint32_t cpu_id = get_apic_id() & 0xFF;
    struct cpu_state* cpu = &cpus[cpu_id];

    spin_lock(&cpu->lock);
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

void smp_add_task(struct task* task, uint32_t cpu_id) {
    if (cpu_id >= num_cpus) return;

    struct cpu_state* cpu = &cpus[cpu_id];
    spin_lock(&cpu->lock);
    task->next = cpu->runqueue;
    cpu->runqueue = task;
    spin_unlock(&cpu->lock);
}
