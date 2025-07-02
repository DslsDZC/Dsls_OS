#ifndef SMP_H
#define SMP_H

#include <stdint.h>
#include <stddef.h>
#include <apic.h>
#include <task.h>
#include <slab.h>

#define MAX_CPUS 64
#define AP_BOOT_ADDR 0x8000

struct cpu_state {
    uint32_t apic_id;
    struct task* current_task;
    struct task* runqueue;
    volatile uint8_t lock;
};

extern struct cpu_state cpus[MAX_CPUS];
extern uint32_t num_cpus;

void ap_entry(void);
void smp_init(void);
void smp_schedule(void);
void smp_add_task(struct task* task, uint32_t cpu_id);

#endif