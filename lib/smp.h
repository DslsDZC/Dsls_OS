#pragma once

#define MAX_CPUS      16
#define AP_BOOT_ADDR  0x8

void smp_init();
void smp_schedule();
void smp_add_task(struct task* task, uint32_t cpu_id);
