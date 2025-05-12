#pragma once
#include <stdint.h>

void apic_init();

void apic_send_init(uint32_t cpu_id);

void apic_send_startup(uint32_t cpu_id, uint8_t vector);

int apic_is_cpu_present(uint32_t cpu_id);

void apic_timer_init(uint32_t frequency);

