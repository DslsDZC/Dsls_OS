#pragma once
#include <stdint.h>

// APIC初始化
void apic_init();

// 发送INIT IPI
void apic_send_init(uint32_t cpu_id);

// 发送STARTUP IPI
void apic_send_startup(uint32_t cpu_id, uint8_t vector);

// 检查CPU是否存在
int apic_is_cpu_present(uint32_t cpu_id);

// APIC定时器配置
void apic_timer_init(uint32_t frequency);