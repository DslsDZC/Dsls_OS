#ifndef PANIC_H
#define PANIC_H

#include <stdio.h>

// 内核级致命错误处理
static inline void panic(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args); // 或者输出到串口/屏幕
    va_end(args);
    // 停止系统
    for (;;);
}

#endif // PANIC_H