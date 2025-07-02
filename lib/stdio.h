#ifndef STDIO_H
#define STDIO_H

#include <stdarg.h>
#include <stddef.h>

// 定义 FILE 结构体的占位符（可根据实际实现调整）
typedef struct _FILE FILE;
// 定义 fpos_t 结构体的占位符（可根据实际实现调整）
typedef struct {    long __pos;
} fpos_t;

// 简单的输出函数声明（适用于裸机或UEFI环境，可根据实际实现调整）
int printf(const char *fmt, ...);
int vprintf(const char *fmt, va_list args);
// 其他常用的标准输入输出函数声明
int scanf(const char *fmt, ...);
int vscanf(const char *fmt, va_list args);
// 读取字符串
char *gets(char *s);
// 写入字符串
int puts(const char *s);
// 读取字符
int getchar(void);
// 写入字符
int getc(FILE *stream);
int putc(int c, FILE *stream);
// 文件操作
FILE *fopen(const char *filename, const char *mode);
int fclose(FILE *stream);
size_t fread(void *ptr, size_t size, size_t count, FILE *stream);
size_t fwrite(const void *ptr, size_t size, size_t count, FILE *stream);
int fseek(FILE *stream, long offset, int whence);
long ftell(FILE *stream);
void rewind(FILE *stream);
// 错误处理
int ferror(FILE *stream);
// 清除错误标志
void clearerr(FILE *stream);
// 文件描述符操作
int fileno(FILE *stream);
// 文件状态
int feof(FILE *stream);
// 文件缓冲
int fflush(FILE *stream);
// 设置缓冲模式
int setvbuf(FILE *stream, char *buf, int mode, size_t size);
// 获取文件状态
int fstat(int fd, struct stat *statbuf);
// 获取文件描述符
int fileno(FILE *stream);
// 文件锁
int flock(int fd, int operation);
// 文件操作函数
int fcntl(int fd, int cmd, ... /* arg */);
// 文件流操作
int fileno_unlocked(FILE *stream);
// 设置文件流位置
int fsetpos(FILE *stream, const fpos_t *pos);
// 获取文件流位置       
int fgetpos(FILE *stream, fpos_t *pos); 
// 其他常用的标准输入输出函数声明
int sprintf(char *str, const char *fmt, ...);
int vsprintf(char *str, const char *fmt, va_list args);
int snprintf(char *str, size_t size, const char *fmt, ...);
int vsnprintf(char *str, size_t size, const char *fmt, va_list args);
// 文件流操作
FILE *tmpfile(void);
// 获取标准输入输出流
FILE *stdin;
FILE *stdout;
FILE *stderr;
// 文件流操作
int fileno(FILE *stream);
// 设置文件流缓冲   
int setbuf(FILE *stream, char *buf);
// 设置文件流缓冲模式
int setvbuf(FILE *stream, char *buf, int mode, size_t size);    
// 获取文件流位置
long ftell(FILE *stream);
// 设置文件流位置
int fseek(FILE *stream, long offset, int whence);   
// 重置文件流位置
void rewind(FILE *stream);
// 读取文件流
size_t fread(void *ptr, size_t size, size_t count, FILE *stream);
// 写入文件流           
size_t fwrite(const void *ptr, size_t size, size_t count, FILE *stream);
// 读取字符
int fgetc(FILE *stream);
// 写入字符
int fputc(int c, FILE *stream);

// 你可以根据需要添加 putchar、puts 等声明
int putchar(int c);
int puts(const char *s);

#endif // STDIO_H