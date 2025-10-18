#ifndef DEBUG_H
#define DEBUG_H

#include <stdio.h>
#include <time.h>

#define DEBUG_LEVEL 0

#if DEBUG_LEVEL > 0
#define DBG(fmt, ...) do { \
    fprintf(stderr, "[DEBUG %s:%d] " fmt, __FILE__, __LINE__, ##__VA_ARGS__); \
} while(0)
#else
#define DBG(fmt, ...)
#endif

#define LOG(fmt, ...) do { \
    time_t t = time(NULL); \
    struct tm *tm = localtime(&t); \
    fprintf(stderr, "[%04d-%02d-%02d %02d:%02d:%02d] " fmt, \
            tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday, \
            tm->tm_hour, tm->tm_min, tm->tm_sec, ##__VA_ARGS__); \
} while(0)

#define ERROR(fmt, ...) do { \
    time_t t = time(NULL); \
    struct tm *tm = localtime(&t); \
    fprintf(stderr, "[ERROR %s:%d] " fmt, __FILE__, __LINE__, ##__VA_ARGS__); \
} while(0)

#endif
