#ifndef UTIL_H
#define UTIL_H

#include <stdint.h>
#include <time.h>

uint16_t checksum(uint16_t *addr, int len);
uint32_t hash32(uint32_t val);
uint64_t get_timestamp_ms(void);
void hexdump(const void *data, size_t len);

#endif
