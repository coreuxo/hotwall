#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include "util.h"

uint16_t checksum(uint16_t *addr, int len) {
    int nleft = len;
    uint32_t sum = 0;
    uint16_t *w = addr;
    uint16_t answer = 0;

    while (nleft > 1) {
        sum += *w++;
        nleft -= 2;
    }

    if (nleft == 1) {
        *(unsigned char *)(&answer) = *(unsigned char *)w;
        sum += answer;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = ~sum;
    return answer;
}

uint32_t hash32(uint32_t val) {
    val = ((val >> 16) ^ val) * 0x45d9f3b;
    val = ((val >> 16) ^ val) * 0x45d9f3b;
    val = (val >> 16) ^ val;
    return val;
}

uint64_t get_timestamp_ms(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

void hexdump(const void *data, size_t len) {
    const unsigned char *bytes = data;
    size_t i;
    
    for (i = 0; i < len; i++) {
        if (i > 0 && i % 16 == 0) printf("\n");
        printf("%02x ", bytes[i]);
    }
    printf("\n");
}
