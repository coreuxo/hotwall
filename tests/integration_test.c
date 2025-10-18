#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "../src/firewall.h"

int integration_test(void) {
    struct firewall_ctx *fw;
    int failures = 0;
    
    printf("\n=== Integration Test ===\n");
    
    fw = firewall_init();
    if (!fw) {
        printf("FAIL: firewall_init\n");
        return 1;
    }
    printf("PASS: firewall_init\n");
    
    int ret = firewall_start(fw);
    if (ret != 0) {
        printf("FAIL: firewall_start returned %d\n", ret);
        failures++;
    } else {
        printf("PASS: firewall_start\n");
    }
    
    sleep(1);
    
    uint64_t stats = firewall_get_stats(fw, 0);
    printf("Packets processed: %lu\n", stats);
    
    firewall_stop(fw);
    firewall_cleanup(fw);
    
    return failures;
}

int main(void) {
    return integration_test();
}
