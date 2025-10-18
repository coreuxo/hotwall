#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include "../src/filter/filter.h"
#include "../src/state/state.h"
#include "../src/nat/nat.h"
#include "../src/ids/ids.h"
#include "../src/qos/qos.h"

#define TEST_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("FAIL: %s:%d: %s\n", __FILE__, __LINE__, msg); \
        failures++; \
    } else { \
        printf("PASS: %s\n", msg); \
    } \
} while(0)

int test_filter_rules(void) {
    struct filter_ctx *filter;
    struct rule r;
    int failures = 0;
    
    printf("\n=== Testing Filter Rules ===\n");
    
    filter = filter_init();
    TEST_ASSERT(filter != NULL, "filter_init");
    
    memset(&r, 0, sizeof(r));
    r.action = RULE_ACTION_ACCEPT;
    r.direction = RULE_DIR_IN;
    r.protocol = PROTO_TCP;
    r.dst_port_start = 80;
    r.dst_port_end = 80;
    r.enabled = 1;
    
    int ret = filter_add_rule(filter, RULE_DIR_IN, &r);
    TEST_ASSERT(ret == 0, "filter_add_rule");
    
    TEST_ASSERT(filter->rules.input.rule_count == 1, "rule_count");
    
    filter_cleanup(filter);
    return failures;
}

int test_state_tracking(void) {
    struct state_ctx *state;
    int failures = 0;
    
    printf("\n=== Testing State Tracking ===\n");
    
    state = state_init(1000);
    TEST_ASSERT(state != NULL, "state_init");
    
    TEST_ASSERT(state_get_connection_count(state) == 0, "initial connection count");
    
    state_cleanup(state);
    return failures;
}

int test_nat_mapping(void) {
    struct nat_ctx *nat;
    int failures = 0;
    
    printf("\n=== Testing NAT ===\n");
    
    nat = nat_init(inet_addr("1.2.3.4"));
    TEST_ASSERT(nat != NULL, "nat_init");
    
    int rule_id = nat_add_rule(nat, NAT_TYPE_SNAT, 
                              inet_addr("192.168.1.0"), inet_addr("255.255.255.0"),
                              0, 0, 0, 0, 0, inet_addr("1.2.3.4"), 0);
    TEST_ASSERT(rule_id > 0, "nat_add_rule");
    
    nat_cleanup(nat);
    return failures;
}

int test_ids_signatures(void) {
    struct ids_ctx *ids;
    int failures = 0;
    
    printf("\n=== Testing IDS ===\n");
    
    ids = ids_init();
    TEST_ASSERT(ids != NULL, "ids_init");
    
    int sig_id = ids_add_sig(ids, "test_sig", "testpattern", IDS_PROTO_HTTP, 0, 80, IDS_SEV_MED, IDS_ACT_ALERT);
    TEST_ASSERT(sig_id > 0, "ids_add_sig");
    
    ids_cleanup(ids);
    return failures;
}

int test_qos_classes(void) {
    struct qos_ctx *qos;
    int failures = 0;
    
    printf("\n=== Testing QoS ===\n");
    
    qos = qos_init();
    TEST_ASSERT(qos != NULL, "qos_init");
    
    int rule_id = qos_add_rule(qos, 0, 0, 0, 0, 0, 0, 0, QOS_CLASS_STANDARD, QOS_ACTION_PASS, 1000);
    TEST_ASSERT(rule_id > 0, "qos_add_rule");
    
    qos_cleanup(qos);
    return failures;
}

int test_packet_parsing(void) {
    int failures = 0;
    
    printf("\n=== Testing Packet Parsing ===\n");
    
    uint8_t test_packet[] = {
        0x45, 0x00, 0x00, 0x3c, 0x00, 0x00, 0x40, 0x00, 
        0x40, 0x06, 0x00, 0x00, 0xc0, 0xa8, 0x01, 0x01,
        0xc0, 0xa8, 0x01, 0x02, 0x04, 0xd2, 0x00, 0x50,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x50, 0x02, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    
    struct packet_info pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.data = test_packet;
    pkt.len = sizeof(test_packet);
    
    int ret = packet_parse(&pkt);
    TEST_ASSERT(ret == 0, "packet_parse");
    TEST_ASSERT(pkt.ip != NULL, "ip_header");
    TEST_ASSERT(pkt.tcp != NULL, "tcp_header");
    TEST_ASSERT(pkt.src_ip == inet_addr("192.168.1.1"), "src_ip");
    TEST_ASSERT(pkt.dst_ip == inet_addr("192.168.1.2"), "dst_ip");
    TEST_ASSERT(pkt.src_port == 1234, "src_port");
    TEST_ASSERT(pkt.dst_port == 80, "dst_port");
    
    return failures;
}

int main(void) {
    int total_failures = 0;
    
    printf("Firewall Test Suite\n");
    printf("===================\n");
    
    total_failures += test_filter_rules();
    total_failures += test_state_tracking();
    total_failures += test_nat_mapping();
    total_failures += test_ids_signatures();
    total_failures += test_qos_classes();
    total_failures += test_packet_parsing();
    
    printf("\n=== Test Summary ===\n");
    if (total_failures == 0) {
        printf("ALL TESTS PASSED\n");
    } else {
        printf("%d TESTS FAILED\n", total_failures);
    }
    
    return total_failures;
}
