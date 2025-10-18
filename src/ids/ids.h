#ifndef IDS_H
#define IDS_H

#include <stdint.h>
#include <pthread.h>
#include "../capture/packet.h"

#define IDS_SIG_MAX_LEN 128
#define IDS_MAX_SIGS 5000
#define IDS_MAX_SESSIONS 50000
#define IDS_HTTP_HDR_MAX 4096
#define IDS_DNS_NAME_MAX 253
#define IDS_SESSION_TIMEOUT 300
#define IDS_MAX_PATTERN_LEN 100

typedef enum {
    IDS_PROTO_ANY = 0,
    IDS_PROTO_TCP = 6,
    IDS_PROTO_UDP = 17,
    IDS_PROTO_HTTP = 80,
    IDS_PROTO_DNS = 53
} ids_proto_t;

typedef enum {
    IDS_SEV_LOW = 1,
    IDS_SEV_MED = 2, 
    IDS_SEV_HIGH = 3,
    IDS_SEV_CRIT = 4
} ids_sev_t;

typedef enum {
    IDS_ACT_ALERT = 0,
    IDS_ACT_DROP = 1,
    IDS_ACT_REJECT = 2
} ids_act_t;

struct ids_sig {
    uint32_t id;
    char name[48];
    char pattern[IDS_SIG_MAX_LEN];
    uint16_t plen;
    ids_proto_t proto;
    uint16_t sport;
    uint16_t dport;
    ids_sev_t sev;
    ids_act_t act;
    uint8_t enabled;
    uint32_t matches;
    struct ids_sig *next;
};

struct ids_http_sess {
    uint32_t sip;
    uint32_t dip;
    uint16_t sport;
    uint16_t dport;
    char method[12];
    char uri[512];
    char host[128];
    char ua[256];
    uint8_t *body;
    uint32_t blen;
    uint32_t clen;
    time_t last;
    struct ids_http_sess *next;
};

struct ids_dns_sess {
    uint32_t sip;
    uint32_t dip;
    uint16_t sport;
    uint16_t dport;
    uint16_t txid;
    char qname[IDS_DNS_NAME_MAX];
    uint16_t qtype;
    time_t last;
    struct ids_dns_sess *next;
};

struct ids_ctx {
    struct ids_sig *sigs;
    struct ids_http_sess *http_sess;
    struct ids_dns_sess *dns_sess;
    pthread_mutex_t sig_lock;
    pthread_mutex_t sess_lock;
    uint32_t next_sig_id;
    uint64_t total_pkts;
    uint64_t total_matches;
    uint64_t total_drops;
    uint32_t sess_count;
    uint8_t enabled;
};

struct ids_ctx *ids_init(void);
void ids_cleanup(struct ids_ctx *ctx);
int ids_add_sig(struct ids_ctx *ctx, const char *name, const char *pat, ids_proto_t proto, 
               uint16_t sport, uint16_t dport, ids_sev_t sev, ids_act_t act);
int ids_del_sig(struct ids_ctx *ctx, uint32_t sig_id);
int ids_proc_pkt(struct ids_ctx *ctx, struct packet_info *pkt);
int ids_scan_buf(struct ids_ctx *ctx, const uint8_t *data, uint32_t len,
                struct packet_info *pkt, ids_proto_t proto);
int ids_parse_http(struct ids_ctx *ctx, struct packet_info *pkt);
int ids_parse_dns(struct ids_ctx *ctx, struct packet_info *pkt);
struct ids_http_sess *ids_find_http(struct ids_ctx *ctx, struct packet_info *pkt);
struct ids_dns_sess *ids_find_dns(struct ids_ctx *ctx, struct packet_info *pkt);
void ids_clean_sess(struct ids_ctx *ctx);
void ids_dump_sigs(struct ids_ctx *ctx);
void ids_add_default_sigs(struct ids_ctx *ctx);

#endif
