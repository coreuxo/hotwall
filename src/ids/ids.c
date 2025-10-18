#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <pthread.h>
#include <arpa/inet.h>
#include "ids.h"

struct ids_ctx *ids_init(void) {
    struct ids_ctx *ctx;
    int ret;
    
    ctx = calloc(1, sizeof(struct ids_ctx));
    if (!ctx) goto fail;
    
    ret = pthread_mutex_init(&ctx->sig_lock, NULL);
    if (ret != 0) goto fail;
    
    ret = pthread_mutex_init(&ctx->sess_lock, NULL);
    if (ret != 0) {
        pthread_mutex_destroy(&ctx->sig_lock);
        goto fail;
    }
    
    ctx->next_sig_id = 1;
    ctx->enabled = 1;
    ctx->sess_count = 0;
    
    ids_add_default_sigs(ctx);
    
    return ctx;

fail:
    if (ctx) free(ctx);
    return NULL;
}

void ids_cleanup(struct ids_ctx *ctx) {
    struct ids_sig *sig, *sig_next;
    struct ids_http_sess *http, *http_next;
    struct ids_dns_sess *dns, *dns_next;
    
    if (!ctx) return;
    
    pthread_mutex_lock(&ctx->sig_lock);
    sig = ctx->sigs;
    while (sig) {
        sig_next = sig->next;
        free(sig);
        sig = sig_next;
    }
    pthread_mutex_unlock(&ctx->sig_lock);
    
    pthread_mutex_lock(&ctx->sess_lock);
    http = ctx->http_sess;
    while (http) {
        http_next = http->next;
        if (http->body) free(http->body);
        free(http);
        http = http_next;
    }
    
    dns = ctx->dns_sess;
    while (dns) {
        dns_next = dns->next;
        free(dns);
        dns = dns_next;
    }
    pthread_mutex_unlock(&ctx->sess_lock);
    
    pthread_mutex_destroy(&ctx->sig_lock);
    pthread_mutex_destroy(&ctx->sess_lock);
    free(ctx);
}

void ids_add_default_sigs(struct ids_ctx *ctx) {
    ids_add_sig(ctx, "sql_inject_union", "union select", IDS_PROTO_HTTP, 0, 80, IDS_SEV_HIGH, IDS_ACT_DROP);
    ids_add_sig(ctx, "sql_inject_or", "or 1=1", IDS_PROTO_HTTP, 0, 80, IDS_SEV_HIGH, IDS_ACT_DROP);
    ids_add_sig(ctx, "xss_script", "<script>", IDS_PROTO_HTTP, 0, 80, IDS_SEV_HIGH, IDS_ACT_DROP);
    ids_add_sig(ctx, "xss_onload", "onload=", IDS_PROTO_HTTP, 0, 80, IDS_SEV_MED, IDS_ACT_DROP);
    ids_add_sig(ctx, "path_traversal", "../", IDS_PROTO_HTTP, 0, 80, IDS_SEV_MED, IDS_ACT_DROP);
    ids_add_sig(ctx, "cmd_inject_bash", "/bin/bash", IDS_PROTO_HTTP, 0, 80, IDS_SEV_HIGH, IDS_ACT_DROP);
    ids_add_sig(ctx, "cmd_inject_cmd", "cmd.exe", IDS_PROTO_HTTP, 0, 80, IDS_SEV_HIGH, IDS_ACT_DROP);
    ids_add_sig(ctx, "ssh_brute", "SSH-", IDS_PROTO_TCP, 0, 22, IDS_SEV_MED, IDS_ACT_ALERT);
    ids_add_sig(ctx, "nmap_scan", "nmap", IDS_PROTO_ANY, 0, 0, IDS_SEV_LOW, IDS_ACT_ALERT);
    ids_add_sig(ctx, "metasploit", "metasploit", IDS_PROTO_ANY, 0, 0, IDS_SEV_HIGH, IDS_ACT_DROP);
    ids_add_sig(ctx, "shellcode_nops", "\x90\x90\x90", IDS_PROTO_ANY, 0, 0, IDS_SEV_CRIT, IDS_ACT_DROP);
    ids_add_sig(ctx, "dns_tunnel_b64", "base64", IDS_PROTO_DNS, 0, 53, IDS_SEV_MED, IDS_ACT_ALERT);
    ids_add_sig(ctx, "data_exfil_pass", "password=", IDS_PROTO_HTTP, 0, 80, IDS_SEV_HIGH, IDS_ACT_DROP);
    ids_add_sig(ctx, "sqli_comment", "--", IDS_PROTO_HTTP, 0, 80, IDS_SEV_MED, IDS_ACT_DROP);
    ids_add_sig(ctx, "lfi_include", "include(", IDS_PROTO_HTTP, 0, 80, IDS_SEV_HIGH, IDS_ACT_DROP);
}

int ids_add_sig(struct ids_ctx *ctx, const char *name, const char *pat, ids_proto_t proto, 
               uint16_t sport, uint16_t dport, ids_sev_t sev, ids_act_t act) {
    struct ids_sig *sig, *new_sig;
    size_t name_len, pat_len;
    
    if (!ctx || !name || !pat) return -1;
    
    name_len = strlen(name);
    pat_len = strlen(pat);
    if (name_len == 0 || name_len >= sizeof(new_sig->name) || 
        pat_len == 0 || pat_len >= sizeof(new_sig->pattern)) {
        return -1;
    }
    
    new_sig = calloc(1, sizeof(struct ids_sig));
    if (!new_sig) return -1;
    
    strncpy(new_sig->name, name, sizeof(new_sig->name) - 1);
    strncpy(new_sig->pattern, pat, sizeof(new_sig->pattern) - 1);
    new_sig->plen = (uint16_t)pat_len;
    new_sig->proto = proto;
    new_sig->sport = sport;
    new_sig->dport = dport;
    new_sig->sev = sev;
    new_sig->act = act;
    new_sig->enabled = 1;
    
    pthread_mutex_lock(&ctx->sig_lock);
    
    new_sig->id = ctx->next_sig_id++;
    if (!ctx->sigs) {
        ctx->sigs = new_sig;
    } else {
        sig = ctx->sigs;
        while (sig->next) sig = sig->next;
        sig->next = new_sig;
    }
    
    pthread_mutex_unlock(&ctx->sig_lock);
    return new_sig->id;
}

int ids_del_sig(struct ids_ctx *ctx, uint32_t sig_id) {
    struct ids_sig *sig, *prev = NULL;
    int ret = -1;
    
    if (!ctx) return -1;
    
    pthread_mutex_lock(&ctx->sig_lock);
    
    sig = ctx->sigs;
    while (sig) {
        if (sig->id == sig_id) {
            if (prev) {
                prev->next = sig->next;
            } else {
                ctx->sigs = sig->next;
            }
            free(sig);
            ret = 0;
            break;
        }
        prev = sig;
        sig = sig->next;
    }
    
    pthread_mutex_unlock(&ctx->sig_lock);
    return ret;
}

static int bm_search(const uint8_t *txt, uint32_t tlen, const char *pat, uint16_t plen) {
    uint32_t bad_char[256];
    uint32_t i, j;
    
    if (plen == 0 || tlen < plen) return -1;
    
    for (i = 0; i < 256; i++) bad_char[i] = plen;
    for (i = 0; i < plen - 1; i++) bad_char[(uint8_t)pat[i]] = plen - i - 1;
    
    j = 0;
    while (j <= tlen - plen) {
        i = plen - 1;
        while (i > 0 && pat[i] == txt[j + i]) i--;
        if (i == 0 && pat[0] == txt[j]) return j;
        j += bad_char[(uint8_t)txt[j + plen - 1]];
    }
    
    return -1;
}

int ids_scan_buf(struct ids_ctx *ctx, const uint8_t *data, uint32_t len,
                struct packet_info *pkt, ids_proto_t proto) {
    struct ids_sig *sig;
    int match_pos;
    int action = IDS_ACT_ALERT;
    ids_sev_t max_sev = IDS_SEV_LOW;
    char sip[16], dip[16];
    
    if (!ctx || !data || len == 0 || !pkt) return IDS_ACT_ALERT;
    
    inet_ntop(AF_INET, &pkt->src_ip, sip, sizeof(sip));
    inet_ntop(AF_INET, &pkt->dst_ip, dip, sizeof(dip));
    
    pthread_mutex_lock(&ctx->sig_lock);
    
    sig = ctx->sigs;
    while (sig) {
        if (!sig->enabled) {
            sig = sig->next;
            continue;
        }
        
        if (sig->proto != IDS_PROTO_ANY && sig->proto != proto) {
            sig = sig->next;
            continue;
        }
        
        if (sig->sport != 0 && sig->sport != pkt->src_port) {
            sig = sig->next;
            continue;
        }
        
        if (sig->dport != 0 && sig->dport != pkt->dst_port) {
            sig = sig->next;
            continue;
        }
        
        if (sig->plen > len) {
            sig = sig->next;
            continue;
        }
        
        match_pos = bm_search(data, len, sig->pattern, sig->plen);
        if (match_pos >= 0) {
            sig->matches++;
            ctx->total_matches++;
            
            if (sig->sev > max_sev) {
                max_sev = sig->sev;
                action = sig->act;
            }
            
            const char *sev_str;
            switch (sig->sev) {
                case IDS_SEV_LOW: sev_str = "LOW"; break;
                case IDS_SEV_MED: sev_str = "MED"; break;
                case IDS_SEV_HIGH: sev_str = "HIGH"; break;
                case IDS_SEV_CRIT: sev_str = "CRIT"; break;
                default: sev_str = "UNK"; break;
            }
            
            const char *proto_str;
            switch (proto) {
                case IDS_PROTO_HTTP: proto_str = "HTTP"; break;
                case IDS_PROTO_DNS: proto_str = "DNS"; break;
                case IDS_PROTO_TCP: proto_str = "TCP"; break;
                case IDS_PROTO_UDP: proto_str = "UDP"; break;
                default: proto_str = "RAW"; break;
            }
            
            printf("IDS: [%s] %s %s:%d->%s:%d %s @%d\n", 
                   sev_str, proto_str, sip, pkt->src_port, dip, pkt->dst_port,
                   sig->name, match_pos);
            
            if (sig->act == IDS_ACT_DROP) ctx->total_drops++;
        }
        
        sig = sig->next;
    }
    
    pthread_mutex_unlock(&ctx->sig_lock);
    return action;
}

struct ids_http_sess *ids_find_http(struct ids_ctx *ctx, struct packet_info *pkt) {
    struct ids_http_sess *sess;
    
    if (!ctx || !pkt) return NULL;
    
    pthread_mutex_lock(&ctx->sess_lock);
    
    sess = ctx->http_sess;
    while (sess) {
        if (sess->sip == pkt->src_ip && sess->dip == pkt->dst_ip &&
            sess->sport == pkt->src_port && sess->dport == pkt->dst_port) {
            sess->last = time(NULL);
            pthread_mutex_unlock(&ctx->sess_lock);
            return sess;
        }
        sess = sess->next;
    }
    
    pthread_mutex_unlock(&ctx->sess_lock);
    return NULL;
}

struct ids_dns_sess *ids_find_dns(struct ids_ctx *ctx, struct packet_info *pkt) {
    struct ids_dns_sess *sess;
    
    if (!ctx || !pkt) return NULL;
    
    pthread_mutex_lock(&ctx->sess_lock);
    
    sess = ctx->dns_sess;
    while (sess) {
        if (sess->sip == pkt->src_ip && sess->dip == pkt->dst_ip &&
            sess->sport == pkt->src_port && sess->dport == pkt->dst_port) {
            sess->last = time(NULL);
            pthread_mutex_unlock(&ctx->sess_lock);
            return sess;
        }
        sess = sess->next;
    }
    
    pthread_mutex_unlock(&ctx->sess_lock);
    return NULL;
}

int ids_parse_http(struct ids_ctx *ctx, struct packet_info *pkt) {
    struct ids_http_sess *sess;
    uint8_t *data = pkt->payload;
    uint32_t len = pkt->payload_len;
    char *hdr_copy = NULL;
    char *line, *saveptr, *key, *val;
    int action = IDS_ACT_ALERT;
    int ret = -1;
    
    if (!data || len < 10 || len > IDS_HTTP_HDR_MAX) return IDS_ACT_ALERT;
    
    sess = ids_find_http(ctx, pkt);
    if (!sess) {
        if (ctx->sess_count >= IDS_MAX_SESSIONS) return IDS_ACT_ALERT;
        
        sess = calloc(1, sizeof(struct ids_http_sess));
        if (!sess) return IDS_ACT_ALERT;
        
        sess->sip = pkt->src_ip;
        sess->dip = pkt->dst_ip;
        sess->sport = pkt->src_port;
        sess->dport = pkt->dst_port;
        sess->last = time(NULL);
        
        pthread_mutex_lock(&ctx->sess_lock);
        sess->next = ctx->http_sess;
        ctx->http_sess = sess;
        ctx->sess_count++;
        pthread_mutex_unlock(&ctx->sess_lock);
    }
    
    hdr_copy = malloc(len + 1);
    if (!hdr_copy) goto cleanup;
    memcpy(hdr_copy, data, len);
    hdr_copy[len] = '\0';
    
    line = strtok_r(hdr_copy, "\r\n", &saveptr);
    if (!line) goto cleanup;
    
    if (sscanf(line, "%11s %511s", sess->method, sess->uri) == 2) {
        action = ids_scan_buf(ctx, (uint8_t*)sess->uri, strlen(sess->uri), pkt, IDS_PROTO_HTTP);
        if (action == IDS_ACT_DROP) goto success;
    }
    
    while ((line = strtok_r(NULL, "\r\n", &saveptr)) != NULL) {
        if (strlen(line) == 0) break;
        
        key = line;
        val = strchr(line, ':');
        if (!val) continue;
        
        *val = '\0';
        val++;
        while (*val && isspace(*val)) val++;
        
        if (strcasecmp(key, "Host") == 0) {
            strncpy(sess->host, val, sizeof(sess->host) - 1);
        } else if (strcasecmp(key, "User-Agent") == 0) {
            strncpy(sess->ua, val, sizeof(sess->ua) - 1);
            action = ids_scan_buf(ctx, (uint8_t*)val, strlen(val), pkt, IDS_PROTO_HTTP);
            if (action == IDS_ACT_DROP) goto success;
        } else if (strcasecmp(key, "Content-Length") == 0) {
            sess->clen = atoi(val);
        }
    }
    
    char *body = strstr(hdr_copy, "\r\n\r\n");
    if (body) {
        body += 4;
        uint32_t body_len = len - (body - hdr_copy);
        if (body_len > 0 && body_len <= 8192) {
            action = ids_scan_buf(ctx, (uint8_t*)body, body_len, pkt, IDS_PROTO_HTTP);
        }
    }

success:
    ret = action;
cleanup:
    if (hdr_copy) free(hdr_copy);
    return ret;
}

int ids_parse_dns(struct ids_ctx *ctx, struct packet_info *pkt) {
    struct ids_dns_sess *sess;
    uint8_t *data = pkt->payload;
    uint32_t len = pkt->payload_len;
    uint16_t flags, qdcount;
    char name[IDS_DNS_NAME_MAX];
    int i, pos = 0;
    int action = IDS_ACT_ALERT;
    
    if (len < 12) return IDS_ACT_ALERT;
    
    sess = ids_find_dns(ctx, pkt);
    if (!sess) {
        if (ctx->sess_count >= IDS_MAX_SESSIONS) return IDS_ACT_ALERT;
        
        sess = calloc(1, sizeof(struct ids_dns_sess));
        if (!sess) return IDS_ACT_ALERT;
        
        sess->sip = pkt->src_ip;
        sess->dip = pkt->dst_ip;
        sess->sport = pkt->src_port;
        sess->dport = pkt->dst_port;
        sess->last = time(NULL);
        
        pthread_mutex_lock(&ctx->sess_lock);
        sess->next = ctx->dns_sess;
        ctx->dns_sess = sess;
        ctx->sess_count++;
        pthread_mutex_unlock(&ctx->sess_lock);
    }
    
    sess->txid = (data[0] << 8) | data[1];
    flags = (data[2] << 8) | data[3];
    qdcount = (data[4] << 8) | data[5];
    
    pos = 12;
    for (i = 0; i < qdcount && pos < len - 4; i++) {
        int name_pos = 0;
        while (pos < len && data[pos] != 0) {
            int label_len = data[pos++];
            if (label_len == 0 || pos + label_len > len || name_pos + label_len + 1 >= IDS_DNS_NAME_MAX) 
                break;
            
            if (name_pos > 0) name[name_pos++] = '.';
            memcpy(name + name_pos, data + pos, label_len);
            name_pos += label_len;
            pos += label_len;
        }
        if (pos >= len) break;
        
        name[name_pos] = '\0';
        pos++;
        
        if (pos + 4 <= len) {
            sess->qtype = (data[pos] << 8) | data[pos + 1];
            pos += 4;
        }
        
        strncpy(sess->qname, name, sizeof(sess->qname) - 1);
        action = ids_scan_buf(ctx, (uint8_t*)name, strlen(name), pkt, IDS_PROTO_DNS);
        if (action == IDS_ACT_DROP) break;
    }
    
    return action;
}

int ids_proc_pkt(struct ids_ctx *ctx, struct packet_info *pkt) {
    int action = IDS_ACT_ALERT;
    
    if (!ctx || !pkt || !ctx->enabled) return IDS_ACT_ALERT;
    
    ctx->total_pkts++;
    
    if (pkt->is_tcp && pkt->dst_port == 80) {
        action = ids_parse_http(ctx, pkt);
    } else if (pkt->is_tcp && pkt->dst_port == 443) {
        action = ids_scan_buf(ctx, pkt->payload, pkt->payload_len, pkt, IDS_PROTO_HTTP);
    } else if (pkt->is_udp && pkt->dst_port == 53) {
        action = ids_parse_dns(ctx, pkt);
    } else {
        action = ids_scan_buf(ctx, pkt->payload, pkt->payload_len, pkt, IDS_PROTO_ANY);
    }
    
    return action;
}

void ids_clean_sess(struct ids_ctx *ctx) {
    struct ids_http_sess *http, *http_prev, *http_next;
    struct ids_dns_sess *dns, *dns_prev, *dns_next;
    time_t now = time(NULL);
    uint32_t cleaned = 0;
    
    if (!ctx) return;
    
    pthread_mutex_lock(&ctx->sess_lock);
    
    http_prev = NULL;
    http = ctx->http_sess;
    while (http) {
        http_next = http->next;
        if (now - http->last > IDS_SESSION_TIMEOUT) {
            if (http_prev) {
                http_prev->next = http_next;
            } else {
                ctx->http_sess = http_next;
            }
            if (http->body) free(http->body);
            free(http);
            cleaned++;
            ctx->sess_count--;
        } else {
            http_prev = http;
        }
        http = http_next;
    }
    
    dns_prev = NULL;
    dns = ctx->dns_sess;
    while (dns) {
        dns_next = dns->next;
        if (now - dns->last > 60) {
            if (dns_prev) {
                dns_prev->next = dns_next;
            } else {
                ctx->dns_sess = dns_next;
            }
            free(dns);
            cleaned++;
            ctx->sess_count--;
        } else {
            dns_prev = dns;
        }
        dns = dns_next;
    }
    
    pthread_mutex_unlock(&ctx->sess_lock);
    
    if (cleaned > 0) {
        printf("IDS: cleaned %u stale sessions, %u active\n", cleaned, ctx->sess_count);
    }
}

void ids_dump_sigs(struct ids_ctx *ctx) {
    struct ids_sig *sig;
    
    if (!ctx) return;
    
    printf("\n=== IDS Signatures (%lu packets, %lu matches, %lu drops) ===\n",
           ctx->total_pkts, ctx->total_matches, ctx->total_drops);
    printf("ID  Name                          Proto Ports    Sev  Act    Matches\n");
    printf("--- ----------------------------- ----- -------- ---  ---    -------\n");
    
    pthread_mutex_lock(&ctx->sig_lock);
    
    sig = ctx->sigs;
    while (sig) {
        const char *proto_str;
        switch (sig->proto) {
            case IDS_PROTO_ANY: proto_str = "ANY"; break;
            case IDS_PROTO_TCP: proto_str = "TCP"; break;
            case IDS_PROTO_UDP: proto_str = "UDP"; break;
            case IDS_PROTO_HTTP: proto_str = "HTTP"; break;
            case IDS_PROTO_DNS: proto_str = "DNS"; break;
            default: proto_str = "UNK"; break;
        }
        
        const char *sev_str;
        switch (sig->sev) {
            case IDS_SEV_LOW: sev_str = "LOW"; break;
            case IDS_SEV_MED: sev_str = "MED"; break;
            case IDS_SEV_HIGH: sev_str = "HIGH"; break;
            case IDS_SEV_CRIT: sev_str = "CRIT"; break;
            default: sev_str = "UNK"; break;
        }
        
        const char *act_str;
        switch (sig->act) {
            case IDS_ACT_ALERT: act_str = "ALERT"; break;
            case IDS_ACT_DROP: act_str = "DROP"; break;
            case IDS_ACT_REJECT: act_str = "REJECT"; break;
            default: act_str = "UNK"; break;
        }
        
        char ports[16];
        if (sig->sport == 0 && sig->dport == 0) {
            strcpy(ports, "any");
        } else if (sig->sport == 0) {
            snprintf(ports, sizeof(ports), "->%d", sig->dport);
        } else if (sig->dport == 0) {
            snprintf(ports, sizeof(ports), "%d->", sig->sport);
        } else {
            snprintf(ports, sizeof(ports), "%d->%d", sig->sport, sig->dport);
        }
        
        printf("%-3d %-30s %-5s %-8s %-3s  %-6s %-7d\n",
               sig->id, sig->name, proto_str, ports, sev_str, act_str, sig->matches);
        
        sig = sig->next;
    }
    
    pthread_mutex_unlock(&ctx->sig_lock);
}
