#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if.h>
#include <errno.h>
#include "capture.h"
#include "../util/util.h"

struct capture_ctx {
    int sockfd;
    char iface[16];
    int promisc;
    int timeout_ms;
    volatile int running;
};

struct capture_ctx *capture_init(const char *iface, int promisc, int timeout_ms) {
    struct capture_ctx *ctx;
    struct sockaddr_ll saddr;
    struct ifreq ifr;
    int sockfd, ret;
    
    sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd < 0) {
        perror("socket");
        return NULL;
    }
    
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    
    ret = ioctl(sockfd, SIOCGIFINDEX, &ifr);
    if (ret < 0) {
        perror("ioctl SIOCGIFINDEX");
        close(sockfd);
        return NULL;
    }
    
    memset(&saddr, 0, sizeof(saddr));
    saddr.sll_family = AF_PACKET;
    saddr.sll_protocol = htons(ETH_P_ALL);
    saddr.sll_ifindex = ifr.ifr_ifindex;
    
    ret = bind(sockfd, (struct sockaddr *)&saddr, sizeof(saddr));
    if (ret < 0) {
        perror("bind");
        close(sockfd);
        return NULL;
    }
    
    if (promisc) {
        ret = ioctl(sockfd, SIOCGIFFLAGS, &ifr);
        if (ret < 0) {
            perror("ioctl SIOCGIFFLAGS");
            close(sockfd);
            return NULL;
        }
        
        ifr.ifr_flags |= IFF_PROMISC;
        ret = ioctl(sockfd, SIOCSIFFLAGS, &ifr);
        if (ret < 0) {
            perror("ioctl SIOCSIFFLAGS promisc");
            close(sockfd);
            return NULL;
        }
    }
    
    if (timeout_ms > 0) {
        struct timeval tv;
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;
        setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    }
    
    ctx = malloc(sizeof(struct capture_ctx));
    if (!ctx) {
        close(sockfd);
        return NULL;
    }
    
    ctx->sockfd = sockfd;
    strncpy(ctx->iface, iface, sizeof(ctx->iface) - 1);
    ctx->promisc = promisc;
    ctx->timeout_ms = timeout_ms;
    ctx->running = 0;
    
    return ctx;
}

int capture_start(struct capture_ctx *ctx, packet_handler handler, void *user_data) {
    uint8_t buffer[MAX_PACKET_SIZE];
    struct packet_info pkt;
    ssize_t n;
    int ret;
    
    if (!ctx || !handler) {
        return -1;
    }
    
    ctx->running = 1;
    
    printf("Starting capture on %s (promisc=%d)\n", ctx->iface, ctx->promisc);
    
    while (ctx->running) {
        n = recv(ctx->sockfd, buffer, sizeof(buffer), 0);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                continue;
            }
            if (errno == EINTR) {
                break;
            }
            perror("recv");
            break;
        }
        
        if (n == 0) {
            continue;
        }
        
        memset(&pkt, 0, sizeof(pkt));
        pkt.data = buffer;
        pkt.len = n;
        pkt.cap_len = n;
        
        ret = packet_parse(&pkt);
        if (ret == 0) {
            handler(&pkt, user_data);
        }
    }
    
    return 0;
}

void capture_stop(struct capture_ctx *ctx) {
    if (ctx) {
        ctx->running = 0;
    }
}

void capture_cleanup(struct capture_ctx *ctx) {
    if (ctx) {
        if (ctx->sockfd >= 0) {
            if (ctx->promisc) {
                struct ifreq ifr;
                memset(&ifr, 0, sizeof(ifr));
                strncpy(ifr.ifr_name, ctx->iface, IFNAMSIZ - 1);
                
                if (ioctl(ctx->sockfd, SIOCGIFFLAGS, &ifr) == 0) {
                    ifr.ifr_flags &= ~IFF_PROMISC;
                    ioctl(ctx->sockfd, SIOCSIFFLAGS, &ifr);
                }
            }
            close(ctx->sockfd);
        }
        free(ctx);
    }
}
