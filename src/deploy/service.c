#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <syslog.h>
#include "service.h"
#include "../util/debug.h"

static int running = 1;

void signal_handler(int sig) {
    switch (sig) {
        case SIGINT:
        case SIGTERM:
            running = 0;
            syslog(LOG_INFO, "Received shutdown signal");
            break;
        case SIGHUP:
            syslog(LOG_INFO, "Received reload signal");
            break;
    }
}

int service_install(void) {
    FILE *file;
    const char *service_file = 
        "[Unit]\n"
        "Description=Firewall Service\n"
        "After=network.target\n"
        "\n"
        "[Service]\n"
        "Type=simple\n"
        "ExecStart=/usr/local/bin/firewall -D\n"
        "ExecReload=/bin/kill -HUP $MAINPID\n"
        "Restart=on-failure\n"
        "RestartSec=5s\n"
        "\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n";
    
    file = fopen("/etc/systemd/system/firewall.service", "w");
    if (!file) {
        ERROR("Failed to create service file: %m\n");
        return -1;
    }
    
    fputs(service_file, file);
    fclose(file);
    
    printf("Service file created at /etc/systemd/system/firewall.service\n");
    printf("Run 'systemctl daemon-reload' and 'systemctl enable firewall' to enable\n");
    
    return 0;
}

int service_uninstall(void) {
    if (unlink("/etc/systemd/system/firewall.service") != 0) {
        if (errno != ENOENT) {
            ERROR("Failed to remove service file: %m\n");
            return -1;
        }
    }
    
    printf("Service file removed\n");
    return 0;
}

int service_setup_logging(void) {
    openlog("firewall", LOG_PID | LOG_NDELAY, LOG_DAEMON);
    syslog(LOG_INFO, "Firewall service starting");
    return 0;
}

int service_main(int argc, char **argv) {
    struct firewall_ctx *fw;
    int ret;
    
    service_setup_logging();
    
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGHUP, signal_handler);
    
    syslog(LOG_INFO, "Initializing firewall service");
    
    fw = firewall_init();
    if (!fw) {
        syslog(LOG_ERR, "Failed to initialize firewall");
        return 1;
    }
    
    firewall_set_daemon_mode(fw, 1);
    
    ret = firewall_start(fw);
    if (ret != 0) {
        syslog(LOG_ERR, "Failed to start firewall: %d", ret);
        firewall_cleanup(fw);
        return 1;
    }
    
    syslog(LOG_INFO, "Firewall service started successfully");
    
    while (running) {
        sleep(1);
    }
    
    syslog(LOG_INFO, "Firewall service stopping");
    firewall_stop(fw);
    firewall_cleanup(fw);
    
    syslog(LOG_INFO, "Firewall service stopped");
    closelog();
    
    return 0;
}

void service_cleanup(void) {
    closelog();
}
