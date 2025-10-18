#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/resource.h>
#include "integration.h"
#include "../util/debug.h"

int system_setup(void) {
    struct rlimit rlim;
    int ret;
    
    printf("Setting up firewall system...\n");
    
    rlim.rlim_cur = RLIM_INFINITY;
    rlim.rlim_max = RLIM_INFINITY;
    ret = setrlimit(RLIMIT_CORE, &rlim);
    if (ret != 0) {
        DBG("Could not set core dump limit: %m\n");
    }
    
    rlim.rlim_cur = 65536;
    rlim.rlim_max = 65536;
    ret = setrlimit(RLIMIT_NOFILE, &rlim);
    if (ret != 0) {
        DBG("Could not set file descriptor limit: %m\n");
    }
    
    ret = system_create_dirs();
    if (ret != 0) {
        ERROR("Failed to create system directories\n");
        return -1;
    }
    
    ret = system_drop_privileges();
    if (ret != 0) {
        ERROR("Failed to drop privileges\n");
        return -1;
    }
    
    signal(SIGPIPE, SIG_IGN);
    
    printf("System setup complete\n");
    return 0;
}

int system_create_dirs(void) {
    const char *dirs[] = {
        "/var/log/firewall",
        "/var/run/firewall",
        "/etc/firewall",
        NULL
    };
    
    int i;
    
    for (i = 0; dirs[i] != NULL; i++) {
        if (mkdir(dirs[i], 0755) != 0) {
            if (errno != EEXIST) {
                ERROR("Failed to create directory %s: %m\n", dirs[i]);
                return -1;
            }
        }
        DBG("Created directory: %s\n", dirs[i]);
    }
    
    return 0;
}

int system_drop_privileges(void) {
    if (getuid() != 0) {
        DBG("Not running as root, privileges already dropped\n");
        return 0;
    }
    
    if (setgid(65534) != 0) {
        ERROR("Failed to set group ID: %m\n");
        return -1;
    }
    
    if (setuid(65534) != 0) {
        ERROR("Failed to set user ID: %m\n");
        return -1;
    }
    
    DBG("Dropped privileges to nobody\n");
    return 0;
}

int system_write_pidfile(void) {
    FILE *file;
    pid_t pid = getpid();
    
    file = fopen("/var/run/firewall/firewall.pid", "w");
    if (!file) {
        ERROR("Failed to create pid file: %m\n");
        return -1;
    }
    
    fprintf(file, "%d\n", pid);
    fclose(file);
    
    DBG("Wrote PID %d to pid file\n", pid);
    return 0;
}

int system_remove_pidfile(void) {
    if (unlink("/var/run/firewall/firewall.pid") != 0) {
        if (errno != ENOENT) {
            ERROR("Failed to remove pid file: %m\n");
            return -1;
        }
    }
    
    DBG("Removed pid file\n");
    return 0;
}

int system_daemonize(void) {
    pid_t pid;
    int fd;
    
    pid = fork();
    if (pid < 0) {
        ERROR("Failed to fork: %m\n");
        return -1;
    }
    
    if (pid > 0) {
        exit(0);
    }
    
    if (setsid() < 0) {
        ERROR("Failed to create session: %m\n");
        return -1;
    }
    
    pid = fork();
    if (pid < 0) {
        ERROR("Failed to fork again: %m\n");
        return -1;
    }
    
    if (pid > 0) {
        exit(0);
    }
    
    umask(0);
    
    if (chdir("/") != 0) {
        ERROR("Failed to change directory: %m\n");
        return -1;
    }
    
    for (fd = 0; fd < 3; fd++) {
        close(fd);
    }
    
    fd = open("/dev/null", O_RDWR);
    if (fd < 0) {
        ERROR("Failed to open /dev/null: %m\n");
        return -1;
    }
    
    dup2(fd, STDIN_FILENO);
    dup2(fd, STDOUT_FILENO);
    dup2(fd, STDERR_FILENO);
    
    if (fd > 2) {
        close(fd);
    }
    
    DBG("Daemonized successfully\n");
    return 0;
}

int system_get_cpu_usage(double *usage) {
    static unsigned long long last_total = 0;
    static unsigned long long last_idle = 0;
    FILE *file;
    char line[256];
    unsigned long long user, nice, system, idle, iowait, irq, softirq;
    unsigned long long total, total_diff, idle_diff;
    
    file = fopen("/proc/stat", "r");
    if (!file) {
        return -1;
    }
    
    if (!fgets(line, sizeof(line), file)) {
        fclose(file);
        return -1;
    }
    
    fclose(file);
    
    if (sscanf(line, "cpu %llu %llu %llu %llu %llu %llu %llu",
               &user, &nice, &system, &idle, &iowait, &irq, &softirq) != 7) {
        return -1;
    }
    
    total = user + nice + system + idle + iowait + irq + softirq;
    
    if (last_total > 0) {
        total_diff = total - last_total;
        idle_diff = idle - last_idle;
        
        if (total_diff > 0) {
            *usage = 100.0 * (1.0 - ((double)idle_diff / total_diff));
        } else {
            *usage = 0.0;
        }
    } else {
        *usage = 0.0;
    }
    
    last_total = total;
    last_idle = idle;
    
    return 0;
}

int system_get_memory_usage(double *usage) {
    FILE *file;
    char line[256];
    unsigned long long total, free, buffers, cached;
    
    file = fopen("/proc/meminfo", "r");
    if (!file) {
        return -1;
    }
    
    total = free = buffers = cached = 0;
    
    while (fgets(line, sizeof(line), file)) {
        if (strncmp(line, "MemTotal:", 9) == 0) {
            sscanf(line + 9, "%llu", &total);
        } else if (strncmp(line, "MemFree:", 8) == 0) {
            sscanf(line + 8, "%llu", &free);
        } else if (strncmp(line, "Buffers:", 8) == 0) {
            sscanf(line + 8, "%llu", &buffers);
        } else if (strncmp(line, "Cached:", 7) == 0) {
            sscanf(line + 7, "%llu", &cached);
        }
    }
    
    fclose(file);
    
    if (total > 0) {
        unsigned long long used = total - free - buffers - cached;
        *usage = 100.0 * ((double)used / total);
    } else {
        *usage = 0.0;
    }
    
    return 0;
}

void system_cleanup(void) {
    system_remove_pidfile();
    DBG("System cleanup complete\n");
}
