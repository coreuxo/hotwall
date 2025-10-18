#ifndef INTEGRATION_H
#define INTEGRATION_H

#include <sys/types.h>

int system_setup(void);
int system_create_dirs(void);
int system_drop_privileges(void);
int system_write_pidfile(void);
int system_remove_pidfile(void);
int system_daemonize(void);
int system_get_cpu_usage(double *usage);
int system_get_memory_usage(double *usage);
void system_cleanup(void);

#endif
