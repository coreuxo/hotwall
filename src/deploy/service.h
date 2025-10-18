#ifndef SERVICE_H
#define SERVICE_H

int service_install(void);
int service_uninstall(void);
int service_setup_logging(void);
int service_main(int argc, char **argv);
void service_cleanup(void);

#endif
