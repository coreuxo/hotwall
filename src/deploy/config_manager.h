#ifndef CONFIG_MANAGER_H
#define CONFIG_MANAGER_H

#include "../filter/filter.h"
#include "../firewall.h"

int config_load_rules(const char *filename, struct filter_ctx *filter);
int config_save_rules(const char *filename, struct filter_ctx *filter);
int config_load_json(const char *filename, struct firewall_ctx *fw);
int config_validate_rules(struct filter_ctx *filter);
int config_backup_rules(const char *backup_dir);
int config_restore_rules(const char *backup_file);

#endif
