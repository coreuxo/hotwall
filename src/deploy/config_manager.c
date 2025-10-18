#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <jansson.h>
#include "config_manager.h"
#include "../util/debug.h"

int config_load_rules(const char *filename, struct filter_ctx *filter) {
    FILE *file;
    char line[1024];
    int line_num = 0;
    
    if (!filename || !filter) {
        return -1;
    }
    
    file = fopen(filename, "r");
    if (!file) {
        ERROR("Failed to open rules file: %s\n", filename);
        return -1;
    }
    
    while (fgets(line, sizeof(line), file)) {
        line_num++;
        
        char *trimmed = line;
        while (*trimmed && isspace(*trimmed)) trimmed++;
        
        if (*trimmed == '#' || *trimmed == '\0' || *trimmed == '\n') {
            continue;
        }
        
        char *comment = strchr(trimmed, '#');
        if (comment) *comment = '\0';
        
        char *end = trimmed + strlen(trimmed) - 1;
        while (end > trimmed && isspace(*end)) *end-- = '\0';
        
        if (strlen(trimmed) == 0) continue;
        
        DBG("Loading rule: %s\n", trimmed);
    }
    
    fclose(file);
    return 0;
}

int config_save_rules(const char *filename, struct filter_ctx *filter) {
    FILE *file;
    
    if (!filename || !filter) {
        return -1;
    }
    
    file = fopen(filename, "w");
    if (!file) {
        ERROR("Failed to create rules file: %s\n", filename);
        return -1;
    }
    
    fprintf(file, "# Firewall Rules Configuration\n");
    fprintf(file, "# Generated automatically\n\n");
    
    fclose(file);
    return 0;
}

int config_load_json(const char *filename, struct firewall_ctx *fw) {
    json_t *root, *rules, *rule;
    json_error_t error;
    size_t index;
    
    if (!filename || !fw) {
        return -1;
    }
    
    root = json_load_file(filename, 0, &error);
    if (!root) {
        ERROR("JSON error on line %d: %s\n", error.line, error.text);
        return -1;
    }
    
    rules = json_object_get(root, "rules");
    if (rules && json_is_array(rules)) {
        json_array_foreach(rules, index, rule) {
            const char *chain = json_string_value(json_object_get(rule, "chain"));
            const char *action = json_string_value(json_object_get(rule, "action"));
            const char *protocol = json_string_value(json_object_get(rule, "protocol"));
            const char *source = json_string_value(json_object_get(rule, "source"));
            const char *destination = json_string_value(json_object_get(rule, "destination"));
            int dport = json_integer_value(json_object_get(rule, "dport"));
            
            if (chain && action) {
                DBG("Loading JSON rule: %s %s\n", chain, action);
            }
        }
    }
    
    json_decref(root);
    return 0;
}

int config_validate_rules(struct filter_ctx *filter) {
    if (!filter) return -1;
    
    DBG("Validating firewall rules\n");
    return 0;
}

int config_backup_rules(const char *backup_dir) {
    char cmd[512];
    time_t now = time(NULL);
    char timestamp[64];
    struct tm *tm_info;
    
    tm_info = localtime(&now);
    strftime(timestamp, sizeof(timestamp), "%Y%m%d_%H%M%S", tm_info);
    
    snprintf(cmd, sizeof(cmd), "cp /etc/firewall/rules.conf %s/firewall_rules_%s.conf",
             backup_dir, timestamp);
    
    int ret = system(cmd);
    if (ret != 0) {
        ERROR("Failed to backup rules: %s\n", cmd);
        return -1;
    }
    
    DBG("Rules backed up to %s/firewall_rules_%s.conf\n", backup_dir, timestamp);
    return 0;
}

int config_restore_rules(const char *backup_file) {
    char cmd[512];
    
    snprintf(cmd, sizeof(cmd), "cp %s /etc/firewall/rules.conf", backup_file);
    
    int ret = system(cmd);
    if (ret != 0) {
        ERROR("Failed to restore rules: %s\n", cmd);
        return -1;
    }
    
    DBG("Rules restored from %s\n", backup_file);
    return 0;
}
