/**
 * @file nxld_plugin_loader.c
 * @brief NXLD插件批量加载器实现 / NXLD Plugin Batch Loader Implementation / NXLD-Plugin-Stapellader Implementierung
 */

#include "nxld_plugin_loader.h"
#include "nxld_utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

int32_t nxld_load_plugins_from_config(const nxld_config_t* config, const char* config_file_path, 
                                   nxld_plugin_t** plugins, size_t* loaded_count) {
    if (config == NULL || config_file_path == NULL || plugins == NULL || loaded_count == NULL) {
        return -1;
    }
    
    if (config->enabled_root_plugins_count == 0) {
        *plugins = NULL;
        *loaded_count = 0;
        return 0;
    }
    
    nxld_plugin_t* plugin_array = (nxld_plugin_t*)malloc(config->enabled_root_plugins_count * sizeof(nxld_plugin_t));
    if (plugin_array == NULL) {
        return -1;
    }
    
    memset(plugin_array, 0, config->enabled_root_plugins_count * sizeof(nxld_plugin_t));
    
    char config_dir[4096];
    if (!nxld_utils_get_config_dir(config_file_path, config_dir, sizeof(config_dir))) {
        free(plugin_array);
        return -1;
    }
    
    size_t success_count = 0;
    int32_t failure_policy = config->plugin_load_failure_policy;
    
    for (size_t i = 0; i < config->enabled_root_plugins_count; i++) {
        char full_path[4096];
        if (!nxld_utils_build_plugin_full_path(config_dir, config->enabled_root_plugins[i], full_path, sizeof(full_path))) {
            if (failure_policy == 1) {
                for (size_t j = 0; j < success_count; j++) {
                    nxld_plugin_free(&plugin_array[j]);
                }
                free(plugin_array);
                return -1;
            }
            continue;
        }
        
        nxld_plugin_load_result_t load_result = nxld_plugin_load(full_path, &plugin_array[success_count]);
        if (load_result != NXLD_PLUGIN_LOAD_SUCCESS) {
            if (failure_policy == 1) {
                for (size_t j = 0; j < success_count; j++) {
                    nxld_plugin_free(&plugin_array[j]);
                }
                free(plugin_array);
                return -1;
            }
            continue;
        }
        
        success_count++;
    }
    
    *plugins = plugin_array;
    *loaded_count = success_count;
    
    return 0;
}

void nxld_free_plugins(nxld_plugin_t* plugins, size_t count) {
    if (plugins == NULL) {
        return;
    }
    
    for (size_t i = 0; i < count; i++) {
        nxld_plugin_free(&plugins[i]);
    }
    
    free(plugins);
}

