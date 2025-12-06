/**
 * @file nx_main.c
 * @brief NXLD主程序 / NXLD Main Program / NXLD-Hauptprogramm
 * @details 加载配置文件并初始化根插件 / Load config file and initialize root plugins / Konfigurationsdatei laden und Root-Plugins initialisieren
 */

#include "nxld_parser.h"
#include "nxld_logger.h"
#include "nxld_plugin.h"
#include "nxld_plugin_loader.h"
#include "nxld_plugin_interface.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <dlfcn.h>
#endif

int main(int argc, char* argv[]) {
    const char* config_file = argc > 1 ? argv[1] : "NexusEngine.nxld";
    const char* log_file = "nxld_parser.log";
    
    if (nxld_logger_init(log_file) != 0) {
        fprintf(stderr, "Failed to initialize logger\n");
        return 1;
    }
    
    nxld_log_info("Starting NXLD engine");
    nxld_log_info("Config file: %s", config_file);
    
    nxld_config_t config;
    nxld_parse_result_t result = nxld_parse_file(config_file, &config);
    
    if (result != NXLD_PARSE_SUCCESS) {
        const char* error_msg = nxld_get_error_message(result);
        nxld_log_error("Parse failed: %s", error_msg);
        fprintf(stderr, "Parse failed: %s\n", error_msg);
        nxld_logger_close();
        return 1;
    }
    
    nxld_log_info("Parse successful");
    printf("Parse successful!\n\n");
    
    printf("Configuration:\n");
    printf("  LockMode: %d\n", config.lock_mode);
    printf("  MaxRootPlugins: %d\n", config.max_root_plugins);
    printf("  EnabledRootPlugins (%zu):\n", config.enabled_root_plugins_count);
    for (size_t i = 0; i < config.enabled_root_plugins_count; i++) {
        printf("    [%zu] %s\n", i + 1, config.enabled_root_plugins[i]);
    }
    printf("  VirtualParent mappings (%zu):\n", config.virtual_parent_count);
    for (size_t i = 0; i < config.virtual_parent_count; i++) {
        printf("    %s = %s\n", config.virtual_parent_keys[i], config.virtual_parent_values[i]);
    }
    
    printf("\nLoading root plugins:\n");
    nxld_plugin_t* plugins = NULL;
    size_t loaded_count = 0;
    
    if (nxld_load_plugins_from_config(&config, config_file, &plugins, &loaded_count) != 0) {
        fprintf(stderr, "Failed to load plugins\n");
        nxld_config_free(&config);
        nxld_logger_close();
        return 1;
    }
    
    printf("Successfully loaded %zu/%zu root plugins:\n", loaded_count, config.enabled_root_plugins_count);
    for (size_t i = 0; i < loaded_count; i++) {
        printf("  [%zu] Plugin loaded:\n", i + 1);
        printf("    UID: %s\n", plugins[i].uid);
        printf("    Name: %s\n", plugins[i].plugin_name);
        printf("    Version: %s\n", plugins[i].plugin_version);
        printf("    Path: %s\n", plugins[i].plugin_path);
        printf("    Interfaces (%zu):\n", plugins[i].interface_count);
        for (size_t j = 0; j < plugins[i].interface_count; j++) {
            const char* desc = plugins[i].interfaces[j].description != NULL ? plugins[i].interfaces[j].description : "";
            printf("      - %s (v%s): %s\n", 
                   plugins[i].interfaces[j].name != NULL ? plugins[i].interfaces[j].name : "unknown",
                   plugins[i].interfaces[j].version != NULL ? plugins[i].interfaces[j].version : "unknown",
                   desc);
        }
    }
    
    nxld_free_plugins(plugins, loaded_count);
    
    nxld_config_free(&config);
    nxld_log_info("Engine initialized successfully");
    nxld_logger_close();
    
    return 0;
}

