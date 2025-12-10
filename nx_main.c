/**
 * @file nx_main.c
 * @brief NXLD主程序 / NXLD Main Program / NXLD-Hauptprogramm
 * @details 加载配置文件并初始化根插件 / Load config file and initialize root plugins / Konfigurationsdatei laden und Root-Plugins initialisieren
 */

#include "nxld_parser.h"
#include "nxld_plugin.h"
#include "nxld_plugin_loader.h"
#include <stdlib.h>
#include <string.h>

int main(int argc, char* argv[]) {
    const char* config_file = argc > 1 ? argv[1] : "NexusEngine.nxld";
    
    nxld_config_t config;
    nxld_parse_result_t result = nxld_parse_file(config_file, &config);
    
    if (result != NXLD_PARSE_SUCCESS) {
        nxld_config_free(&config);
        return 1;
    }
    
    nxld_plugin_t* plugins = NULL;
    size_t loaded_count = 0;
    
    if (nxld_load_plugins_from_config(&config, config_file, &plugins, &loaded_count) != 0) {
        nxld_config_free(&config);
        return 1;
    }
    
    nxld_free_plugins(plugins, loaded_count);
    
    nxld_config_free(&config);
    
    return 0;
}

