/**
 * @file nxld_plugin_loader.c
 * @brief NXLD插件批量加载器实现 / NXLD Plugin Batch Loader Implementation / NXLD-Plugin-Stapellader Implementierung
 */

#include "nxld_plugin_loader.h"
#include "nxld_logger.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/**
 * @brief 获取配置文件所在目录路径 / Get config file directory path / Konfigurationsdateiverzeichnispfad abrufen
 * @param file_path 配置文件路径 / Config file path / Konfigurationsdateipfad
 * @param dir_path 输出目录路径缓冲区 / Output directory path buffer / Ausgabe-Verzeichnispfad-Puffer
 * @param dir_path_size 缓冲区大小 / Buffer size / Puffergröße
 * @return 成功返回1，失败返回0 / Returns 1 on success, 0 on failure / Gibt 1 bei Erfolg zurück, 0 bei Fehler
 */
static int get_config_dir(const char* file_path, char* dir_path, size_t dir_path_size) {
    if (file_path == NULL || dir_path == NULL || dir_path_size == 0) {
        return 0;
    }
    
    const char* last_slash = strrchr(file_path, '/');
#ifdef _WIN32
    const char* last_backslash = strrchr(file_path, '\\');
    if (last_backslash != NULL && (last_slash == NULL || last_backslash > last_slash)) {
        last_slash = last_backslash;
    }
#endif
    
    if (last_slash == NULL) {
        dir_path[0] = '.';
        dir_path[1] = '\0';
        return 1;
    }
    
    size_t dir_len = last_slash - file_path;
    if (dir_len >= dir_path_size) {
        dir_len = dir_path_size - 1;
    }
    
    memcpy(dir_path, file_path, dir_len);
    dir_path[dir_len] = '\0';
    return 1;
}

/**
 * @brief 构建插件文件的完整路径 / Build full path for plugin file / Vollständigen Pfad für Plugin-Datei erstellen
 * @param config_dir 配置文件目录 / Config file directory / Konfigurationsdateiverzeichnis
 * @param plugin_path 插件相对路径 / Plugin relative path / Plugin-Relativpfad
 * @param full_path 输出完整路径缓冲区 / Output full path buffer / Ausgabe-Vollpfad-Puffer
 * @param full_path_size 缓冲区大小 / Buffer size / Puffergröße
 * @return 成功返回1，失败返回0 / Returns 1 on success, 0 on failure / Gibt 1 bei Erfolg zurück, 0 bei Fehler
 */
static int build_plugin_full_path(const char* config_dir, const char* plugin_path, char* full_path, size_t full_path_size) {
    if (config_dir == NULL || plugin_path == NULL || full_path == NULL || full_path_size == 0) {
        return 0;
    }
    
    size_t config_dir_len = strlen(config_dir);
    const char* normalized_plugin_path = plugin_path;
    
    if (plugin_path[0] == '.' && (plugin_path[1] == '/' || plugin_path[1] == '\\')) {
        normalized_plugin_path = plugin_path + 2;
    }
    
    size_t normalized_len = strlen(normalized_plugin_path);
    
    if (config_dir_len + normalized_len + 2 >= full_path_size) {
        return 0;
    }
    
    memcpy(full_path, config_dir, config_dir_len);
    
#ifdef _WIN32
    if (config_dir_len > 0 && config_dir[config_dir_len - 1] != '\\' && config_dir[config_dir_len - 1] != '/') {
        full_path[config_dir_len] = '\\';
        config_dir_len++;
    }
    memcpy(full_path + config_dir_len, normalized_plugin_path, normalized_len);
    full_path[config_dir_len + normalized_len] = '\0';
#else
    if (config_dir_len > 0 && config_dir[config_dir_len - 1] != '/') {
        full_path[config_dir_len] = '/';
        config_dir_len++;
    }
    memcpy(full_path + config_dir_len, normalized_plugin_path, normalized_len);
    full_path[config_dir_len + normalized_len] = '\0';
#endif
    
    return 1;
}

int nxld_load_plugins_from_config(const nxld_config_t* config, const char* config_file_path, 
                                   nxld_plugin_t** plugins, size_t* loaded_count) {
    if (config == NULL || config_file_path == NULL || plugins == NULL || loaded_count == NULL) {
        nxld_log_error("Invalid parameters for plugin loading");
        return -1;
    }
    
    if (config->enabled_root_plugins_count == 0) {
        *plugins = NULL;
        *loaded_count = 0;
        return 0;
    }
    
    nxld_plugin_t* plugin_array = (nxld_plugin_t*)malloc(config->enabled_root_plugins_count * sizeof(nxld_plugin_t));
    if (plugin_array == NULL) {
        nxld_log_error("Memory allocation failed for plugin array");
        return -1;
    }
    
    memset(plugin_array, 0, config->enabled_root_plugins_count * sizeof(nxld_plugin_t));
    
    char config_dir[4096];
    if (!get_config_dir(config_file_path, config_dir, sizeof(config_dir))) {
        nxld_log_error("Failed to get config file directory");
        free(plugin_array);
        return -1;
    }
    
    size_t success_count = 0;
    
    for (size_t i = 0; i < config->enabled_root_plugins_count; i++) {
        char full_path[4096];
        if (!build_plugin_full_path(config_dir, config->enabled_root_plugins[i], full_path, sizeof(full_path))) {
            nxld_log_error("Failed to build full path for plugin: %s", config->enabled_root_plugins[i]);
            continue;
        }
        
        nxld_plugin_load_result_t load_result = nxld_plugin_load(full_path, &plugin_array[success_count]);
        if (load_result != NXLD_PLUGIN_LOAD_SUCCESS) {
            const char* error_msg = nxld_plugin_get_error_message(load_result);
            nxld_log_error("Failed to load plugin %s (index %zu): %s", config->enabled_root_plugins[i], i, error_msg);
            continue;
        }
        
        nxld_log_info("Plugin loaded successfully: %s (UID: %s, index: %zu)", 
                     config->enabled_root_plugins[i], plugin_array[success_count].uid, i);
        success_count++;
    }
    
    *plugins = plugin_array;
    *loaded_count = success_count;
    
    nxld_log_info("Total plugins loaded: %zu/%zu", success_count, config->enabled_root_plugins_count);
    
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

