/**
 * @file nxld_utils.c
 * @brief NXLD工具函数实现 / NXLD Utility Functions Implementation / NXLD-Hilfsfunktionen-Implementierung
 */

#include "nxld_utils.h"
#include <string.h>
#include <stdint.h>

const char* nxld_utils_find_last_path_separator(const char* file_path) {
    if (file_path == NULL) {
        return NULL;
    }
    
    const char* last_slash = strrchr(file_path, '/');
#ifdef _WIN32
    const char* last_backslash = strrchr(file_path, '\\');
    if (last_backslash != NULL && (last_slash == NULL || last_backslash > last_slash)) {
        last_slash = last_backslash;
    }
#endif
    
    return last_slash;
}

int32_t nxld_utils_get_config_dir(const char* file_path, char* dir_path, size_t dir_path_size) {
    if (file_path == NULL || dir_path == NULL || dir_path_size == 0) {
        return 0;
    }
    
    const char* last_slash = nxld_utils_find_last_path_separator(file_path);
    
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

int32_t nxld_utils_build_plugin_full_path(const char* config_dir, const char* plugin_path, char* full_path, size_t full_path_size) {
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

