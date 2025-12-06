/**
 * @file nxld_plugin.c
 * @brief NXLD插件加载和管理实现 / NXLD Plugin Loading and Management Implementation / NXLD-Plugin-Lade- und Verwaltungsimplementierung
 */

#include "nxld_plugin.h"
#include "nxld_logger.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <string.h>
#define strcpy_safe(dest, dest_size, src) strcpy_s(dest, dest_size, src)
#define strcat_safe(dest, dest_size, src) strcat_s(dest, dest_size, src)
#else
#define strcpy_safe(dest, dest_size, src) do { \
    size_t len = strlen(src); \
    if (len >= dest_size) len = dest_size - 1; \
    memcpy(dest, src, len); \
    dest[len] = '\0'; \
} while(0)
#define strcat_safe(dest, dest_size, src) do { \
    size_t dest_len = strlen(dest); \
    size_t src_len = strlen(src); \
    size_t available = dest_size - dest_len - 1; \
    if (src_len > available) src_len = available; \
    memcpy(dest + dest_len, src, src_len); \
    dest[dest_len + src_len] = '\0'; \
} while(0)
#define strncpy_safe(dest, dest_size, src, count) do { \
    size_t copy_len = (count) < (dest_size - 1) ? (count) : (dest_size - 1); \
    memcpy(dest, src, copy_len); \
    dest[copy_len] = '\0'; \
} while(0)
#endif

#ifdef _WIN32
#include <windows.h>
#else
#include <dlfcn.h>
#endif

#define MAX_NAME_LENGTH 256
#define MAX_VERSION_LENGTH 64
#define MAX_DESCRIPTION_LENGTH 512
#define UID_LENGTH 64

/**
 * @brief 生成64位随机字符串UID / Generate 64-bit random string UID / 64-Bit-Zufallszeichenfolge-UID generieren
 * @param uid 输出UID缓冲区 / Output UID buffer / Ausgabe-UID-Puffer
 * @param uid_size 缓冲区大小 / Buffer size / Puffergröße
 * @return 成功返回1，失败返回0 / Returns 1 on success, 0 on failure / Gibt 1 bei Erfolg zurück, 0 bei Fehler
 */
static int generate_uid(char* uid, size_t uid_size) {
    if (uid == NULL || uid_size < UID_LENGTH + 1) {
        return 0;
    }
    
    static int seeded = 0;
    if (!seeded) {
        srand((unsigned int)time(NULL));
        seeded = 1;
    }
    
    const char charset[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    const size_t charset_size = sizeof(charset) - 1;
    
    for (size_t i = 0; i < UID_LENGTH; i++) {
        uid[i] = charset[rand() % charset_size];
    }
    uid[UID_LENGTH] = '\0';
    
    return 1;
}

/**
 * @brief 加载动态库 / Load dynamic library / Dynamische Bibliothek laden
 * @param plugin_path 插件文件路径 / Plugin file path / Plugin-Dateipfad
 * @return 动态库句柄，失败返回NULL / Dynamic library handle, NULL on failure / Dynamisches Bibliothekshandle, NULL bei Fehler
 */
static void* load_dynamic_library(const char* plugin_path) {
    if (plugin_path == NULL) {
        return NULL;
    }
    
#ifdef _WIN32
    return (void*)LoadLibraryA(plugin_path);
#else
    return dlopen(plugin_path, RTLD_LAZY);
#endif
}

/**
 * @brief 获取动态库符号 / Get dynamic library symbol / Dynamisches Bibliothekssymbol abrufen
 * @param handle 动态库句柄 / Dynamic library handle / Dynamisches Bibliothekshandle
 * @param symbol_name 符号名称 / Symbol name / Symbolname
 * @return 符号地址，失败返回NULL / Symbol address, NULL on failure / Symboladresse, NULL bei Fehler
 */
static void* get_symbol(void* handle, const char* symbol_name) {
    if (handle == NULL || symbol_name == NULL) {
        return NULL;
    }
    
#ifdef _WIN32
    return (void*)GetProcAddress((HMODULE)handle, symbol_name);
#else
    return dlsym(handle, symbol_name);
#endif
}

/**
 * @brief 关闭动态库 / Close dynamic library / Dynamische Bibliothek schließen
 * @param handle 动态库句柄 / Dynamic library handle / Dynamisches Bibliothekshandle
 * @return 成功返回0，失败返回非0 / Returns 0 on success, non-zero on failure / Gibt 0 bei Erfolg zurück, ungleich 0 bei Fehler
 */
static int close_dynamic_library(void* handle) {
    if (handle == NULL) {
        return 0;
    }
    
#ifdef _WIN32
    return FreeLibrary((HMODULE)handle) ? 0 : 1;
#else
    return dlclose(handle);
#endif
}

/**
 * @brief 获取动态库错误信息 / Get dynamic library error message / Dynamische Bibliotheksfehlermeldung abrufen
 * @return 错误信息字符串 / Error message string / Fehlermeldungszeichenfolge
 */
static const char* get_dl_error(void) {
#ifdef _WIN32
    static char error_msg[256];
    DWORD error = GetLastError();
    if (error == 0) {
        return "No error";
    }
    DWORD result = FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                                   NULL, error, MAKELANGID(LANG_ENGLISH, SUBLANG_DEFAULT),
                                   error_msg, sizeof(error_msg), NULL);
    if (result == 0) {
        snprintf(error_msg, sizeof(error_msg), "Error code: %lu", (unsigned long)error);
    } else {
        size_t len = strlen(error_msg);
        while (len > 0 && (error_msg[len - 1] == '\r' || error_msg[len - 1] == '\n' || error_msg[len - 1] == ' ')) {
            error_msg[--len] = '\0';
        }
        for (size_t i = 0; i < len; i++) {
            if (error_msg[i] == '%' && i + 1 < len && error_msg[i + 1] >= '0' && error_msg[i + 1] <= '9') {
                size_t j = i + 1;
                while (j < len && error_msg[j] >= '0' && error_msg[j] <= '9') {
                    j++;
                }
                memmove(error_msg + i, error_msg + j, len - j + 1);
                len -= (j - i);
                i--;
            }
        }
    }
    return error_msg;
#else
    const char* err = dlerror();
    return err != NULL ? err : "No error";
#endif
}

nxld_plugin_load_result_t nxld_plugin_load(const char* plugin_path, nxld_plugin_t* plugin) {
    if (plugin_path == NULL || plugin == NULL) {
        nxld_log_error("Invalid parameters: plugin_path or plugin is NULL");
        return NXLD_PLUGIN_LOAD_FILE_ERROR;
    }
    
    memset(plugin, 0, sizeof(nxld_plugin_t));
    
    void* handle = load_dynamic_library(plugin_path);
    if (handle == NULL) {
        nxld_log_error("Failed to load dynamic library: %s, error: %s", plugin_path, get_dl_error());
        return NXLD_PLUGIN_LOAD_FILE_ERROR;
    }
    
    plugin->handle = handle;
    
    plugin->plugin_path = (char*)malloc(strlen(plugin_path) + 1);
    if (plugin->plugin_path == NULL) {
        close_dynamic_library(handle);
        nxld_log_error("Memory allocation failed for plugin path");
        return NXLD_PLUGIN_LOAD_MEMORY_ERROR;
    }
    strcpy_safe(plugin->plugin_path, strlen(plugin_path) + 1, plugin_path);
    
    nxld_plugin_get_name_func get_name = (nxld_plugin_get_name_func)get_symbol(handle, "nxld_plugin_get_name");
    nxld_plugin_get_version_func get_version = (nxld_plugin_get_version_func)get_symbol(handle, "nxld_plugin_get_version");
    nxld_plugin_get_interface_count_func get_interface_count = (nxld_plugin_get_interface_count_func)get_symbol(handle, "nxld_plugin_get_interface_count");
    nxld_plugin_get_interface_info_func get_interface_info = (nxld_plugin_get_interface_info_func)get_symbol(handle, "nxld_plugin_get_interface_info");
    
    if (get_name == NULL || get_version == NULL || get_interface_count == NULL || get_interface_info == NULL) {
        char missing_funcs[512] = {0};
        int first = 1;
        
        if (get_name == NULL) {
            if (!first) strcat_safe(missing_funcs, sizeof(missing_funcs), ", ");
            strcat_safe(missing_funcs, sizeof(missing_funcs), "nxld_plugin_get_name");
            first = 0;
        }
        if (get_version == NULL) {
            if (!first) strcat_safe(missing_funcs, sizeof(missing_funcs), ", ");
            strcat_safe(missing_funcs, sizeof(missing_funcs), "nxld_plugin_get_version");
            first = 0;
        }
        if (get_interface_count == NULL) {
            if (!first) strcat_safe(missing_funcs, sizeof(missing_funcs), ", ");
            strcat_safe(missing_funcs, sizeof(missing_funcs), "nxld_plugin_get_interface_count");
            first = 0;
        }
        if (get_interface_info == NULL) {
            if (!first) strcat_safe(missing_funcs, sizeof(missing_funcs), ", ");
            strcat_safe(missing_funcs, sizeof(missing_funcs), "nxld_plugin_get_interface_info");
            first = 0;
        }
        
        nxld_log_error("Required exported functions not found in plugin %s: %s", plugin_path, missing_funcs);
        close_dynamic_library(handle);
        nxld_plugin_free(plugin);
        return NXLD_PLUGIN_LOAD_SYMBOL_ERROR;
    }
    
    char name_buffer[MAX_NAME_LENGTH];
    char version_buffer[MAX_VERSION_LENGTH];
    
    if (get_name(name_buffer, sizeof(name_buffer)) != 0) {
        nxld_log_error("Failed to get plugin name from: %s", plugin_path);
        close_dynamic_library(handle);
        nxld_plugin_free(plugin);
        return NXLD_PLUGIN_LOAD_METADATA_ERROR;
    }
    
    plugin->plugin_name = (char*)malloc(strlen(name_buffer) + 1);
    if (plugin->plugin_name == NULL) {
        close_dynamic_library(handle);
        nxld_plugin_free(plugin);
        nxld_log_error("Memory allocation failed for plugin name");
        return NXLD_PLUGIN_LOAD_MEMORY_ERROR;
    }
    strcpy_safe(plugin->plugin_name, strlen(name_buffer) + 1, name_buffer);
    
    if (get_version(version_buffer, sizeof(version_buffer)) != 0) {
        nxld_log_error("Failed to get plugin version from: %s", plugin_path);
        close_dynamic_library(handle);
        nxld_plugin_free(plugin);
        return NXLD_PLUGIN_LOAD_METADATA_ERROR;
    }
    
    plugin->plugin_version = (char*)malloc(strlen(version_buffer) + 1);
    if (plugin->plugin_version == NULL) {
        close_dynamic_library(handle);
        nxld_plugin_free(plugin);
        nxld_log_error("Memory allocation failed for plugin version");
        return NXLD_PLUGIN_LOAD_MEMORY_ERROR;
    }
    strcpy_safe(plugin->plugin_version, strlen(version_buffer) + 1, version_buffer);
    
    size_t interface_count = 0;
    if (get_interface_count(&interface_count) != 0) {
        nxld_log_error("Failed to get interface count from: %s", plugin_path);
        close_dynamic_library(handle);
        nxld_plugin_free(plugin);
        return NXLD_PLUGIN_LOAD_METADATA_ERROR;
    }
    
    plugin->interface_count = interface_count;
    
    if (interface_count > 0) {
        plugin->interfaces = (nxld_interface_info_t*)malloc(interface_count * sizeof(nxld_interface_info_t));
        if (plugin->interfaces == NULL) {
            close_dynamic_library(handle);
            nxld_plugin_free(plugin);
            nxld_log_error("Memory allocation failed for interface array");
            return NXLD_PLUGIN_LOAD_MEMORY_ERROR;
        }
        
        memset(plugin->interfaces, 0, interface_count * sizeof(nxld_interface_info_t));
        
        // 获取参数信息查询函数（可选） / Get parameter info query functions (optional) / Parameterinformationsabfragefunktionen abrufen (optional)
        nxld_plugin_get_interface_param_count_func get_param_count = 
            (nxld_plugin_get_interface_param_count_func)get_symbol(handle, "nxld_plugin_get_interface_param_count");
        nxld_plugin_get_interface_param_info_func get_param_info = 
            (nxld_plugin_get_interface_param_info_func)get_symbol(handle, "nxld_plugin_get_interface_param_info");
        
        int has_param_info = (get_param_count != NULL && get_param_info != NULL);
        if (!has_param_info) {
            nxld_log_info("Plugin %s does not provide parameter information functions", plugin_path);
        }
        
        for (size_t i = 0; i < interface_count; i++) {
            char iface_name[MAX_NAME_LENGTH] = {0};
            char iface_desc[MAX_DESCRIPTION_LENGTH] = {0};
            char iface_version[MAX_VERSION_LENGTH] = {0};
            
            if (get_interface_info(i, iface_name, sizeof(iface_name),
                                   iface_desc, sizeof(iface_desc),
                                   iface_version, sizeof(iface_version)) != 0) {
                nxld_log_error("Failed to get interface info at index %zu from: %s", i, plugin_path);
                close_dynamic_library(handle);
                nxld_plugin_free(plugin);
                return NXLD_PLUGIN_LOAD_METADATA_ERROR;
            }
            
            plugin->interfaces[i].name = (char*)malloc(strlen(iface_name) + 1);
            plugin->interfaces[i].description = (char*)malloc(strlen(iface_desc) + 1);
            plugin->interfaces[i].version = (char*)malloc(strlen(iface_version) + 1);
            
            if (plugin->interfaces[i].name == NULL || 
                plugin->interfaces[i].description == NULL || 
                plugin->interfaces[i].version == NULL) {
                nxld_log_error("Memory allocation failed for interface info at index %zu", i);
                close_dynamic_library(handle);
                nxld_plugin_free(plugin);
                return NXLD_PLUGIN_LOAD_MEMORY_ERROR;
            }
            
            strcpy_safe(plugin->interfaces[i].name, strlen(iface_name) + 1, iface_name);
            strcpy_safe(plugin->interfaces[i].description, strlen(iface_desc) + 1, iface_desc);
            strcpy_safe(plugin->interfaces[i].version, strlen(iface_version) + 1, iface_version);
            
            // 初始化参数信息 / Initialize parameter info / Parameterinformationen initialisieren
            plugin->interfaces[i].param_count_type = NXLD_PARAM_COUNT_UNKNOWN;
            plugin->interfaces[i].min_param_count = 0;
            plugin->interfaces[i].max_param_count = -1;
            plugin->interfaces[i].params = NULL;
            plugin->interfaces[i].param_count = 0;
            
            // 收集插件提供的参数信息 / Collect parameter info provided by plugin / Von Plugin bereitgestellte Parameterinformationen sammeln
            if (has_param_info) {
                nxld_param_count_type_t count_type;
                int min_count, max_count;
                
                if (get_param_count(i, &count_type, &min_count, &max_count) == 0) {
                    plugin->interfaces[i].param_count_type = count_type;
                    plugin->interfaces[i].min_param_count = min_count;
                    plugin->interfaces[i].max_param_count = max_count;
                    
                    // 收集固定参数信息 / Collect fixed parameter info / Feste Parameterinformationen sammeln
                    if (count_type == NXLD_PARAM_COUNT_FIXED && min_count > 0) {
                        plugin->interfaces[i].param_count = min_count;
                        plugin->interfaces[i].params = (nxld_param_info_t*)malloc(min_count * sizeof(nxld_param_info_t));
                        if (plugin->interfaces[i].params == NULL) {
                            nxld_log_error("Memory allocation failed for parameter info at interface %zu", i);
                            close_dynamic_library(handle);
                            nxld_plugin_free(plugin);
                            return NXLD_PLUGIN_LOAD_MEMORY_ERROR;
                        }
                        
                        memset(plugin->interfaces[i].params, 0, min_count * sizeof(nxld_param_info_t));
                        
                        for (int j = 0; j < min_count; j++) {
                            char param_name[MAX_NAME_LENGTH];
                            nxld_param_type_t param_type;
                            char type_name[MAX_NAME_LENGTH] = {0};
                            
                            if (get_param_info(i, j, param_name, sizeof(param_name),
                                              &param_type, type_name, sizeof(type_name)) == 0) {
                                plugin->interfaces[i].params[j].name = (char*)malloc(strlen(param_name) + 1);
                                if (plugin->interfaces[i].params[j].name == NULL) {
                                    nxld_log_error("Memory allocation failed for parameter name at interface %zu param %d", i, j);
                                    close_dynamic_library(handle);
                                    nxld_plugin_free(plugin);
                                    return NXLD_PLUGIN_LOAD_MEMORY_ERROR;
                                }
                                strcpy_safe(plugin->interfaces[i].params[j].name, strlen(param_name) + 1, param_name);
                                
                                plugin->interfaces[i].params[j].type = param_type;
                                
                                if (strlen(type_name) > 0) {
                                    plugin->interfaces[i].params[j].type_name = (char*)malloc(strlen(type_name) + 1);
                                    if (plugin->interfaces[i].params[j].type_name == NULL) {
                                        nxld_log_error("Memory allocation failed for type name at interface %zu param %d", i, j);
                                        close_dynamic_library(handle);
                                        nxld_plugin_free(plugin);
                                        return NXLD_PLUGIN_LOAD_MEMORY_ERROR;
                                    }
                                    strcpy_safe(plugin->interfaces[i].params[j].type_name, strlen(type_name) + 1, type_name);
                                } else {
                                    plugin->interfaces[i].params[j].type_name = NULL;
                                }
                            } else {
                                nxld_log_warning("Failed to get parameter info at interface %zu param %d", i, j);
                                plugin->interfaces[i].params[j].name = NULL;
                                plugin->interfaces[i].params[j].type = NXLD_PARAM_TYPE_UNKNOWN;
                                plugin->interfaces[i].params[j].type_name = NULL;
                            }
                        }
                    } else if (count_type == NXLD_PARAM_COUNT_VARIABLE) {
                        // 可变参数：收集最小数量的参数信息，并标记为可变 / Variable params: collect min count param info and mark as variable / Variable Parameter: Mindestanzahl Parameterinformationen sammeln und als variabel markieren
                        if (min_count > 0) {
                            plugin->interfaces[i].param_count = min_count;
                            plugin->interfaces[i].params = (nxld_param_info_t*)malloc(min_count * sizeof(nxld_param_info_t));
                            if (plugin->interfaces[i].params == NULL) {
                                nxld_log_error("Memory allocation failed for parameter info at interface %zu", i);
                                close_dynamic_library(handle);
                                nxld_plugin_free(plugin);
                                return NXLD_PLUGIN_LOAD_MEMORY_ERROR;
                            }
                            
                            memset(plugin->interfaces[i].params, 0, min_count * sizeof(nxld_param_info_t));
                            
                            for (int j = 0; j < min_count; j++) {
                                char param_name[MAX_NAME_LENGTH];
                                nxld_param_type_t param_type;
                                char type_name[MAX_NAME_LENGTH] = {0};
                                
                                if (get_param_info(i, j, param_name, sizeof(param_name),
                                                  &param_type, type_name, sizeof(type_name)) == 0) {
                                    plugin->interfaces[i].params[j].name = (char*)malloc(strlen(param_name) + 1);
                                    if (plugin->interfaces[i].params[j].name == NULL) {
                                        nxld_log_error("Memory allocation failed for parameter name at interface %zu param %d", i, j);
                                        close_dynamic_library(handle);
                                        nxld_plugin_free(plugin);
                                        return NXLD_PLUGIN_LOAD_MEMORY_ERROR;
                                    }
                                    strcpy_safe(plugin->interfaces[i].params[j].name, strlen(param_name) + 1, param_name);
                                    
                                    plugin->interfaces[i].params[j].type = param_type;
                                    
                                    if (strlen(type_name) > 0) {
                                        plugin->interfaces[i].params[j].type_name = (char*)malloc(strlen(type_name) + 1);
                                        if (plugin->interfaces[i].params[j].type_name == NULL) {
                                            nxld_log_error("Memory allocation failed for type name at interface %zu param %d", i, j);
                                            close_dynamic_library(handle);
                                            nxld_plugin_free(plugin);
                                            return NXLD_PLUGIN_LOAD_MEMORY_ERROR;
                                        }
                                        strcpy_safe(plugin->interfaces[i].params[j].type_name, strlen(type_name) + 1, type_name);
                                    } else {
                                        plugin->interfaces[i].params[j].type_name = NULL;
                                    }
                                } else {
                                    nxld_log_warning("Failed to get parameter info at interface %zu param %d", i, j);
                                    plugin->interfaces[i].params[j].name = NULL;
                                    plugin->interfaces[i].params[j].type = NXLD_PARAM_TYPE_UNKNOWN;
                                    plugin->interfaces[i].params[j].type_name = NULL;
                                }
                            }
                        }
                    }
                } else {
                    nxld_log_warning("Failed to get parameter count for interface %zu", i);
                }
            }
        }
    }
    
    if (!generate_uid(plugin->uid, sizeof(plugin->uid))) {
        nxld_log_error("Failed to generate UID for plugin: %s", plugin_path);
        close_dynamic_library(handle);
        nxld_plugin_free(plugin);
        return NXLD_PLUGIN_LOAD_MEMORY_ERROR;
    }
    
    nxld_log_info("Plugin loaded successfully: %s (UID: %s)", plugin_path, plugin->uid);
    
    // 自动生成.nxp元数据文件 / Automatically generate .nxp metadata file / .nxp-Metadaten-Datei automatisch generieren
    {
        char nxp_path[1024];
        const char* ext_pos = strrchr(plugin_path, '.');
        size_t base_len;
        
        if (ext_pos != NULL) {
            base_len = ext_pos - plugin_path;
        } else {
            base_len = strlen(plugin_path);
        }
        
        if (base_len < sizeof(nxp_path) - 5) {
            memcpy(nxp_path, plugin_path, base_len);
            memcpy(nxp_path + base_len, ".nxp", 5);
            
            if (nxld_plugin_generate_metadata_file(plugin, nxp_path) == 0) {
                nxld_log_info("Plugin metadata file generated: %s", nxp_path);
            } else {
                nxld_log_warning("Failed to generate metadata file: %s", nxp_path);
            }
        } else {
            nxld_log_warning("Plugin path too long to generate metadata file name");
        }
    }
    
    return NXLD_PLUGIN_LOAD_SUCCESS;
}

void nxld_plugin_unload(nxld_plugin_t* plugin) {
    if (plugin == NULL || plugin->handle == NULL) {
        return;
    }
    
    close_dynamic_library(plugin->handle);
    plugin->handle = NULL;
}

void nxld_plugin_free(nxld_plugin_t* plugin) {
    if (plugin == NULL) {
        return;
    }
    
    if (plugin->handle != NULL) {
        nxld_plugin_unload(plugin);
    }
    
    if (plugin->plugin_path != NULL) {
        free(plugin->plugin_path);
        plugin->plugin_path = NULL;
    }
    
    if (plugin->plugin_name != NULL) {
        free(plugin->plugin_name);
        plugin->plugin_name = NULL;
    }
    
    if (plugin->plugin_version != NULL) {
        free(plugin->plugin_version);
        plugin->plugin_version = NULL;
    }
    
    if (plugin->interfaces != NULL) {
        for (size_t i = 0; i < plugin->interface_count; i++) {
            if (plugin->interfaces[i].name != NULL) {
                free(plugin->interfaces[i].name);
            }
            if (plugin->interfaces[i].description != NULL) {
                free(plugin->interfaces[i].description);
            }
            if (plugin->interfaces[i].version != NULL) {
                free(plugin->interfaces[i].version);
            }
            
            // 释放参数信息 / Free parameter info / Parameterinformationen freigeben
            if (plugin->interfaces[i].params != NULL) {
                for (size_t j = 0; j < plugin->interfaces[i].param_count; j++) {
                    if (plugin->interfaces[i].params[j].name != NULL) {
                        free(plugin->interfaces[i].params[j].name);
                    }
                    if (plugin->interfaces[i].params[j].type_name != NULL) {
                        free(plugin->interfaces[i].params[j].type_name);
                    }
                }
                free(plugin->interfaces[i].params);
                plugin->interfaces[i].params = NULL;
            }
        }
        free(plugin->interfaces);
        plugin->interfaces = NULL;
    }
    
    plugin->interface_count = 0;
}

const char* nxld_plugin_get_error_message(nxld_plugin_load_result_t result) {
    switch (result) {
        case NXLD_PLUGIN_LOAD_SUCCESS:
            return "Plugin load successful";
        case NXLD_PLUGIN_LOAD_FILE_ERROR:
            return "Failed to load plugin file";
        case NXLD_PLUGIN_LOAD_SYMBOL_ERROR:
            return "Required symbols not found in plugin";
        case NXLD_PLUGIN_LOAD_METADATA_ERROR:
            return "Failed to get plugin metadata";
        case NXLD_PLUGIN_LOAD_MEMORY_ERROR:
            return "Memory allocation error";
        default:
            return "Unknown error";
    }
}

/**
 * @brief 获取参数类型名称字符串 / Get parameter type name string / Parametertypnamen-Zeichenfolge abrufen
 */
static const char* get_param_type_name(nxld_param_type_t type) {
    switch (type) {
        case NXLD_PARAM_TYPE_VOID: return "void";
        case NXLD_PARAM_TYPE_INT: return "int";
        case NXLD_PARAM_TYPE_LONG: return "long";
        case NXLD_PARAM_TYPE_FLOAT: return "float";
        case NXLD_PARAM_TYPE_DOUBLE: return "double";
        case NXLD_PARAM_TYPE_CHAR: return "char";
        case NXLD_PARAM_TYPE_POINTER: return "pointer";
        case NXLD_PARAM_TYPE_STRING: return "string";
        case NXLD_PARAM_TYPE_VARIADIC: return "variadic";
        case NXLD_PARAM_TYPE_ANY: return "any";
        case NXLD_PARAM_TYPE_UNKNOWN: return "unknown";
        default: return "unknown";
    }
}

/**
 * @brief 获取参数数量类型名称字符串 / Get parameter count type name string / Parameteranzahl-Typnamen-Zeichenfolge abrufen
 */
static const char* get_param_count_type_name(nxld_param_count_type_t count_type) {
    switch (count_type) {
        case NXLD_PARAM_COUNT_FIXED: return "fixed";
        case NXLD_PARAM_COUNT_VARIABLE: return "variable";
        case NXLD_PARAM_COUNT_UNKNOWN: return "unknown";
        default: return "unknown";
    }
}

int nxld_plugin_generate_metadata_file(const nxld_plugin_t* plugin, const char* output_path) {
    if (plugin == NULL || output_path == NULL) {
        nxld_log_error("Invalid parameters for metadata file generation");
        return -1;
    }
    
    FILE* fp = fopen(output_path, "w");
    if (fp == NULL) {
        nxld_log_error("Failed to open file for writing: %s", output_path);
        return -1;
    }
    
    // 写入文件头 / Write file header / Dateikopf schreiben
    fprintf(fp, "# NXLD Plugin Metadata File / NXLD插件元数据文件\n");
    fprintf(fp, "# Generated automatically / 自动生成\n");
    fprintf(fp, "# Format: NXP v1.0 / 格式: NXP v1.0\n");
    fprintf(fp, "\n");
    
    // 写入插件基本信息 / Write plugin basic info / Plugin-Grundinformationen schreiben
    fprintf(fp, "[Plugin]\n");
    fprintf(fp, "Name=%s\n", plugin->plugin_name != NULL ? plugin->plugin_name : "Unknown");
    fprintf(fp, "Version=%s\n", plugin->plugin_version != NULL ? plugin->plugin_version : "Unknown");
    fprintf(fp, "UID=%s\n", plugin->uid);
    fprintf(fp, "Path=%s\n", plugin->plugin_path != NULL ? plugin->plugin_path : "Unknown");
    fprintf(fp, "\n");
    
    // 写入接口信息 / Write interface info / Schnittstelleninformationen schreiben
    fprintf(fp, "[Interfaces]\n");
    fprintf(fp, "Count=%zu\n", plugin->interface_count);
    fprintf(fp, "\n");
    
    for (size_t i = 0; i < plugin->interface_count; i++) {
        const nxld_interface_info_t* iface = &plugin->interfaces[i];
        
        fprintf(fp, "[Interface_%zu]\n", i);
        fprintf(fp, "Name=%s\n", iface->name != NULL ? iface->name : "Unknown");
        fprintf(fp, "Description=%s\n", iface->description != NULL ? iface->description : "");
        fprintf(fp, "Version=%s\n", iface->version != NULL ? iface->version : "Unknown");
        
        // 写入参数数量信息 / Write parameter count info / Parameteranzahl-Informationen schreiben
        fprintf(fp, "ParamCountType=%s\n", get_param_count_type_name(iface->param_count_type));
        fprintf(fp, "MinParamCount=%d\n", iface->min_param_count);
        if (iface->max_param_count >= 0) {
            fprintf(fp, "MaxParamCount=%d\n", iface->max_param_count);
        } else {
            fprintf(fp, "MaxParamCount=unlimited\n");
        }
        fprintf(fp, "FixedParamCount=%zu\n", iface->param_count);
        
        // 写入参数详细信息 / Write parameter details / Detaillierte Parameterinformationen schreiben
        if (iface->param_count > 0 && iface->params != NULL) {
            fprintf(fp, "Params=\n");
            for (size_t j = 0; j < iface->param_count; j++) {
                const nxld_param_info_t* param = &iface->params[j];
                fprintf(fp, "  [%zu]\n", j);
                fprintf(fp, "    Name=%s\n", param->name != NULL ? param->name : "unnamed");
                fprintf(fp, "    Type=%s\n", get_param_type_name(param->type));
                if (param->type_name != NULL && strlen(param->type_name) > 0) {
                    fprintf(fp, "    TypeName=%s\n", param->type_name);
                }
            }
        } else if (iface->param_count_type == NXLD_PARAM_COUNT_VARIABLE) {
            fprintf(fp, "Params=variadic\n");
        } else if (iface->param_count_type == NXLD_PARAM_COUNT_UNKNOWN) {
            fprintf(fp, "Params=unknown\n");
        } else {
            fprintf(fp, "Params=none\n");
        }
        
        fprintf(fp, "\n");
    }
    
    fclose(fp);
    nxld_log_info("Plugin metadata file generated: %s", output_path);
    return 0;
}

