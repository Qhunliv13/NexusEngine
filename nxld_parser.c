/**
 * @file nxld_parser.c
 * @brief NXLD配置文件解析器实现 / NXLD Configuration File Parser Implementation / NXLD-Konfigurationsdatei-Parser-Implementierung
 * @details 实现解析.nxld格式配置文件的逻辑，验证配置有效性，返回配置结构体 / Implements logic for parsing .nxld format configuration files, validates configuration validity, returns configuration structure / Implementiert Logik zum Parsen von .nxld-Format-Konfigurationsdateien, validiert Konfigurationsgültigkeit, gibt Konfigurationsstruktur zurück
 */

#include "nxld_parser.h"
#include "nxld_logger.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>

#ifdef _WIN32
#include <io.h>
#include <string.h>
#define access _access
#define F_OK 0
#define strcasecmp _stricmp
#else
#include <unistd.h>
#include <strings.h>
#endif

#define MAX_LINE_LENGTH 4096
#define MAX_SECTION_NAME 256
#define MAX_KEY_LENGTH 256
#define MAX_VALUE_LENGTH 2048
#define MAX_PATH_LENGTH 4096

/**
 * @brief 检查文件是否为有效的UTF-8编码 / Check if file is valid UTF-8 encoding / Prüfen, ob Datei gültige UTF-8-Kodierung ist
 * @param file_path 文件路径 / File path / Dateipfad
 * @return 有效UTF-8返回1，无效返回0 / Returns 1 if valid UTF-8, 0 if invalid / Gibt 1 bei gültigem UTF-8 zurück, 0 bei ungültig
 * @details 检查文件前3字节是否符合UTF-8编码规范 / Checks if first 3 bytes of file conform to UTF-8 encoding specification / Prüft, ob erste 3 Bytes der Datei UTF-8-Kodierungsspezifikation entsprechen
 */
static int is_valid_utf8_file(const char* file_path) {
    FILE* file = fopen(file_path, "rb");
    if (file == NULL) {
        return 0;
    }
    
    uint8_t buffer[3];
    size_t read = fread(buffer, 1, 3, file);
    fclose(file);
    
    if (read < 3) {
        return 1;
    }
    
    if (buffer[0] == 0xEF && buffer[1] == 0xBB && buffer[2] == 0xBF) {
        return 1;
    }
    
    if ((buffer[0] & 0x80) == 0) {
        return 1;
    }
    
    if ((buffer[0] & 0xE0) == 0xC0 && (buffer[1] & 0xC0) == 0x80) {
        return 1;
    }
    
    if ((buffer[0] & 0xF0) == 0xE0 && (buffer[1] & 0xC0) == 0x80 && (buffer[2] & 0xC0) == 0x80) {
        return 1;
    }
    
    return 1;
}

/**
 * @brief 去除字符串首尾空白字符 / Trim whitespace from string / Leerzeichen am Anfang und Ende entfernen
 * @param str 字符串指针 / String pointer / Zeichenfolgenzeiger
 * @return 去除空白后的字符串指针 / Pointer to trimmed string / Zeiger auf bereinigte Zeichenfolge
 * @details 修改原字符串，去除首尾空白字符 / Modifies original string, removes leading and trailing whitespace / Modifiziert ursprüngliche Zeichenfolge, entfernt führende und nachfolgende Leerzeichen
 */
static char* trim_whitespace(char* str) {
    if (str == NULL) {
        return NULL;
    }
    
    while (isspace((unsigned char)*str)) {
        str++;
    }
    
    if (*str == 0) {
        return str;
    }
    
    char* end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) {
        end--;
    }
    
    end[1] = '\0';
    return str;
}

/**
 * @brief 按分隔符分割字符串 / Split string by delimiter / Zeichenfolge nach Trennzeichen aufteilen
 * @param str 输入字符串 / Input string / Eingabezeichenfolge
 * @param delimiter 分隔符 / Delimiter / Trennzeichen
 * @param count 输出分割后的元素数量 / Output element count after split / Anzahl der Elemente nach Aufteilung
 * @return 字符串数组指针，失败返回NULL / String array pointer, NULL on failure / Zeichenfolgenarray-Zeiger, NULL bei Fehler
 * @details 动态分配内存存储分割结果，调用者负责释放 / Dynamically allocates memory to store split results, caller is responsible for freeing / Weist Speicher dynamisch zu, um Aufteilungsergebnisse zu speichern, Aufrufer ist für Freigabe verantwortlich
 */
static char** split_string(const char* str, char delimiter, size_t* count) {
    if (str == NULL || strlen(str) == 0) {
        *count = 0;
        return NULL;
    }
    
    size_t capacity = 8;
    size_t size = 0;
    char** result = (char**)malloc(capacity * sizeof(char*));
    if (result == NULL) {
        *count = 0;
        return NULL;
    }
    
    const char* start = str;
    const char* current = str;
    
    while (*current != '\0') {
        if (*current == delimiter) {
            if (current > start) {
                size_t len = current - start;
                char* token = (char*)malloc(len + 1);
                if (token == NULL) {
                    for (size_t i = 0; i < size; i++) {
                        free(result[i]);
                    }
                    free(result);
                    *count = 0;
                    return NULL;
                }
                memcpy(token, start, len);
                token[len] = '\0';
                char* trimmed = trim_whitespace(token);
                if (strlen(trimmed) > 0) {
                    if (size >= capacity) {
                        capacity *= 2;
                        result = (char**)realloc(result, capacity * sizeof(char*));
                        if (result == NULL) {
                            for (size_t i = 0; i < size; i++) {
                                free(result[i]);
                            }
                            free(token);
                            *count = 0;
                            return NULL;
                        }
                    }
                    result[size] = (char*)malloc(strlen(trimmed) + 1);
                    if (result[size] == NULL) {
                        for (size_t i = 0; i < size; i++) {
                            free(result[i]);
                        }
                        free(result);
                        free(token);
                        *count = 0;
                        return NULL;
                    }
                    strcpy(result[size], trimmed);
                    size++;
                }
                free(token);
            }
            start = current + 1;
        }
        current++;
    }
    
    if (current > start) {
        size_t len = current - start;
        char* token = (char*)malloc(len + 1);
        if (token == NULL) {
            for (size_t i = 0; i < size; i++) {
                free(result[i]);
            }
            free(result);
            *count = 0;
            return NULL;
        }
        memcpy(token, start, len);
        token[len] = '\0';
        char* trimmed = trim_whitespace(token);
        if (strlen(trimmed) > 0) {
            if (size >= capacity) {
                capacity *= 2;
                result = (char**)realloc(result, capacity * sizeof(char*));
                if (result == NULL) {
                    for (size_t i = 0; i < size; i++) {
                        free(result[i]);
                    }
                    free(result);
                    free(token);
                    *count = 0;
                    return NULL;
                }
            }
            result[size] = (char*)malloc(strlen(trimmed) + 1);
            if (result[size] == NULL) {
                for (size_t i = 0; i < size; i++) {
                    free(result[i]);
                }
                free(result);
                free(token);
                *count = 0;
                return NULL;
            }
            strcpy(result[size], trimmed);
            size++;
        }
        free(token);
    }
    
    *count = size;
    return result;
}

/**
 * @brief 解析配置段名称 / Parse section name / Abschnittsname analysieren
 * @param line 输入行 / Input line / Eingabezeile
 * @param section_name 输出段名称缓冲区 / Output section name buffer / Ausgabe-Abschnittsname-Puffer
 * @return 成功返回1，失败返回0 / Returns 1 on success, 0 on failure / Gibt 1 bei Erfolg zurück, 0 bei Fehler
 * @details 从格式为[SectionName]的行中提取段名称 / Extracts section name from line in format [SectionName] / Extrahiert Abschnittsname aus Zeile im Format [SectionName]
 */
static int parse_section_name(const char* line, char* section_name) {
    const char* start = strchr(line, '[');
    if (start == NULL) {
        return 0;
    }
    
    start++;
    const char* end = strchr(start, ']');
    if (end == NULL) {
        return 0;
    }
    
    size_t len = end - start;
    if (len >= MAX_SECTION_NAME) {
        len = MAX_SECTION_NAME - 1;
    }
    
    memcpy(section_name, start, len);
    section_name[len] = '\0';
    
    char* trimmed = trim_whitespace(section_name);
    memmove(section_name, trimmed, strlen(trimmed) + 1);
    
    return 1;
}

/**
 * @brief 解析键值对 / Parse key-value pair / Schlüssel-Wert-Paar analysieren
 * @param line 输入行 / Input line / Eingabezeile
 * @param key 输出键缓冲区 / Output key buffer / Ausgabe-Schlüssel-Puffer
 * @param value 输出值缓冲区 / Output value buffer / Ausgabe-Wert-Puffer
 * @return 成功返回1，失败返回0 / Returns 1 on success, 0 on failure / Gibt 1 bei Erfolg zurück, 0 bei Fehler
 * @details 从格式为key=value的行中提取键和值 / Extracts key and value from line in format key=value / Extrahiert Schlüssel und Wert aus Zeile im Format key=value
 */
static int parse_key_value(const char* line, char* key, char* value) {
    const char* eq_pos = strchr(line, '=');
    if (eq_pos == NULL) {
        return 0;
    }
    
    size_t key_len = eq_pos - line;
    if (key_len >= MAX_KEY_LENGTH) {
        key_len = MAX_KEY_LENGTH - 1;
    }
    
    memcpy(key, line, key_len);
    key[key_len] = '\0';
    char* trimmed_key = trim_whitespace(key);
    memmove(key, trimmed_key, strlen(trimmed_key) + 1);
    
    const char* value_start = eq_pos + 1;
    size_t value_len = strlen(value_start);
    if (value_len >= MAX_VALUE_LENGTH) {
        value_len = MAX_VALUE_LENGTH - 1;
    }
    
    memcpy(value, value_start, value_len);
    value[value_len] = '\0';
    char* trimmed_value = trim_whitespace(value);
    memmove(value, trimmed_value, strlen(trimmed_value) + 1);
    
    return 1;
}

/**
 * @brief 获取配置文件所在目录路径 / Get config file directory path / Konfigurationsdateiverzeichnispfad abrufen
 * @param file_path 配置文件路径 / Config file path / Konfigurationsdateipfad
 * @param dir_path 输出目录路径缓冲区 / Output directory path buffer / Ausgabe-Verzeichnispfad-Puffer
 * @param dir_path_size 缓冲区大小 / Buffer size / Puffergröße
 * @return 成功返回1，失败返回0 / Returns 1 on success, 0 on failure / Gibt 1 bei Erfolg zurück, 0 bei Fehler
 * @details 从文件路径中提取目录部分 / Extracts directory portion from file path / Extrahiert Verzeichnisteil aus Dateipfad
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
 * @details 将相对路径与配置目录组合为绝对路径 / Combines relative path with config directory to form absolute path / Kombiniert Relativpfad mit Konfigurationsverzeichnis zu absolutem Pfad
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
    
    strcpy(full_path, config_dir);
    
#ifdef _WIN32
    if (config_dir_len > 0 && config_dir[config_dir_len - 1] != '\\' && config_dir[config_dir_len - 1] != '/') {
        strcat(full_path, "\\");
    }
    strcat(full_path, normalized_plugin_path);
#else
    if (config_dir_len > 0 && config_dir[config_dir_len - 1] != '/') {
        strcat(full_path, "/");
    }
    strcat(full_path, normalized_plugin_path);
#endif
    
    return 1;
}

/**
 * @brief 获取文件扩展名 / Get file extension / Dateierweiterung abrufen
 * @param file_path 文件路径 / File path / Dateipfad
 * @return 扩展名字符串指针，无扩展名返回NULL / Pointer to extension string, NULL if no extension / Zeiger auf Erweiterungszeichenfolge, NULL wenn keine Erweiterung
 * @details 返回指向扩展名部分的指针，包含点号 / Returns pointer to extension portion, includes dot / Gibt Zeiger auf Erweiterungsteil zurück, enthält Punkt
 */
static const char* get_file_extension(const char* file_path) {
    if (file_path == NULL) {
        return NULL;
    }
    
    const char* last_dot = strrchr(file_path, '.');
    const char* last_slash = strrchr(file_path, '/');
#ifdef _WIN32
    const char* last_backslash = strrchr(file_path, '\\');
    if (last_backslash != NULL && (last_slash == NULL || last_backslash > last_slash)) {
        last_slash = last_backslash;
    }
#endif
    
    if (last_dot == NULL) {
        return NULL;
    }
    
    if (last_slash != NULL && last_dot < last_slash) {
        return NULL;
    }
    
    return last_dot;
}

/**
 * @brief 检查插件文件扩展名是否符合运行系统要求 / Check if plugin file extension matches running system / Prüfen, ob Plugin-Dateierweiterung dem laufenden System entspricht
 * @param plugin_path 插件路径 / Plugin path / Plugin-Pfad
 * @return 符合返回1，不符合返回0 / Returns 1 if matches, 0 if not matches / Gibt 1 zurück, wenn übereinstimmt, 0 wenn nicht übereinstimmt
 * @details Windows系统检查.dll扩展名，Linux系统检查.so扩展名 / Checks .dll extension on Windows, .so extension on Linux / Prüft .dll-Erweiterung unter Windows, .so-Erweiterung unter Linux
 */
static int is_valid_plugin_format(const char* plugin_path) {
    if (plugin_path == NULL) {
        return 0;
    }
    
    const char* ext = get_file_extension(plugin_path);
    if (ext == NULL) {
        return 0;
    }
    
#ifdef _WIN32
    if (strcasecmp(ext, ".dll") == 0) {
        return 1;
    }
#else
    if (strcasecmp(ext, ".so") == 0) {
        return 1;
    }
#endif
    
    return 0;
}

/**
 * @brief 检查插件文件是否存在 / Check if plugin file exists / Prüfen, ob Plugin-Datei existiert
 * @param plugin_path 插件路径 / Plugin path / Plugin-Pfad
 * @return 存在返回1，不存在返回0 / Returns 1 if exists, 0 if not exists / Gibt 1 zurück, wenn vorhanden, 0 wenn nicht vorhanden
 * @details 使用系统调用检查文件可访问性 / Uses system call to check file accessibility / Verwendet Systemaufruf zur Prüfung der Dateizugänglichkeit
 */
static int plugin_file_exists(const char* plugin_path) {
    if (plugin_path == NULL) {
        return 0;
    }
    return access(plugin_path, F_OK) == 0;
}

/**
 * @brief 验证配置有效性 / Validate configuration validity / Konfigurationsgültigkeit validieren
 * @param config 配置结构体指针 / Config structure pointer / Konfigurationsstruktur-Zeiger
 * @param config_file_path 配置文件路径 / Config file path / Konfigurationsdateipfad
 * @return 解析结果 / Parse result / Parse-Ergebnis
 * @details 检查锁模式、插件数量、插件文件存在性和格式 / Checks lock mode, plugin count, plugin file existence and format / Prüft Sperrmodus, Plugin-Anzahl, Plugin-Datei-Existenz und -Format
 */
static nxld_parse_result_t validate_config(const nxld_config_t* config, const char* config_file_path) {
    if (config->lock_mode != 0 && config->lock_mode != 1) {
        nxld_log_error("LockMode value is invalid, only 0 (off) or 1 (on) are supported");
        return NXLD_PARSE_INVALID_LOCK_MODE;
    }
    
    if (config->lock_mode == 1 && config->max_root_plugins < 1) {
        nxld_log_error("MaxRootPlugins must be >= 1 in lock mode");
        return NXLD_PARSE_INVALID_MAX_PLUGINS;
    }
    
    if (config->enabled_root_plugins_count == 0) {
        nxld_log_error("EnabledRootPlugins cannot be empty, at least 1 root plugin must be specified");
        return NXLD_PARSE_EMPTY_PLUGINS;
    }
    
    if (config->lock_mode == 1) {
        if ((int)config->enabled_root_plugins_count > config->max_root_plugins) {
            nxld_log_error("EnabledRootPlugins count (%zu) exceeds MaxRootPlugins (%d) in lock mode", 
                          config->enabled_root_plugins_count, config->max_root_plugins);
            return NXLD_PARSE_INVALID_MAX_PLUGINS;
        }
    }
    
    char config_dir[MAX_PATH_LENGTH];
    if (!get_config_dir(config_file_path, config_dir, sizeof(config_dir))) {
        nxld_log_error("Failed to get config file directory");
        return NXLD_PARSE_FILE_ERROR;
    }
    
    for (size_t i = 0; i < config->enabled_root_plugins_count; i++) {
        if (!is_valid_plugin_format(config->enabled_root_plugins[i])) {
#ifdef _WIN32
            nxld_log_error("Plugin file format is invalid for Windows system: %s (expected .dll)", config->enabled_root_plugins[i]);
#else
            nxld_log_error("Plugin file format is invalid for Linux system: %s (expected .so)", config->enabled_root_plugins[i]);
#endif
            return NXLD_PARSE_PLUGIN_INVALID_FORMAT;
        }
        
        char full_path[MAX_PATH_LENGTH];
        if (!build_plugin_full_path(config_dir, config->enabled_root_plugins[i], full_path, sizeof(full_path))) {
            nxld_log_error("Failed to build full path for plugin: %s", config->enabled_root_plugins[i]);
            return NXLD_PARSE_FILE_ERROR;
        }
        
        if (!plugin_file_exists(full_path)) {
            nxld_log_error("Plugin file not found: %s (resolved path: %s)", config->enabled_root_plugins[i], full_path);
            return NXLD_PARSE_PLUGIN_NOT_FOUND;
        }
    }
    
    for (size_t i = 0; i < config->virtual_parent_count; i++) {
        if (!is_plugin_in_enabled_list(config->virtual_parent_keys[i], config->enabled_root_plugins, config->enabled_root_plugins_count)) {
            nxld_log_error("Child plugin path in virtual parent config is not in EnabledRootPlugins: %s", config->virtual_parent_keys[i]);
            return NXLD_PARSE_VIRTUAL_PARENT_INVALID;
        }
        
        if (!is_plugin_in_enabled_list(config->virtual_parent_values[i], config->enabled_root_plugins, config->enabled_root_plugins_count)) {
            nxld_log_error("Parent plugin path in virtual parent config is not in EnabledRootPlugins: %s", config->virtual_parent_values[i]);
            return NXLD_PARSE_VIRTUAL_PARENT_INVALID;
        }
    }
    
    return NXLD_PARSE_SUCCESS;
}

/**
 * @brief 规范化插件路径用于比较 / Normalize plugin path for comparison / Plugin-Pfad für Vergleich normalisieren
 * @param path 插件路径 / Plugin path / Plugin-Pfad
 * @param normalized 输出规范化路径缓冲区 / Output normalized path buffer / Ausgabe-normalisierter Pfad-Puffer
 * @param normalized_size 缓冲区大小 / Buffer size / Puffergröße
 * @return 成功返回1，失败返回0 / Returns 1 on success, 0 on failure / Gibt 1 bei Erfolg zurück, 0 bei Fehler
 * @details 去除路径首尾空白字符以便比较 / Removes leading and trailing whitespace from path for comparison / Entfernt führende und nachfolgende Leerzeichen aus Pfad für Vergleich
 */
static int normalize_plugin_path(const char* path, char* normalized, size_t normalized_size) {
    if (path == NULL || normalized == NULL || normalized_size == 0) {
        return 0;
    }
    
    size_t len = strlen(path);
    if (len >= normalized_size) {
        len = normalized_size - 1;
    }
    
    strncpy(normalized, path, len);
    normalized[len] = '\0';
    
    char* trimmed = trim_whitespace(normalized);
    if (trimmed != normalized) {
        memmove(normalized, trimmed, strlen(trimmed) + 1);
    }
    
    return 1;
}

/**
 * @brief 检查插件路径是否在启用列表中 / Check if plugin path is in enabled list / Prüfen, ob Plugin-Pfad in aktivierter Liste ist
 * @param plugin_path 插件路径 / Plugin path / Plugin-Pfad
 * @param enabled_plugins 启用的插件路径列表 / Enabled plugin paths list / Liste aktivierter Plugin-Pfade
 * @param enabled_count 启用插件数量 / Number of enabled plugins / Anzahl aktivierter Plugins
 * @return 存在返回1，不存在返回0 / Returns 1 if exists, 0 if not exists / Gibt 1 zurück, wenn vorhanden, 0 wenn nicht vorhanden
 */
static int is_plugin_in_enabled_list(const char* plugin_path, char** enabled_plugins, size_t enabled_count) {
    if (plugin_path == NULL || enabled_plugins == NULL) {
        return 0;
    }
    
    char normalized_path[MAX_PATH_LENGTH];
    if (!normalize_plugin_path(plugin_path, normalized_path, sizeof(normalized_path))) {
        return 0;
    }
    
    for (size_t i = 0; i < enabled_count; i++) {
        if (enabled_plugins[i] == NULL) {
            continue;
        }
        
        char normalized_enabled[MAX_PATH_LENGTH];
        if (!normalize_plugin_path(enabled_plugins[i], normalized_enabled, sizeof(normalized_enabled))) {
            continue;
        }
        
        if (strcmp(normalized_path, normalized_enabled) == 0) {
            return 1;
        }
    }
    
    return 0;
}

nxld_parse_result_t nxld_parse_file(const char* file_path, nxld_config_t* config) {
    if (file_path == NULL || config == NULL) {
        nxld_log_error("Invalid parameters: file_path or config is NULL");
        return NXLD_PARSE_FILE_ERROR;
    }
    
    memset(config, 0, sizeof(nxld_config_t));
    
    if (!is_valid_utf8_file(file_path)) {
        nxld_log_error("File encoding check failed: file is not valid UTF-8 or is binary file");
        return NXLD_PARSE_ENCODING_ERROR;
    }
    
    FILE* file = fopen(file_path, "r");
    if (file == NULL) {
        nxld_log_error("Failed to open file: %s", file_path);
        return NXLD_PARSE_FILE_ERROR;
    }
    
    char line[MAX_LINE_LENGTH];
    char current_section[MAX_SECTION_NAME] = {0};
    int engine_core_found = 0;
    char key[MAX_KEY_LENGTH];
    char value[MAX_VALUE_LENGTH];
    
    size_t virtual_parent_capacity = 8;
    config->virtual_parent_keys = (char**)malloc(virtual_parent_capacity * sizeof(char*));
    config->virtual_parent_values = (char**)malloc(virtual_parent_capacity * sizeof(char*));
    if (config->virtual_parent_keys == NULL || config->virtual_parent_values == NULL) {
        fclose(file);
        nxld_log_error("Memory allocation failed for virtual parent arrays");
        return NXLD_PARSE_MEMORY_ERROR;
    }
    
    while (fgets(line, sizeof(line), file) != NULL) {
        char* trimmed_line = trim_whitespace(line);
        
        if (trimmed_line[0] == '\0' || trimmed_line[0] == '#') {
            continue;
        }
        
        if (trimmed_line[0] == '[') {
            if (parse_section_name(trimmed_line, current_section)) {
                if (strcmp(current_section, "EngineCore") == 0) {
                    engine_core_found = 1;
                } else if (strcmp(current_section, "RootPluginVirtualParent") == 0) {
                } else {
                    current_section[0] = '\0';
                }
            }
            continue;
        }
        
        if (strlen(current_section) == 0) {
            continue;
        }
        
        if (parse_key_value(trimmed_line, key, value)) {
            if (strcmp(current_section, "EngineCore") == 0) {
                if (strcmp(key, "LockMode") == 0) {
                    config->lock_mode = atoi(value);
                } else if (strcmp(key, "MaxRootPlugins") == 0) {
                    config->max_root_plugins = atoi(value);
                } else if (strcmp(key, "EnabledRootPlugins") == 0) {
                    size_t count = 0;
                    char** plugins = split_string(value, ',', &count);
                    if (plugins == NULL && count > 0) {
                        fclose(file);
                        nxld_config_free(config);
                        nxld_log_error("Memory allocation failed for plugin paths");
                        return NXLD_PARSE_MEMORY_ERROR;
                    }
                    config->enabled_root_plugins = plugins;
                    config->enabled_root_plugins_count = count;
                }
            } else if (strcmp(current_section, "RootPluginVirtualParent") == 0) {
                if (config->virtual_parent_count >= virtual_parent_capacity) {
                    virtual_parent_capacity *= 2;
                    config->virtual_parent_keys = (char**)realloc(config->virtual_parent_keys, virtual_parent_capacity * sizeof(char*));
                    config->virtual_parent_values = (char**)realloc(config->virtual_parent_values, virtual_parent_capacity * sizeof(char*));
                    if (config->virtual_parent_keys == NULL || config->virtual_parent_values == NULL) {
                        fclose(file);
                        nxld_config_free(config);
                        nxld_log_error("Memory allocation failed for virtual parent arrays expansion");
                        return NXLD_PARSE_MEMORY_ERROR;
                    }
                }
                
                config->virtual_parent_keys[config->virtual_parent_count] = (char*)malloc(strlen(key) + 1);
                config->virtual_parent_values[config->virtual_parent_count] = (char*)malloc(strlen(value) + 1);
                if (config->virtual_parent_keys[config->virtual_parent_count] == NULL || 
                    config->virtual_parent_values[config->virtual_parent_count] == NULL) {
                    fclose(file);
                    nxld_config_free(config);
                    nxld_log_error("Memory allocation failed for virtual parent key-value pair");
                    return NXLD_PARSE_MEMORY_ERROR;
                }
                
                strcpy(config->virtual_parent_keys[config->virtual_parent_count], key);
                strcpy(config->virtual_parent_values[config->virtual_parent_count], value);
                config->virtual_parent_count++;
            }
        }
    }
    
    fclose(file);
    
    if (!engine_core_found) {
        nxld_log_error("NXLD config file is missing required [EngineCore] section");
        return NXLD_PARSE_MISSING_SECTION;
    }
    
    nxld_parse_result_t validation_result = validate_config(config, file_path);
    if (validation_result != NXLD_PARSE_SUCCESS) {
        nxld_config_free(config);
        return validation_result;
    }
    
    return NXLD_PARSE_SUCCESS;
}

void nxld_config_free(nxld_config_t* config) {
    if (config == NULL) {
        return;
    }
    
    if (config->enabled_root_plugins != NULL) {
        for (size_t i = 0; i < config->enabled_root_plugins_count; i++) {
            free(config->enabled_root_plugins[i]);
        }
        free(config->enabled_root_plugins);
        config->enabled_root_plugins = NULL;
    }
    
    if (config->virtual_parent_keys != NULL) {
        for (size_t i = 0; i < config->virtual_parent_count; i++) {
            free(config->virtual_parent_keys[i]);
        }
        free(config->virtual_parent_keys);
        config->virtual_parent_keys = NULL;
    }
    
    if (config->virtual_parent_values != NULL) {
        for (size_t i = 0; i < config->virtual_parent_count; i++) {
            free(config->virtual_parent_values[i]);
        }
        free(config->virtual_parent_values);
        config->virtual_parent_values = NULL;
    }
    
    config->enabled_root_plugins_count = 0;
    config->virtual_parent_count = 0;
}

const char* nxld_get_error_message(nxld_parse_result_t result) {
    switch (result) {
        case NXLD_PARSE_SUCCESS:
            return "Parse successful";
        case NXLD_PARSE_FILE_ERROR:
            return "File read error";
        case NXLD_PARSE_ENCODING_ERROR:
            return "Encoding error: file is not valid UTF-8 or is binary file";
        case NXLD_PARSE_MISSING_SECTION:
            return "NXLD config file is missing required [EngineCore] section";
        case NXLD_PARSE_INVALID_LOCK_MODE:
            return "LockMode value is invalid, only 0 (off) or 1 (on) are supported";
        case NXLD_PARSE_INVALID_MAX_PLUGINS:
            return "MaxRootPlugins must be >= 1 in lock mode";
        case NXLD_PARSE_EMPTY_PLUGINS:
            return "EnabledRootPlugins cannot be empty, at least 1 root plugin must be specified";
        case NXLD_PARSE_PLUGIN_NOT_FOUND:
            return "Plugin file not found";
        case NXLD_PARSE_PLUGIN_INVALID_FORMAT:
#ifdef _WIN32
            return "Plugin file format is invalid for Windows system (expected .dll)";
#else
            return "Plugin file format is invalid for Linux system (expected .so)";
#endif
        case NXLD_PARSE_VIRTUAL_PARENT_INVALID:
            return "Plugin path in virtual parent config is not in EnabledRootPlugins";
        case NXLD_PARSE_MEMORY_ERROR:
            return "Memory allocation error";
        default:
            return "Unknown error";
    }
}

