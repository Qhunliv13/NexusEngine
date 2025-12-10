/**
 * @file nxld_parser.c
 * @brief NXLD配置文件解析器实现 / NXLD Configuration File Parser Implementation / NXLD-Konfigurationsdatei-Parser-Implementierung
 * @details 实现解析.nxld格式配置文件的逻辑，验证配置有效性，返回配置结构体 / Implements logic for parsing .nxld format configuration files, validates configuration validity, returns configuration structure / Implementiert Logik zum Parsen von .nxld-Format-Konfigurationsdateien, validiert Konfigurationsgültigkeit, gibt Konfigurationsstruktur zurück
 */

#include "nxld_parser.h"
#include "nxld_utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>
#include <limits.h>
#include <errno.h>

#ifdef _WIN32
#include <io.h>
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
 * @details 检查文件前几个字节是否符合UTF-8编码规范 / Checks if first bytes of file conform to UTF-8 encoding specification / Prüft, ob erste Bytes der Datei UTF-8-Kodierungsspezifikation entsprechen
 */
static int32_t is_valid_utf8_file(const char* file_path) {
    FILE* file = fopen(file_path, "rb");
    if (file == NULL) {
        return 0;
    }
    
    uint8_t buffer[4];
    size_t read = fread(buffer, 1, 4, file);
    /**
     * 检查fread操作是否成功 / Check if fread operation succeeded / Prüfen, ob fread-Operation erfolgreich war
     * 如果读取失败且发生错误，返回失败 / If read fails and error occurs, return failure / Wenn Lesen fehlschlägt und Fehler auftritt, Fehler zurückgeben
     */
    if (read == 0 && ferror(file)) {
        fclose(file);
        return 0;
    }
    fclose(file);
    
    /**
     * 空文件视为有效UTF-8编码 / Empty file is considered valid UTF-8 encoding / Leere Datei wird als gültige UTF-8-Kodierung betrachtet
     * 允许空配置文件存在 / Allow empty configuration files / Leere Konfigurationsdateien zulassen
     */
    if (read == 0) {
        return 1;
    }
    
    if (read >= 3 && buffer[0] == 0xEF && buffer[1] == 0xBB && buffer[2] == 0xBF) {
        return 1;
    }
    
    size_t pos = 0;
    while (pos < read) {
        if ((buffer[pos] & 0x80) == 0) {
            pos++;
        } else if ((buffer[pos] & 0xE0) == 0xC0) {
            if (pos + 1 >= read || (buffer[pos + 1] & 0xC0) != 0x80) {
                return 0;
            }
            pos += 2;
        } else if ((buffer[pos] & 0xF0) == 0xE0) {
            if (pos + 2 >= read || (buffer[pos + 1] & 0xC0) != 0x80 || (buffer[pos + 2] & 0xC0) != 0x80) {
                return 0;
            }
            pos += 3;
        } else if ((buffer[pos] & 0xF8) == 0xF0) {
            if (pos + 3 >= read || (buffer[pos + 1] & 0xC0) != 0x80 || (buffer[pos + 2] & 0xC0) != 0x80 || (buffer[pos + 3] & 0xC0) != 0x80) {
                return 0;
            }
            pos += 4;
        } else {
            return 0;
        }
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
 * @brief 释放split_string分配的结果数组 / Free result array allocated by split_string / Ergebnisarray von split_string freigeben
 */
static void free_split_result(char** result, size_t size) {
    if (result != NULL) {
        for (size_t i = 0; i < size; i++) {
            free(result[i]);
        }
        free(result);
    }
}

/**
 * @brief 添加token到结果数组 / Add token to result array / Token zu Ergebnisarray hinzufügen
 * @param result 结果数组指针的指针 / Pointer to result array pointer / Zeiger auf Ergebnisarray-Zeiger
 * @param size 当前大小指针 / Pointer to current size / Zeiger auf aktuelle Größe
 * @param capacity 当前容量指针 / Pointer to current capacity / Zeiger auf aktuelle Kapazität
 * @param trimmed 已修剪的token字符串 / Trimmed token string / Bereinigte Token-Zeichenfolge
 * @return 成功返回1，失败返回0 / Returns 1 on success, 0 on failure / Gibt 1 bei Erfolg zurück, 0 bei Fehler
 */
static int32_t add_token_to_result(char*** result, size_t* size, size_t* capacity, const char* trimmed) {
    if (strlen(trimmed) == 0) {
        return 1;
    }
    
    if (*size >= *capacity) {
        *capacity *= 2;
        char** new_result = (char**)realloc(*result, *capacity * sizeof(char*));
        if (new_result == NULL) {
            return 0;
        }
        *result = new_result;
    }
    
    size_t trimmed_len = strlen(trimmed);
    (*result)[*size] = (char*)malloc(trimmed_len + 1);
    if ((*result)[*size] == NULL) {
        return 0;
    }
    
    memcpy((*result)[*size], trimmed, trimmed_len + 1);
    (*size)++;
    return 1;
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
                    free_split_result(result, size);
                    *count = 0;
                    return NULL;
                }
                memcpy(token, start, len);
                token[len] = '\0';
                char* trimmed = trim_whitespace(token);
                if (!add_token_to_result(&result, &size, &capacity, trimmed)) {
                    free(token);
                    free_split_result(result, size);
                    *count = 0;
                    return NULL;
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
            free_split_result(result, size);
            *count = 0;
            return NULL;
        }
        memcpy(token, start, len);
        token[len] = '\0';
        char* trimmed = trim_whitespace(token);
        if (!add_token_to_result(&result, &size, &capacity, trimmed)) {
            free(token);
            free_split_result(result, size);
            *count = 0;
            return NULL;
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
static int32_t parse_section_name(const char* line, char* section_name) {
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
    
    trim_whitespace(section_name);
    
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
static int32_t parse_key_value(const char* line, char* key, char* value) {
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
    trim_whitespace(key);
    
    const char* value_start = eq_pos + 1;
    size_t value_len = strlen(value_start);
    if (value_len >= MAX_VALUE_LENGTH) {
        value_len = MAX_VALUE_LENGTH - 1;
    }
    
    memcpy(value, value_start, value_len);
    value[value_len] = '\0';
    trim_whitespace(value);
    
    return 1;
}

/**
 * @brief 安全地将字符串转换为int32_t / Safely convert string to int32_t / Zeichenfolge sicher in int32_t umwandeln
 * @param str 输入字符串 / Input string / Eingabezeichenfolge
 * @param value 输出值指针 / Output value pointer / Ausgabe-Wert-Zeiger
 * @param min 最小值 / Minimum value / Mindestwert
 * @param max 最大值 / Maximum value / Maximalwert
 * @return 成功返回1，失败返回0 / Returns 1 on success, 0 on failure / Gibt 1 bei Erfolg zurück, 0 bei Fehler
 */
static int32_t safe_strtoi32(const char* str, int32_t* value, int32_t min, int32_t max) {
    if (str == NULL || value == NULL) {
        return 0;
    }
    
    char* endptr = NULL;
    errno = 0;
    long int result = strtol(str, &endptr, 10);
    
    /**
     * 检查字符串到整数转换错误 / Check string to integer conversion errors / Zeichenfolge-zu-Ganzzahl-Konvertierungsfehler prüfen
     * 检查errno、空指针或未完全转换的情况 / Check errno, null pointer or incomplete conversion cases / errno, Nullzeiger oder unvollständige Konvertierungsfälle prüfen
     */
    if (errno != 0 || endptr == str || *endptr != '\0') {
        return 0;
    }
    
    /**
     * 检查转换结果是否在有效范围内 / Check if conversion result is within valid range / Prüfen, ob Konvertierungsergebnis innerhalb des gültigen Bereichs liegt
     * 结果必须大于等于最小值且小于等于最大值 / Result must be greater than or equal to minimum and less than or equal to maximum / Ergebnis muss größer oder gleich Minimum und kleiner oder gleich Maximum sein
     */
    if (result < min || result > max) {
        return 0;
    }
    
    *value = (int32_t)result;
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
    const char* last_slash = nxld_utils_find_last_path_separator(file_path);
    
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
 * @details Windows系统检查.dll扩展名，Linux系统检查.so扩展名，macOS系统检查.dylib扩展名 / Checks .dll extension on Windows, .so extension on Linux, .dylib extension on macOS / Prüft .dll-Erweiterung unter Windows, .so-Erweiterung unter Linux, .dylib-Erweiterung unter macOS
 */
static int32_t is_valid_plugin_format(const char* plugin_path) {
    if (plugin_path == NULL) {
        return 0;
    }
    
    const char* ext = get_file_extension(plugin_path);
    if (ext == NULL) {
        return 0;
    }
    
#ifdef _WIN32
    return (strcasecmp(ext, ".dll") == 0);
#elif defined(__APPLE__) || defined(__MACH__)
    return (strcasecmp(ext, ".dylib") == 0);
#else
    return (strcasecmp(ext, ".so") == 0);
#endif
}

/**
 * @brief 检查插件文件是否存在 / Check if plugin file exists / Prüfen, ob Plugin-Datei existiert
 * @param plugin_path 插件路径 / Plugin path / Plugin-Pfad
 * @return 存在返回1，不存在返回0 / Returns 1 if exists, 0 if not exists / Gibt 1 zurück, wenn vorhanden, 0 wenn nicht vorhanden
 * @details 使用系统调用检查文件可访问性 / Uses system call to check file accessibility / Verwendet Systemaufruf zur Prüfung der Dateizugänglichkeit
 */
static int32_t plugin_file_exists(const char* plugin_path) {
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
static int32_t is_plugin_in_enabled_list(const char* plugin_path, char** enabled_plugins, size_t enabled_count);

static nxld_parse_result_t validate_config(const nxld_config_t* config, const char* config_file_path) {
    if (config->lock_mode != 0 && config->lock_mode != 1) {
        return NXLD_PARSE_INVALID_LOCK_MODE;
    }
    
    if (config->lock_mode == 1 && config->max_root_plugins < 1) {
        return NXLD_PARSE_INVALID_MAX_PLUGINS;
    }
    
    if (config->enabled_root_plugins_count == 0) {
        return NXLD_PARSE_EMPTY_PLUGINS;
    }
    
    if (config->lock_mode == 1) {
        if ((int32_t)config->enabled_root_plugins_count > config->max_root_plugins) {
            return NXLD_PARSE_INVALID_MAX_PLUGINS;
        }
    }
    
    
    char config_dir[MAX_PATH_LENGTH];
    if (!nxld_utils_get_config_dir(config_file_path, config_dir, sizeof(config_dir))) {
        return NXLD_PARSE_FILE_ERROR;
    }
    
    for (size_t i = 0; i < config->enabled_root_plugins_count; i++) {
        if (!is_valid_plugin_format(config->enabled_root_plugins[i])) {
            return NXLD_PARSE_PLUGIN_INVALID_FORMAT;
        }
        
        char full_path[MAX_PATH_LENGTH];
        if (!nxld_utils_build_plugin_full_path(config_dir, config->enabled_root_plugins[i], full_path, sizeof(full_path))) {
            return NXLD_PARSE_FILE_ERROR;
        }
        
        if (!plugin_file_exists(full_path)) {
            return NXLD_PARSE_PLUGIN_NOT_FOUND;
        }
    }
    
    for (size_t i = 0; i < config->virtual_parent_count; i++) {
        if (!is_plugin_in_enabled_list(config->virtual_parent_keys[i], config->enabled_root_plugins, config->enabled_root_plugins_count)) {
            return NXLD_PARSE_VIRTUAL_PARENT_INVALID;
        }
        
        if (!is_plugin_in_enabled_list(config->virtual_parent_values[i], config->enabled_root_plugins, config->enabled_root_plugins_count)) {
            return NXLD_PARSE_VIRTUAL_PARENT_INVALID;
        }
    }
    
    return NXLD_PARSE_SUCCESS;
}

/**
 * @brief 检查插件路径是否在启用列表中 / Check if plugin path is in enabled list / Prüfen, ob Plugin-Pfad in aktivierter Liste ist
 * @param plugin_path 插件路径 / Plugin path / Plugin-Pfad
 * @param enabled_plugins 启用的插件路径列表 / Enabled plugin paths list / Liste aktivierter Plugin-Pfade
 * @param enabled_count 启用插件数量 / Number of enabled plugins / Anzahl aktivierter Plugins
 * @return 存在返回1，不存在返回0 / Returns 1 if exists, 0 if not exists / Gibt 1 zurück, wenn vorhanden, 0 wenn nicht vorhanden
 */
static int32_t is_plugin_in_enabled_list(const char* plugin_path, char** enabled_plugins, size_t enabled_count) {
    if (plugin_path == NULL || enabled_plugins == NULL) {
        return 0;
    }
    
    char normalized_path[MAX_PATH_LENGTH];
    size_t path_len = strlen(plugin_path);
    if (path_len >= MAX_PATH_LENGTH) {
        path_len = MAX_PATH_LENGTH - 1;
    }
    memcpy(normalized_path, plugin_path, path_len);
    normalized_path[path_len] = '\0';
    trim_whitespace(normalized_path);
    
    for (size_t i = 0; i < enabled_count; i++) {
        if (enabled_plugins[i] == NULL) {
            continue;
        }
        
        char normalized_enabled[MAX_PATH_LENGTH];
        size_t enabled_len = strlen(enabled_plugins[i]);
        if (enabled_len >= MAX_PATH_LENGTH) {
            enabled_len = MAX_PATH_LENGTH - 1;
        }
        memcpy(normalized_enabled, enabled_plugins[i], enabled_len);
        normalized_enabled[enabled_len] = '\0';
        trim_whitespace(normalized_enabled);
        
        if (strcmp(normalized_path, normalized_enabled) == 0) {
            return 1;
        }
    }
    
    return 0;
}

nxld_parse_result_t nxld_parse_file(const char* file_path, nxld_config_t* config) {
    if (file_path == NULL || config == NULL) {
        return NXLD_PARSE_FILE_ERROR;
    }
    
    memset(config, 0, sizeof(nxld_config_t));
    config->plugin_load_failure_policy = 0;
    
    if (!is_valid_utf8_file(file_path)) {
        return NXLD_PARSE_ENCODING_ERROR;
    }
    
    FILE* file = fopen(file_path, "r");
    if (file == NULL) {
        return NXLD_PARSE_FILE_ERROR;
    }
    
    char line[MAX_LINE_LENGTH];
    char current_section[MAX_SECTION_NAME] = {0};
    int32_t engine_core_found = 0;
    char key[MAX_KEY_LENGTH];
    char value[MAX_VALUE_LENGTH];
    
    size_t virtual_parent_capacity = 8;
    config->virtual_parent_keys = (char**)malloc(virtual_parent_capacity * sizeof(char*));
    config->virtual_parent_values = (char**)malloc(virtual_parent_capacity * sizeof(char*));
    if (config->virtual_parent_keys == NULL || config->virtual_parent_values == NULL) {
        fclose(file);
        if (config->virtual_parent_keys != NULL) {
            free(config->virtual_parent_keys);
        }
        if (config->virtual_parent_values != NULL) {
            free(config->virtual_parent_values);
        }
        return NXLD_PARSE_MEMORY_ERROR;
    }
    
    while (fgets(line, sizeof(line), file) != NULL) {
        /**
         * 检查行是否被截断 / Check if line was truncated / Prüfen, ob Zeile abgeschnitten wurde
         * 如果行长度等于缓冲区大小减1且最后一个字符不是换行符，则行被截断 / If line length equals buffer size minus 1 and last character is not newline, line is truncated / Wenn Zeilenlänge gleich Puffergröße minus 1 ist und letztes Zeichen kein Zeilenumbruch ist, wurde Zeile abgeschnitten
         */
        size_t line_len = strlen(line);
        if (line_len > 0 && line[line_len - 1] != '\n' && line_len == sizeof(line) - 1) {
            /**
             * 行被截断时跳过剩余字符直到换行符 / When line is truncated, skip remaining characters until newline / Wenn Zeile abgeschnitten wurde, verbleibende Zeichen bis Zeilenumbruch überspringen
             * 避免读取不完整的数据 / Avoid reading incomplete data / Unvollständige Daten vermeiden
             */
            int ch;
            while ((ch = fgetc(file)) != EOF && ch != '\n') {
                /* 跳过字符直到换行符 / Skip characters until newline / Zeichen bis Zeilenumbruch überspringen */
            }
            /**
             * 继续处理下一行 / Continue processing next line / Mit nächster Zeile fortfahren
             * 被截断的行将被忽略 / Truncated line will be ignored / Abgeschnittene Zeile wird ignoriert
             */
            continue;
        }
        
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
                    int32_t lock_mode_val;
                    if (!safe_strtoi32(value, &lock_mode_val, 0, 1)) {
                        fclose(file);
                        nxld_config_free(config);
                        return NXLD_PARSE_INVALID_LOCK_MODE;
                    }
                    config->lock_mode = lock_mode_val;
                } else if (strcmp(key, "MaxRootPlugins") == 0) {
                    int32_t max_plugins_val;
                    if (!safe_strtoi32(value, &max_plugins_val, 1, INT32_MAX)) {
                        fclose(file);
                        nxld_config_free(config);
                        return NXLD_PARSE_INVALID_MAX_PLUGINS;
                    }
                    config->max_root_plugins = max_plugins_val;
                } else if (strcmp(key, "EnabledRootPlugins") == 0) {
                    size_t count = 0;
                    char** plugins = split_string(value, ',', &count);
                    if (plugins == NULL && count > 0) {
                        fclose(file);
                        nxld_config_free(config);
                        return NXLD_PARSE_MEMORY_ERROR;
                    }
                    config->enabled_root_plugins = plugins;
                    config->enabled_root_plugins_count = count;
                } else if (strcmp(key, "PluginLoadFailurePolicy") == 0) {
                    int32_t policy_val;
                    if (!safe_strtoi32(value, &policy_val, 0, 1)) {
                        /**
                         * 解析失败时使用默认值0 / Use default value 0 when parsing fails / Standardwert 0 verwenden, wenn Parsen fehlschlägt
                         * 默认策略为继续加载其他插件 / Default policy is to continue loading other plugins / Standardrichtlinie ist, andere Plugins weiter zu laden
                         */
                        config->plugin_load_failure_policy = 0;
                    } else {
                        config->plugin_load_failure_policy = policy_val;
                    }
                }
            } else if (strcmp(current_section, "RootPluginVirtualParent") == 0) {
                if (config->virtual_parent_count >= virtual_parent_capacity) {
                    virtual_parent_capacity *= 2;
                    /**
                     * 使用临时指针保存realloc结果，避免内存泄漏 / Use temporary pointers to save realloc results, avoid memory leaks / Temporäre Zeiger verwenden, um realloc-Ergebnisse zu speichern, Speicherlecks vermeiden
                     * 如果realloc失败，原指针仍然有效 / If realloc fails, original pointer remains valid / Wenn realloc fehlschlägt, bleibt ursprünglicher Zeiger gültig
                     */
                    char** new_keys = (char**)realloc(config->virtual_parent_keys, virtual_parent_capacity * sizeof(char*));
                    char** new_values = (char**)realloc(config->virtual_parent_values, virtual_parent_capacity * sizeof(char*));
                    if (new_keys == NULL || new_values == NULL) {
                        /**
                         * realloc部分失败时的回滚处理 / Rollback handling when realloc partially fails / Rollback-Behandlung, wenn realloc teilweise fehlschlägt
                         * 如果其中一个成功而另一个失败，需要释放已分配的内存 / If one succeeds and the other fails, need to free allocated memory / Wenn einer erfolgreich ist und der andere fehlschlägt, muss zugewiesener Speicher freigegeben werden
                         */
                        if (new_keys != NULL) {
                            /**
                             * new_keys成功但new_values失败，释放new_keys / new_keys succeeded but new_values failed, free new_keys / new_keys erfolgreich, aber new_values fehlgeschlagen, new_keys freigeben
                             */
                            free(new_keys);
                        }
                        if (new_values != NULL) {
                            /**
                             * new_values成功但new_keys失败，释放new_values / new_values succeeded but new_keys failed, free new_values / new_values erfolgreich, aber new_keys fehlgeschlagen, new_values freigeben
                             */
                            free(new_values);
                        }
                        fclose(file);
                        nxld_config_free(config);
                        return NXLD_PARSE_MEMORY_ERROR;
                    }
                    /**
                     * 两个realloc操作都成功，更新配置结构体指针 / Both realloc operations succeeded, update config structure pointers / Beide realloc-Operationen erfolgreich, Konfigurationsstruktur-Zeiger aktualisieren
                     * 使用新分配的内存地址替换原有指针 / Replace original pointers with newly allocated memory addresses / Ursprüngliche Zeiger durch neu zugewiesene Speicheradressen ersetzen
                     */
                    config->virtual_parent_keys = new_keys;
                    config->virtual_parent_values = new_values;
                }
                
                size_t key_len = strlen(key) + 1;
                size_t value_len = strlen(value) + 1;
                config->virtual_parent_keys[config->virtual_parent_count] = (char*)malloc(key_len);
                config->virtual_parent_values[config->virtual_parent_count] = (char*)malloc(value_len);
                if (config->virtual_parent_keys[config->virtual_parent_count] == NULL || 
                    config->virtual_parent_values[config->virtual_parent_count] == NULL) {
                    fclose(file);
                    if (config->virtual_parent_keys[config->virtual_parent_count] != NULL) {
                        free(config->virtual_parent_keys[config->virtual_parent_count]);
                    }
                    if (config->virtual_parent_values[config->virtual_parent_count] != NULL) {
                        free(config->virtual_parent_values[config->virtual_parent_count]);
                    }
                    nxld_config_free(config);
                    return NXLD_PARSE_MEMORY_ERROR;
                }
                
                memcpy(config->virtual_parent_keys[config->virtual_parent_count], key, key_len);
                memcpy(config->virtual_parent_values[config->virtual_parent_count], value, value_len);
                config->virtual_parent_count++;
            }
        }
    }
    
    fclose(file);
    
    if (!engine_core_found) {
        nxld_config_free(config);
        return NXLD_PARSE_MISSING_SECTION;
    }
    
    if (config->plugin_load_failure_policy != 0 && config->plugin_load_failure_policy != 1) {
        config->plugin_load_failure_policy = 0;
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
#elif defined(__APPLE__) || defined(__MACH__)
            return "Plugin file format is invalid for macOS system (expected .dylib)";
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

