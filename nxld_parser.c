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
 * @brief 验证UTF-8字节序列的有效性 / Validate UTF-8 byte sequence validity / Gültigkeit der UTF-8-Bytefolge validieren
 * @param buffer 字节缓冲区 / Byte buffer / Byte-Puffer
 * @param size 缓冲区大小 / Buffer size / Puffergröße
 * @param pos 当前位置指针 / Current position pointer / Zeiger auf aktuelle Position
 * @return 有效返回1，无效返回0 / Returns 1 if valid, 0 if invalid / Gibt 1 bei gültig zurück, 0 bei ungültig
 * @details 检查UTF-8多字节字符的完整性 / Checks UTF-8 multi-byte character completeness / Prüft Vollständigkeit von UTF-8-Mehrbyte-Zeichen
 */
static int32_t validate_utf8_sequence(const uint8_t* buffer, size_t size, size_t* pos) {
    if (*pos >= size) {
        return 0;
    }
    
    uint8_t first_byte = buffer[*pos];
    
    /* ASCII字符 (0xxxxxxx) / ASCII character / ASCII-Zeichen */
    if ((first_byte & 0x80) == 0) {
        (*pos)++;
        return 1;
    }
    
    /* 2字节字符 (110xxxxx 10xxxxxx) / 2-byte character / 2-Byte-Zeichen */
    if ((first_byte & 0xE0) == 0xC0) {
        if (*pos + 1 >= size || (buffer[*pos + 1] & 0xC0) != 0x80) {
            return 0;
        }
        /* 检查是否过度编码 / Check for overlong encoding / Prüfen auf überlange Kodierung */
        if ((first_byte & 0x1E) == 0) {
            return 0;
        }
        *pos += 2;
        return 1;
    }
    
    /* 3字节字符 (1110xxxx 10xxxxxx 10xxxxxx) / 3-byte character / 3-Byte-Zeichen */
    if ((first_byte & 0xF0) == 0xE0) {
        if (*pos + 2 >= size || 
            (buffer[*pos + 1] & 0xC0) != 0x80 || 
            (buffer[*pos + 2] & 0xC0) != 0x80) {
            return 0;
        }
        /* 检查是否过度编码 / Check for overlong encoding / Prüfen auf überlange Kodierung */
        if ((first_byte & 0x0F) == 0 && (buffer[*pos + 1] & 0x20) == 0) {
            return 0;
        }
        *pos += 3;
        return 1;
    }
    
    /* 4字节字符 (11110xxx 10xxxxxx 10xxxxxx 10xxxxxx) / 4-byte character / 4-Byte-Zeichen */
    if ((first_byte & 0xF8) == 0xF0) {
        if (*pos + 3 >= size || 
            (buffer[*pos + 1] & 0xC0) != 0x80 || 
            (buffer[*pos + 2] & 0xC0) != 0x80 || 
            (buffer[*pos + 3] & 0xC0) != 0x80) {
            return 0;
        }
        /* 检查是否过度编码 / Check for overlong encoding / Prüfen auf überlange Kodierung */
        if ((first_byte & 0x07) == 0 && (buffer[*pos + 1] & 0x30) == 0) {
            return 0;
        }
        *pos += 4;
        return 1;
    }
    
    return 0;
}

/**
 * @brief 检查文件是否为有效的UTF-8编码 / Check if file is valid UTF-8 encoding / Prüfen, ob Datei gültige UTF-8-Kodierung ist
 * @param file_path 文件路径 / File path / Dateipfad
 * @return 有效UTF-8返回1，无效返回0 / Returns 1 if valid UTF-8, 0 if invalid / Gibt 1 bei gültigem UTF-8 zurück, 0 bei ungültig
 * @details 检查整个文件是否符合UTF-8编码规范 / Checks if entire file conforms to UTF-8 encoding specification / Prüft, ob gesamte Datei UTF-8-Kodierungsspezifikation entspricht
 */
static int32_t is_valid_utf8_file(const char* file_path) {
    FILE* file = fopen(file_path, "rb");
    if (file == NULL) {
        return 0;
    }
    
    /* 读取BOM标记（如果存在） / Read BOM marker (if present) / BOM-Marker lesen (falls vorhanden) */
    uint8_t bom[3];
    size_t bom_read = fread(bom, 1, 3, file);
    int32_t has_bom = 0;
    if (bom_read >= 3 && bom[0] == 0xEF && bom[1] == 0xBB && bom[2] == 0xBF) {
        has_bom = 1;
    } else {
        /* 如果没有BOM，重置文件指针到开头 / If no BOM, reset file pointer to beginning / Wenn kein BOM, Dateizeiger auf Anfang zurücksetzen */
        rewind(file);
    }
    
    /* 使用缓冲区逐块读取文件 / Read file in chunks using buffer / Datei blockweise mit Puffer lesen */
    uint8_t buffer[4096];
    size_t pos = 0;
    size_t pending_bytes = 0;
    uint8_t pending_buffer[4] = {0};
    
    while (1) {
        size_t read = fread(buffer + pending_bytes, 1, sizeof(buffer) - pending_bytes, file);
        if (read == 0) {
            if (ferror(file)) {
                fclose(file);
                return 0;
            }
            break;
        }
        
        size_t total_size = pending_bytes + read;
        size_t check_pos = 0;
        
        /* 验证缓冲区中的UTF-8序列 / Validate UTF-8 sequences in buffer / UTF-8-Folgen im Puffer validieren */
        while (check_pos < total_size) {
            size_t old_pos = check_pos;
            if (!validate_utf8_sequence(buffer, total_size, &check_pos)) {
                fclose(file);
                return 0;
            }
            /* 如果位置没有改变，避免无限循环 / If position didn't change, avoid infinite loop / Wenn Position sich nicht geändert hat, Endlosschleife vermeiden */
            if (old_pos == check_pos) {
                fclose(file);
                return 0;
            }
        }
        
        /* 处理可能跨块的UTF-8字符 / Handle UTF-8 characters that may span chunks / UTF-8-Zeichen behandeln, die Blöcke überspannen können */
        pending_bytes = 0;
        if (total_size > 0) {
            /* 检查最后几个字节是否可能是多字节字符的开始 / Check if last few bytes might be start of multi-byte character / Prüfen, ob letzte Bytes Start eines Mehrbyte-Zeichens sein könnten */
            for (size_t i = total_size - 1; i > 0 && i >= total_size - 3; i--) {
                if ((buffer[i] & 0xC0) == 0x80) {
                    /* 这是连续字节，可能是多字节字符的一部分 / This is continuation byte, might be part of multi-byte character / Dies ist Fortsetzungsbyte, könnte Teil eines Mehrbyte-Zeichens sein */
                    pending_bytes++;
                } else if ((buffer[i] & 0x80) != 0) {
                    /* 这是多字节字符的开始字节 / This is start byte of multi-byte character / Dies ist Startbyte eines Mehrbyte-Zeichens */
                    pending_bytes = total_size - i;
                    break;
                } else {
                    /* ASCII字符，不需要保留 / ASCII character, no need to keep / ASCII-Zeichen, nicht behalten */
                    break;
                }
            }
            
            if (pending_bytes > 0 && pending_bytes < total_size) {
                /* 将可能不完整的字符移到缓冲区开头 / Move potentially incomplete character to buffer start / Möglicherweise unvollständiges Zeichen an Pufferanfang verschieben */
                memmove(pending_buffer, buffer + total_size - pending_bytes, pending_bytes);
                memmove(buffer, pending_buffer, pending_bytes);
            }
        }
    }
    
    /* 检查是否有未完成的UTF-8字符 / Check for incomplete UTF-8 characters / Prüfen auf unvollständige UTF-8-Zeichen */
    if (pending_bytes > 0) {
        size_t check_pos = 0;
        if (!validate_utf8_sequence(pending_buffer, pending_bytes, &check_pos) || check_pos != pending_bytes) {
            fclose(file);
            return 0;
        }
    }
    
    fclose(file);
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
 * @param result 结果数组指针 / Result array pointer / Ergebnisarray-Zeiger
 * @param size 数组元素数量 / Number of array elements / Anzahl der Array-Elemente
 * @details 释放数组中每个字符串指针以及数组本身的内存 / Frees memory for each string pointer in array and array itself / Gibt Speicher für jeden Zeichenfolgenzeiger im Array und das Array selbst frei
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
 * @brief 验证基本配置项的有效性（在分配内存前） / Validate basic config items validity (before memory allocation) / Gültigkeit grundlegender Konfigurationselemente validieren (vor Speicherzuweisung)
 * @param lock_mode 锁模式值 / Lock mode value / Sperrmoduswert
 * @param max_root_plugins 最大根插件数 / Maximum root plugins / Maximale Stamm-Plugins
 * @param enabled_count 启用的插件数量 / Number of enabled plugins / Anzahl aktivierter Plugins
 * @param lock_mode_set 锁模式是否已设置标志 / Flag indicating if lock mode is set / Flagge, die angibt, ob Sperrmodus gesetzt ist
 * @param max_plugins_set 最大插件数是否已设置标志 / Flag indicating if max plugins is set / Flagge, die angibt, ob maximale Plugin-Anzahl gesetzt ist
 * @return 解析结果 / Parse result / Parse-Ergebnis
 * @details 检查锁模式、插件数量等基本配置项，在分配内存前进行验证。如果相关字段未设置，则跳过相关验证 / Checks basic config items like lock mode and plugin count, validates before memory allocation. Skips related validation if fields are not set / Prüft grundlegende Konfigurationselemente wie Sperrmodus und Plugin-Anzahl, validiert vor Speicherzuweisung. Überspringt verwandte Validierung, wenn Felder nicht gesetzt sind
 */
static nxld_parse_result_t validate_basic_config(int32_t lock_mode, int32_t max_root_plugins, size_t enabled_count, int32_t lock_mode_set, int32_t max_plugins_set) {
    /* 检查插件列表是否为空 / Check if plugin list is empty / Prüfen, ob Plugin-Liste leer ist */
    if (enabled_count == 0) {
        return NXLD_PARSE_EMPTY_PLUGINS;
    }
    
    /* 如果锁模式已设置，验证其有效性 / If lock mode is set, validate its validity / Wenn Sperrmodus gesetzt ist, Gültigkeit validieren */
    if (lock_mode_set) {
        if (lock_mode != 0 && lock_mode != 1) {
            return NXLD_PARSE_INVALID_LOCK_MODE;
        }
        
        /* 如果锁模式开启，验证最大插件数和插件数量关系 / If lock mode is on, validate relationship between max plugins and plugin count / Wenn Sperrmodus aktiviert ist, Beziehung zwischen maximalen Plugins und Plugin-Anzahl validieren */
        if (lock_mode == 1) {
            if (max_plugins_set && max_root_plugins < 1) {
                return NXLD_PARSE_INVALID_MAX_PLUGINS;
            }
            if (max_plugins_set && (int32_t)enabled_count > max_root_plugins) {
                return NXLD_PARSE_INVALID_MAX_PLUGINS;
            }
        }
    }
    
    /* 如果最大插件数已设置但锁模式未设置，检查其有效性 / If max plugins is set but lock mode is not set, check its validity / Wenn maximale Plugin-Anzahl gesetzt ist, aber Sperrmodus nicht, Gültigkeit prüfen */
    if (max_plugins_set && !lock_mode_set && max_root_plugins < 1) {
        return NXLD_PARSE_INVALID_MAX_PLUGINS;
    }
    
    return NXLD_PARSE_SUCCESS;
}

/**
 * @brief 验证配置有效性 / Validate configuration validity / Konfigurationsgültigkeit validieren
 * @param config 配置结构体指针 / Config structure pointer / Konfigurationsstruktur-Zeiger
 * @param config_file_path 配置文件路径 / Config file path / Konfigurationsdateipfad
 * @return 解析结果 / Parse result / Parse-Ergebnis
 * @details 检查插件文件存在性和格式，在解析完成后进行完整验证 / Checks plugin file existence and format, performs complete validation after parsing / Prüft Plugin-Datei-Existenz und -Format, führt vollständige Validierung nach Parsen durch
 */
static int32_t is_plugin_in_enabled_list(const char* plugin_path, char** enabled_plugins, size_t enabled_count);

static nxld_parse_result_t validate_config(const nxld_config_t* config, const char* config_file_path) {
    /* 基本配置验证（在解析完成后进行完整验证） / Basic config validation (complete validation after parsing) / Grundlegende Konfigurationsvalidierung (vollständige Validierung nach Parsen) */
    nxld_parse_result_t basic_result = validate_basic_config(
        config->lock_mode, 
        config->max_root_plugins, 
        config->enabled_root_plugins_count,
        1,  /* lock_mode已设置 / lock_mode is set / lock_mode ist gesetzt */
        1   /* max_plugins已设置 / max_plugins is set / max_plugins ist gesetzt */
    );
    if (basic_result != NXLD_PARSE_SUCCESS) {
        return basic_result;
    }
    
    /* 验证插件文件格式和存在性 / Validate plugin file format and existence / Plugin-Dateiformat und -Existenz validieren */
    char config_dir[MAX_PATH_LENGTH];
    if (!nxld_utils_get_config_dir(config_file_path, config_dir, sizeof(config_dir))) {
        return NXLD_PARSE_FILE_ERROR;
    }
    
    if (config->enabled_root_plugins != NULL) {
        for (size_t i = 0; i < config->enabled_root_plugins_count; i++) {
            if (config->enabled_root_plugins[i] == NULL) {
                return NXLD_PARSE_PLUGIN_INVALID_FORMAT;
            }
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
    int32_t lock_mode_set = 0;      /* 锁模式是否已设置标志 / Flag indicating if lock mode is set / Flagge, die angibt, ob Sperrmodus gesetzt ist */
    int32_t max_plugins_set = 0;    /* 最大插件数是否已设置标志 / Flag indicating if max plugins is set / Flagge, die angibt, ob maximale Plugin-Anzahl gesetzt ist */
    char key[MAX_KEY_LENGTH];
    char value[MAX_VALUE_LENGTH];
    
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
                    lock_mode_set = 1;
                } else if (strcmp(key, "MaxRootPlugins") == 0) {
                    int32_t max_plugins_val;
                    if (!safe_strtoi32(value, &max_plugins_val, 1, INT32_MAX)) {
                        fclose(file);
                        nxld_config_free(config);
                        return NXLD_PARSE_INVALID_MAX_PLUGINS;
                    }
                    config->max_root_plugins = max_plugins_val;
                    max_plugins_set = 1;
                } else if (strcmp(key, "EnabledRootPlugins") == 0) {
                    /* 在分配内存前先验证基本配置项 / Validate basic config items before memory allocation / Grundlegende Konfigurationselemente vor Speicherzuweisung validieren */
                    size_t count = 0;
                    char** plugins = split_string(value, ',', &count);
                    if (plugins == NULL && count > 0) {
                        fclose(file);
                        nxld_config_free(config);
                        return NXLD_PARSE_MEMORY_ERROR;
                    }
                    
                    /* 验证基本配置项，避免无效配置分配内存 / Validate basic config items to avoid allocating memory for invalid config / Grundlegende Konfigurationselemente validieren, um Speicherzuweisung für ungültige Konfiguration zu vermeiden */
                    /* 如果相关字段已设置，立即验证；如果未设置，允许继续，最终验证会在解析完成后进行 / If related fields are set, validate immediately; if not set, allow to continue, final validation will be done after parsing / Wenn verwandte Felder gesetzt sind, sofort validieren; wenn nicht gesetzt, fortfahren erlauben, endgültige Validierung wird nach Parsen durchgeführt */
                    nxld_parse_result_t basic_validation = validate_basic_config(
                        config->lock_mode,
                        config->max_root_plugins,
                        count,
                        lock_mode_set,
                        max_plugins_set
                    );
                    if (basic_validation != NXLD_PARSE_SUCCESS) {
                        /* 释放已分配的内存 / Free allocated memory / Zugewiesenen Speicher freigeben */
                        if (plugins != NULL) {
                            for (size_t i = 0; i < count; i++) {
                                free(plugins[i]);
                            }
                            free(plugins);
                        }
                        fclose(file);
                        nxld_config_free(config);
                        return basic_validation;
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
                } else if (strcmp(key, "GenerateNxpFiles") == 0) {
                    int32_t generate_val;
                    if (!safe_strtoi32(value, &generate_val, 0, 1)) {
                        /**
                         * 解析失败时使用默认值0 / Use default value 0 when parsing fails / Standardwert 0 verwenden, wenn Parsen fehlschlägt
                         * 默认不生成.nxp文件 / Default to not generate .nxp files / Standardmäßig .nxp-Dateien nicht generieren
                         */
                        config->generate_nxp_files = 0;
                    } else {
                        config->generate_nxp_files = generate_val;
                    }
                }
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
    
    config->enabled_root_plugins_count = 0;
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
        case NXLD_PARSE_MEMORY_ERROR:
            return "Memory allocation error";
        default:
            return "Unknown error";
    }
}

