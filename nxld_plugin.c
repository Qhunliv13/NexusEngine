/**
 * @file nxld_plugin.c
 * @brief NXLD插件加载和管理实现 / NXLD Plugin Loading and Management Implementation / NXLD-Plugin-Lade- und Verwaltungsimplementierung
 */

#include "nxld_plugin.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>

#ifdef _WIN32
/**
 * @brief Windows平台字符串安全复制宏 / Windows platform safe string copy macro / Windows-Plattform sicheres Zeichenfolgen-Kopier-Makro
 * @details strcpy_s的参数顺序为(dest, dest_size, src) / Parameter order of strcpy_s is (dest, dest_size, src) / Parameterreihenfolge von strcpy_s ist (dest, dest_size, src)
 */
#define strcpy_safe(dest, dest_size, src) strcpy_s(dest, dest_size, src)
/**
 * @brief Windows平台字符串安全连接宏 / Windows platform safe string concatenation macro / Windows-Plattform sicheres Zeichenfolgen-Verkettungs-Makro
 * @details strcat_s的参数顺序为(dest, dest_size, src) / Parameter order of strcat_s is (dest, dest_size, src) / Parameterreihenfolge von strcat_s ist (dest, dest_size, src)
 */
#define strcat_safe(dest, dest_size, src) strcat_s(dest, dest_size, src)
/**
 * @brief 兼容旧版MSVC编译器的snprintf宏 / Compatibility macro for older MSVC compiler snprintf / Kompatibilitätsmakro für älteren MSVC-Compiler snprintf
 * @details MSVC 2015之前版本使用_snprintf / Versions before MSVC 2015 use _snprintf / Versionen vor MSVC 2015 verwenden _snprintf
 */
#if defined(_MSC_VER) && _MSC_VER < 1900
#define snprintf _snprintf
#endif
/**
 * @brief 兼容旧版MSVC编译器的size_t格式说明符 / Compatibility format specifier for older MSVC compiler size_t / Kompatibilitätsformatbezeichner für älteren MSVC-Compiler size_t
 * @details MSVC 2015之前版本使用"Iu"，之后版本使用"zu" / Versions before MSVC 2015 use "Iu", later versions use "zu" / Versionen vor MSVC 2015 verwenden "Iu", spätere Versionen verwenden "zu"
 */
#ifndef PRIzu
#if defined(_MSC_VER) && _MSC_VER < 1900
#define PRIzu "Iu"
#else
#define PRIzu "zu"
#endif
#endif
#else
/**
 * @brief Unix平台字符串安全复制宏 / Unix platform safe string copy macro / Unix-Plattform sicheres Zeichenfolgen-Kopier-Makro
 * @details 手动实现安全复制，截断超出部分 / Manually implement safe copy, truncate excess / Manuell sicheres Kopieren implementieren, Überschuss abschneiden
 */
#define strcpy_safe(dest, dest_size, src) do { \
    size_t len = strlen(src); \
    if (len >= dest_size) len = dest_size - 1; \
    memcpy(dest, src, len); \
    dest[len] = '\0'; \
} while(0)
/**
 * @brief Unix平台字符串安全连接宏 / Unix platform safe string concatenation macro / Unix-Plattform sicheres Zeichenfolgen-Verkettungs-Makro
 * @details 手动实现安全连接，截断超出部分 / Manually implement safe concatenation, truncate excess / Manuell sicheres Verketten implementieren, Überschuss abschneiden
 */
#define strcat_safe(dest, dest_size, src) do { \
    size_t dest_len = strlen(dest); \
    size_t src_len = strlen(src); \
    size_t available = dest_size - dest_len - 1; \
    if (src_len > available) src_len = available; \
    memcpy(dest + dest_len, src, src_len); \
    dest[dest_len + src_len] = '\0'; \
} while(0)
/**
 * @brief Unix平台size_t格式说明符 / Unix platform size_t format specifier / Unix-Plattform size_t-Formatbezeichner
 * @details 使用标准"zu"格式说明符 / Use standard "zu" format specifier / Standard-"zu"-Formatbezeichner verwenden
 */
#ifndef PRIzu
#define PRIzu "zu"
#endif
#endif

#ifdef _WIN32
#include <windows.h>
#include <wincrypt.h>
#else
#include <dlfcn.h>
#endif

#define MAX_NAME_LENGTH 256
#define MAX_VERSION_LENGTH 64
#define MAX_DESCRIPTION_LENGTH 512
#define UID_LENGTH 64

/**
 * @brief 从.nxp元数据文件中读取UID / Read UID from .nxp metadata file / UID aus .nxp-Metadaten-Datei lesen
 * @param nxp_path .nxp文件路径 / .nxp file path / .nxp-Dateipfad
 * @param uid 输出UID缓冲区 / Output UID buffer / Ausgabe-UID-Puffer
 * @param uid_size 缓冲区大小 / Buffer size / Puffergröße
 * @return 成功返回1，失败返回0 / Returns 1 on success, 0 on failure / Gibt 1 bei Erfolg zurück, 0 bei Fehler
 */
static int32_t read_uid_from_nxp(const char* nxp_path, char* uid, size_t uid_size) {
    if (nxp_path == NULL || uid == NULL || uid_size < UID_LENGTH + 1) {
        return 0;
    }
    
    FILE* fp = fopen(nxp_path, "r");
    if (fp == NULL) {
        return 0;
    }
    
    char line_buffer[1024];
    int32_t in_plugin_section = 0;
    int32_t found = 0;
    
    while (fgets(line_buffer, sizeof(line_buffer), fp) != NULL && !found) {
        /**
         * 去除行首尾空白字符 / Remove leading and trailing whitespace / Führende und nachfolgende Leerzeichen entfernen
         * 包括换行符、回车符、空格和制表符 / Including newline, carriage return, space and tab characters / Einschließlich Zeilenumbruch, Wagenrücklauf, Leerzeichen und Tabulatorzeichen
         */
        size_t len = strlen(line_buffer);
        while (len > 0 && (line_buffer[len - 1] == '\r' || line_buffer[len - 1] == '\n' || line_buffer[len - 1] == ' ' || line_buffer[len - 1] == '\t')) {
            line_buffer[--len] = '\0';
        }
        
        /**
         * 跳过空行和注释行 / Skip empty lines and comment lines / Leere Zeilen und Kommentarzeilen überspringen
         * 注释行以#开头 / Comment lines start with # / Kommentarzeilen beginnen mit #
         */
        if (len == 0 || line_buffer[0] == '#') {
            continue;
        }
        
        /**
         * 检查节标记 / Check section marker / Abschnittsmarkierung prüfen
         * 节标记格式为[SectionName] / Section marker format is [SectionName] / Abschnittsmarkierungsformat ist [SectionName]
         */
        if (len >= 2 && line_buffer[0] == '[' && line_buffer[len - 1] == ']') {
            if (strcmp(line_buffer, "[Plugin]") == 0) {
                in_plugin_section = 1;
            } else {
                in_plugin_section = 0;
            }
            continue;
        }
        
        /**
         * 在[Plugin]节中查找UID键值对 / Look for UID key-value pair in [Plugin] section / UID-Schlüssel-Wert-Paar in [Plugin]-Abschnitt suchen
         * UID格式为UID=value / UID format is UID=value / UID-Format ist UID=value
         */
        if (in_plugin_section && strncmp(line_buffer, "UID=", 4) == 0) {
            const char* uid_value = line_buffer + 4;
            size_t uid_len = strlen(uid_value);
            if (uid_len > 0 && uid_len <= UID_LENGTH) {
                size_t copy_len = uid_len < uid_size - 1 ? uid_len : uid_size - 1;
                memcpy(uid, uid_value, copy_len);
                uid[copy_len] = '\0';
                found = 1;
            }
        }
    }
    
    fclose(fp);
    return found ? 1 : 0;
}

/**
 * @brief 生成64位随机字符串UID / Generate 64-bit random string UID / 64-Bit-Zufallszeichenfolge-UID generieren
 * @param uid 输出UID缓冲区 / Output UID buffer / Ausgabe-UID-Puffer
 * @param uid_size 缓冲区大小 / Buffer size / Puffergröße
 * @return 成功返回1，失败返回0 / Returns 1 on success, 0 on failure / Gibt 1 bei Erfolg zurück, 0 bei Fehler
 * @details 使用平台特定的加密安全随机数生成器 / Uses platform-specific cryptographically secure random number generator / Verwendet plattformspezifischen kryptografisch sicheren Zufallszahlengenerator
 */
static int32_t generate_uid(char* uid, size_t uid_size) {
    if (uid == NULL || uid_size < UID_LENGTH + 1) {
        return 0;
    }
    
    const char charset[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    const size_t charset_size = sizeof(charset) - 1;
    
#ifdef _WIN32
    /**
     * Windows平台：使用CryptGenRandom生成加密安全随机数 / Windows platform: Use CryptGenRandom to generate cryptographically secure random numbers / Windows-Plattform: Verwenden Sie CryptGenRandom, um kryptografisch sichere Zufallszahlen zu generieren
     * 需要wincrypt.h头文件和advapi32库 / Requires wincrypt.h header and advapi32 library / Erfordert wincrypt.h-Header und advapi32-Bibliothek
     */
    HCRYPTPROV hProv = 0;
    if (!CryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        /**
         * CryptAcquireContext失败时回退到time+rand方法 / Fallback to time+rand method when CryptAcquireContext fails / Fallback auf time+rand-Methode, wenn CryptAcquireContext fehlschlägt
         * 此方法安全性较低，仅用于兼容性 / This method has lower security, used only for compatibility / Diese Methode hat geringere Sicherheit, wird nur für Kompatibilität verwendet
         */
        static int32_t seeded = 0;
        if (!seeded) {
            srand((unsigned int)time(NULL));
            seeded = 1;
        }
        for (size_t i = 0; i < UID_LENGTH; i++) {
            uid[i] = charset[rand() % charset_size];
        }
    } else {
        uint8_t random_bytes[UID_LENGTH];
        if (CryptGenRandom(hProv, UID_LENGTH, random_bytes)) {
            for (size_t i = 0; i < UID_LENGTH; i++) {
                uid[i] = charset[random_bytes[i] % charset_size];
            }
        } else {
            CryptReleaseContext(hProv, 0);
            return 0;
        }
        CryptReleaseContext(hProv, 0);
    }
#elif defined(__APPLE__) || defined(__MACH__)
    /**
     * macOS/iOS平台：使用arc4random_uniform生成加密安全随机数 / macOS/iOS platform: Use arc4random_uniform to generate cryptographically secure random numbers / macOS/iOS-Plattform: Verwenden Sie arc4random_uniform, um kryptografisch sichere Zufallszahlen zu generieren
     */
    for (size_t i = 0; i < UID_LENGTH; i++) {
        uid[i] = charset[arc4random_uniform(charset_size)];
    }
#elif defined(__linux__) || defined(__unix__)
    /**
     * Linux/Unix平台：使用/dev/urandom生成加密安全随机数 / Linux/Unix platform: Use /dev/urandom to generate cryptographically secure random numbers / Linux/Unix-Plattform: Verwenden Sie /dev/urandom, um kryptografisch sichere Zufallszahlen zu generieren
     */
    FILE* urandom = fopen("/dev/urandom", "rb");
    if (urandom != NULL) {
        uint8_t random_bytes[UID_LENGTH];
        if (fread(random_bytes, 1, UID_LENGTH, urandom) == UID_LENGTH) {
            for (size_t i = 0; i < UID_LENGTH; i++) {
                uid[i] = charset[random_bytes[i] % charset_size];
            }
            fclose(urandom);
        } else {
            fclose(urandom);
            return 0;
        }
    } else {
        /**
         * /dev/urandom打开失败时回退到time+rand方法 / Fallback to time+rand method when /dev/urandom open fails / Fallback auf time+rand-Methode, wenn /dev/urandom-Öffnen fehlschlägt
         * 此方法安全性较低，仅用于兼容性 / This method has lower security, used only for compatibility / Diese Methode hat geringere Sicherheit, wird nur für Kompatibilität verwendet
         */
        static int32_t seeded = 0;
        if (!seeded) {
            srand((unsigned int)time(NULL));
            seeded = 1;
        }
        for (size_t i = 0; i < UID_LENGTH; i++) {
            uid[i] = charset[rand() % charset_size];
        }
    }
#else
    /**
     * 未知平台：回退到time+rand方法 / Unknown platform: Fallback to time+rand method / Unbekannte Plattform: Fallback auf time+rand-Methode
     * 此方法安全性较低，仅用于兼容性 / This method has lower security, used only for compatibility / Diese Methode hat geringere Sicherheit, wird nur für Kompatibilität verwendet
     */
    static int32_t seeded = 0;
    if (!seeded) {
        srand((unsigned int)time(NULL));
        seeded = 1;
    }
    for (size_t i = 0; i < UID_LENGTH; i++) {
        uid[i] = charset[rand() % charset_size];
    }
#endif
    
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
static int32_t close_dynamic_library(void* handle) {
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
        /**
         * 移除错误消息尾部的换行符和空格字符 / Remove trailing newline and space characters from error message / Nachfolgende Zeilenumbruch- und Leerzeichen aus Fehlermeldung entfernen
         * FormatMessage返回的消息可能包含多余的空白字符 / Messages returned by FormatMessage may contain extra whitespace characters / Von FormatMessage zurückgegebene Nachrichten können zusätzliche Leerzeichen enthalten
         */
        size_t len = strlen(error_msg);
        while (len > 0 && (error_msg[len - 1] == '\r' || error_msg[len - 1] == '\n' || error_msg[len - 1] == ' ')) {
            error_msg[--len] = '\0';
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
        return NXLD_PLUGIN_LOAD_FILE_ERROR;
    }
    
    memset(plugin, 0, sizeof(nxld_plugin_t));
    
    void* handle = load_dynamic_library(plugin_path);
    if (handle == NULL) {
        return NXLD_PLUGIN_LOAD_FILE_ERROR;
    }
    
    plugin->handle = handle;
    
    plugin->plugin_path = (char*)malloc(strlen(plugin_path) + 1);
    if (plugin->plugin_path == NULL) {
        close_dynamic_library(handle);
        return NXLD_PLUGIN_LOAD_MEMORY_ERROR;
    }
    strcpy_safe(plugin->plugin_path, strlen(plugin_path) + 1, plugin_path);
    
    nxld_plugin_get_name_func get_name = (nxld_plugin_get_name_func)get_symbol(handle, "nxld_plugin_get_name");
    nxld_plugin_get_version_func get_version = (nxld_plugin_get_version_func)get_symbol(handle, "nxld_plugin_get_version");
    nxld_plugin_get_interface_count_func get_interface_count = (nxld_plugin_get_interface_count_func)get_symbol(handle, "nxld_plugin_get_interface_count");
    nxld_plugin_get_interface_info_func get_interface_info = (nxld_plugin_get_interface_info_func)get_symbol(handle, "nxld_plugin_get_interface_info");
    
    if (get_name == NULL || get_version == NULL || get_interface_count == NULL || get_interface_info == NULL) {
        close_dynamic_library(handle);
        nxld_plugin_free(plugin);
        return NXLD_PLUGIN_LOAD_SYMBOL_ERROR;
    }
    
    char name_buffer[MAX_NAME_LENGTH];
    char version_buffer[MAX_VERSION_LENGTH];
    
    if (get_name(name_buffer, sizeof(name_buffer)) != 0) {
        close_dynamic_library(handle);
        nxld_plugin_free(plugin);
        return NXLD_PLUGIN_LOAD_METADATA_ERROR;
    }
    
    plugin->plugin_name = (char*)malloc(strlen(name_buffer) + 1);
    if (plugin->plugin_name == NULL) {
        close_dynamic_library(handle);
        nxld_plugin_free(plugin);
        return NXLD_PLUGIN_LOAD_MEMORY_ERROR;
    }
    strcpy_safe(plugin->plugin_name, strlen(name_buffer) + 1, name_buffer);
    
    if (get_version(version_buffer, sizeof(version_buffer)) != 0) {
        close_dynamic_library(handle);
        nxld_plugin_free(plugin);
        return NXLD_PLUGIN_LOAD_METADATA_ERROR;
    }
    
    plugin->plugin_version = (char*)malloc(strlen(version_buffer) + 1);
    if (plugin->plugin_version == NULL) {
        close_dynamic_library(handle);
        nxld_plugin_free(plugin);
        return NXLD_PLUGIN_LOAD_MEMORY_ERROR;
    }
    strcpy_safe(plugin->plugin_version, strlen(version_buffer) + 1, version_buffer);
    
    size_t interface_count = 0;
    if (get_interface_count(&interface_count) != 0) {
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
            return NXLD_PLUGIN_LOAD_MEMORY_ERROR;
        }
        
        memset(plugin->interfaces, 0, interface_count * sizeof(nxld_interface_info_t));
        
        nxld_plugin_get_interface_param_count_func get_param_count = 
            (nxld_plugin_get_interface_param_count_func)get_symbol(handle, "nxld_plugin_get_interface_param_count");
        nxld_plugin_get_interface_param_info_func get_param_info = 
            (nxld_plugin_get_interface_param_info_func)get_symbol(handle, "nxld_plugin_get_interface_param_info");
        
        int32_t has_param_info = (get_param_count != NULL && get_param_info != NULL);
        
        for (size_t i = 0; i < interface_count; i++) {
            char iface_name[MAX_NAME_LENGTH] = {0};
            char iface_desc[MAX_DESCRIPTION_LENGTH] = {0};
            char iface_version[MAX_VERSION_LENGTH] = {0};
            
            if (get_interface_info(i, iface_name, sizeof(iface_name),
                                   iface_desc, sizeof(iface_desc),
                                   iface_version, sizeof(iface_version)) != 0) {
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
                close_dynamic_library(handle);
                nxld_plugin_free(plugin);
                return NXLD_PLUGIN_LOAD_MEMORY_ERROR;
            }
            
            strcpy_safe(plugin->interfaces[i].name, strlen(iface_name) + 1, iface_name);
            strcpy_safe(plugin->interfaces[i].description, strlen(iface_desc) + 1, iface_desc);
            strcpy_safe(plugin->interfaces[i].version, strlen(iface_version) + 1, iface_version);
            
            plugin->interfaces[i].param_count_type = NXLD_PARAM_COUNT_UNKNOWN;
            plugin->interfaces[i].min_param_count = 0;
            plugin->interfaces[i].max_param_count = -1;
            plugin->interfaces[i].params = NULL;
            plugin->interfaces[i].param_count = 0;
            
            if (has_param_info) {
                nxld_param_count_type_t count_type;
                int32_t min_count, max_count;
                
                if (get_param_count(i, &count_type, &min_count, &max_count) == 0) {
                    plugin->interfaces[i].param_count_type = count_type;
                    plugin->interfaces[i].min_param_count = min_count;
                    plugin->interfaces[i].max_param_count = max_count;
                    
                    if (count_type == NXLD_PARAM_COUNT_FIXED && min_count > 0) {
                        plugin->interfaces[i].param_count = min_count;
                        plugin->interfaces[i].params = (nxld_param_info_t*)malloc(min_count * sizeof(nxld_param_info_t));
                        if (plugin->interfaces[i].params == NULL) {
                            close_dynamic_library(handle);
                            nxld_plugin_free(plugin);
                            return NXLD_PLUGIN_LOAD_MEMORY_ERROR;
                        }
                        
                        memset(plugin->interfaces[i].params, 0, min_count * sizeof(nxld_param_info_t));
                        
                        /**
                         * 使用size_t作为循环变量以确保与param_count类型一致 / Use size_t as loop variable to ensure consistency with param_count type / size_t als Schleifenvariable verwenden, um Konsistenz mit param_count-Typ sicherzustellen
                         * min_count已转换为size_t存储在param_count中 / min_count has been converted to size_t and stored in param_count / min_count wurde in size_t konvertiert und in param_count gespeichert
                         */
                        for (size_t j = 0; j < plugin->interfaces[i].param_count; j++) {
                            char param_name[MAX_NAME_LENGTH];
                            nxld_param_type_t param_type;
                            char type_name[MAX_NAME_LENGTH] = {0};
                            
                            if (get_param_info(i, j, param_name, sizeof(param_name),
                                              &param_type, type_name, sizeof(type_name)) == 0) {
                                plugin->interfaces[i].params[j].name = (char*)malloc(strlen(param_name) + 1);
                                if (plugin->interfaces[i].params[j].name == NULL) {
                                    close_dynamic_library(handle);
                                    nxld_plugin_free(plugin);
                                    return NXLD_PLUGIN_LOAD_MEMORY_ERROR;
                                }
                                strcpy_safe(plugin->interfaces[i].params[j].name, strlen(param_name) + 1, param_name);
                                
                                plugin->interfaces[i].params[j].type = param_type;
                                
                                if (strlen(type_name) > 0) {
                                    plugin->interfaces[i].params[j].type_name = (char*)malloc(strlen(type_name) + 1);
                                    if (plugin->interfaces[i].params[j].type_name == NULL) {
                                        close_dynamic_library(handle);
                                        nxld_plugin_free(plugin);
                                        return NXLD_PLUGIN_LOAD_MEMORY_ERROR;
                                    }
                                    strcpy_safe(plugin->interfaces[i].params[j].type_name, strlen(type_name) + 1, type_name);
                                } else {
                                    plugin->interfaces[i].params[j].type_name = NULL;
                                }
                            } else {
                                plugin->interfaces[i].params[j].name = NULL;
                                plugin->interfaces[i].params[j].type = NXLD_PARAM_TYPE_UNKNOWN;
                                plugin->interfaces[i].params[j].type_name = NULL;
                            }
                        }
                    } else if (count_type == NXLD_PARAM_COUNT_VARIABLE) {
                        if (min_count > 0) {
                            plugin->interfaces[i].param_count = min_count;
                            plugin->interfaces[i].params = (nxld_param_info_t*)malloc(min_count * sizeof(nxld_param_info_t));
                            if (plugin->interfaces[i].params == NULL) {
                                close_dynamic_library(handle);
                                nxld_plugin_free(plugin);
                                return NXLD_PLUGIN_LOAD_MEMORY_ERROR;
                            }
                            
                            memset(plugin->interfaces[i].params, 0, min_count * sizeof(nxld_param_info_t));
                            
                            /**
                             * 使用size_t作为循环变量以确保与param_count类型一致 / Use size_t as loop variable to ensure consistency with param_count type / size_t als Schleifenvariable verwenden, um Konsistenz mit param_count-Typ sicherzustellen
                             * min_count已转换为size_t存储在param_count中 / min_count has been converted to size_t and stored in param_count / min_count wurde in size_t konvertiert und in param_count gespeichert
                             */
                            for (size_t j = 0; j < plugin->interfaces[i].param_count; j++) {
                                char param_name[MAX_NAME_LENGTH];
                                nxld_param_type_t param_type;
                                char type_name[MAX_NAME_LENGTH] = {0};
                                
                                if (get_param_info(i, j, param_name, sizeof(param_name),
                                                  &param_type, type_name, sizeof(type_name)) == 0) {
                                    plugin->interfaces[i].params[j].name = (char*)malloc(strlen(param_name) + 1);
                                    if (plugin->interfaces[i].params[j].name == NULL) {
                                        close_dynamic_library(handle);
                                        nxld_plugin_free(plugin);
                                        return NXLD_PLUGIN_LOAD_MEMORY_ERROR;
                                    }
                                    strcpy_safe(plugin->interfaces[i].params[j].name, strlen(param_name) + 1, param_name);
                                    
                                    plugin->interfaces[i].params[j].type = param_type;
                                    
                                    if (strlen(type_name) > 0) {
                                        plugin->interfaces[i].params[j].type_name = (char*)malloc(strlen(type_name) + 1);
                                        if (plugin->interfaces[i].params[j].type_name == NULL) {
                                            close_dynamic_library(handle);
                                            nxld_plugin_free(plugin);
                                            return NXLD_PLUGIN_LOAD_MEMORY_ERROR;
                                        }
                                        strcpy_safe(plugin->interfaces[i].params[j].type_name, strlen(type_name) + 1, type_name);
                                    } else {
                                        plugin->interfaces[i].params[j].type_name = NULL;
                                    }
                                } else {
                                    plugin->interfaces[i].params[j].name = NULL;
                                    plugin->interfaces[i].params[j].type = NXLD_PARAM_TYPE_UNKNOWN;
                                    plugin->interfaces[i].params[j].type_name = NULL;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    
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
            
            if (!read_uid_from_nxp(nxp_path, plugin->uid, sizeof(plugin->uid))) {
                if (!generate_uid(plugin->uid, sizeof(plugin->uid))) {
                    close_dynamic_library(handle);
                    nxld_plugin_free(plugin);
                    return NXLD_PLUGIN_LOAD_MEMORY_ERROR;
                }
            }
            
            nxld_plugin_generate_metadata_file(plugin, nxp_path);
        } else {
            if (!generate_uid(plugin->uid, sizeof(plugin->uid))) {
                close_dynamic_library(handle);
                nxld_plugin_free(plugin);
                return NXLD_PLUGIN_LOAD_MEMORY_ERROR;
            }
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
 * @param type 参数类型枚举值 / Parameter type enumeration value / Parametertyp-Aufzählungswert
 * @return 参数类型名称字符串指针 / Pointer to parameter type name string / Zeiger auf Parametertypnamen-Zeichenfolge
 * @details 将参数类型枚举值转换为对应的字符串名称 / Convert parameter type enumeration value to corresponding string name / Parametertyp-Aufzählungswert in entsprechende Zeichenfolgennamen umwandeln
 */
static const char* get_param_type_name(nxld_param_type_t type) {
    switch (type) {
        case NXLD_PARAM_TYPE_VOID: return "void";
        case NXLD_PARAM_TYPE_INT32: return "int32_t";
        case NXLD_PARAM_TYPE_INT64: return "int64_t";
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
 * @param count_type 参数数量类型枚举值 / Parameter count type enumeration value / Parameteranzahl-Typ-Aufzählungswert
 * @return 参数数量类型名称字符串指针 / Pointer to parameter count type name string / Zeiger auf Parameteranzahl-Typnamen-Zeichenfolge
 * @details 将参数数量类型枚举值转换为对应的字符串名称 / Convert parameter count type enumeration value to corresponding string name / Parameteranzahl-Typ-Aufzählungswert in entsprechende Zeichenfolgennamen umwandeln
 */
static const char* get_param_count_type_name(nxld_param_count_type_t count_type) {
    switch (count_type) {
        case NXLD_PARAM_COUNT_FIXED: return "fixed";
        case NXLD_PARAM_COUNT_VARIABLE: return "variable";
        case NXLD_PARAM_COUNT_UNKNOWN: return "unknown";
        default: return "unknown";
    }
}

int32_t nxld_plugin_generate_metadata_file(const nxld_plugin_t* plugin, const char* output_path) {
    if (plugin == NULL || output_path == NULL) {
        return -1;
    }
    
    FILE* fp = fopen(output_path, "w");
    if (fp == NULL) {
        return -1;
    }
    
    /**
     * 写入元数据文件头 / Write metadata file header / Metadaten-Dateikopf schreiben
     * 包含文件格式标识和版本信息 / Contains file format identifier and version information / Enthält Dateiformatkennung und Versionsinformationen
     */
    fprintf(fp, "# NXLD Plugin Metadata File / NXLD插件元数据文件\n");
    fprintf(fp, "# Generated automatically / 自动生成\n");
    fprintf(fp, "# Format: NXP v1.0 / 格式: NXP v1.0\n");
    fprintf(fp, "\n");
    
    /**
     * 写入插件基本信息节 / Write plugin basic information section / Plugin-Grundinformationsabschnitt schreiben
     * 包含插件名称、版本、UID和路径 / Contains plugin name, version, UID and path / Enthält Plugin-Name, Version, UID und Pfad
     */
    fprintf(fp, "[Plugin]\n");
    fprintf(fp, "Name=%s\n", plugin->plugin_name != NULL ? plugin->plugin_name : "Unknown");
    fprintf(fp, "Version=%s\n", plugin->plugin_version != NULL ? plugin->plugin_version : "Unknown");
    fprintf(fp, "UID=%s\n", plugin->uid);
    fprintf(fp, "Path=%s\n", plugin->plugin_path != NULL ? plugin->plugin_path : "Unknown");
    fprintf(fp, "\n");
    
    /**
     * 写入接口信息节 / Write interface information section / Schnittstelleninformationsabschnitt schreiben
     * 包含接口总数和每个接口的详细信息 / Contains total interface count and detailed information of each interface / Enthält Gesamtschnittstellenanzahl und detaillierte Informationen jeder Schnittstelle
     */
    fprintf(fp, "[Interfaces]\n");
    fprintf(fp, "Count=%" PRIzu "\n", plugin->interface_count);
    fprintf(fp, "\n");
    
    for (size_t i = 0; i < plugin->interface_count; i++) {
        const nxld_interface_info_t* iface = &plugin->interfaces[i];
        
        fprintf(fp, "[Interface_%" PRIzu "]\n", i);
        fprintf(fp, "Name=%s\n", iface->name != NULL ? iface->name : "Unknown");
        fprintf(fp, "Description=%s\n", iface->description != NULL ? iface->description : "");
        fprintf(fp, "Version=%s\n", iface->version != NULL ? iface->version : "Unknown");
        
        /**
         * 写入接口参数数量信息 / Write interface parameter count information / Schnittstellenparameteranzahl-Informationen schreiben
         * 包括参数数量类型、最小和最大参数数量 / Includes parameter count type, minimum and maximum parameter count / Enthält Parameteranzahl-Typ, Mindest- und Maximalparameteranzahl
         */
        fprintf(fp, "ParamCountType=%s\n", get_param_count_type_name(iface->param_count_type));
        fprintf(fp, "MinParamCount=%d\n", iface->min_param_count);
        if (iface->max_param_count >= 0) {
            fprintf(fp, "MaxParamCount=%d\n", iface->max_param_count);
        } else {
            fprintf(fp, "MaxParamCount=unlimited\n");
        }
        fprintf(fp, "FixedParamCount=%" PRIzu "\n", iface->param_count);
        
        /**
         * 写入接口参数详细信息 / Write interface parameter detailed information / Detaillierte Schnittstellenparameter-Informationen schreiben
         * 包括每个参数的名称、类型和类型名称 / Includes name, type and type name of each parameter / Enthält Name, Typ und Typname jedes Parameters
         */
        if (iface->param_count > 0 && iface->params != NULL) {
            fprintf(fp, "Params=\n");
            for (size_t j = 0; j < iface->param_count; j++) {
                const nxld_param_info_t* param = &iface->params[j];
                fprintf(fp, "  [%" PRIzu "]\n", j);
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
    return 0;
}

