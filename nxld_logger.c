/**
 * @file nxld_logger.c
 * @brief NXLD配置文件解析器日志系统实现 / NXLD Configuration File Parser Logging System Implementation / NXLD-Konfigurationsdatei-Parser-Protokollierungssystem-Implementierung
 * @details 实现日志系统插件化包装器，保持与原有接口兼容 / Implements pluginized logging system wrapper, maintains compatibility with original interface / Implementiert pluginisiertes Protokollierungssystem-Wrapper, behält Kompatibilität mit ursprünglicher Schnittstelle
 */

#include "nxld_logger.h"
#include "logger_plugin_interface.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <dlfcn.h>
#endif

static void* g_logger_plugin_handle = NULL;
static int (*g_logger_plugin_init_func)(const char*) = NULL;
static void (*g_logger_plugin_close_func)(void) = NULL;
static void (*g_logger_plugin_write_func)(logger_level_t, const char*, va_list) = NULL;
static int g_logger_plugin_loaded = 0;

/**
 * @brief 文件日志实现 / File logger implementation / Datei-Logger-Implementierung
 * @details 当日志插件未加载时使用的文件日志实现 / File logger implementation used when logger plugin is not loaded / Datei-Logger-Implementierung, die verwendet wird, wenn Logger-Plugin nicht geladen ist
 */
static FILE* g_fallback_log_file = NULL;

static void fallback_log_write(const char* level, const char* format, va_list args) {
    if (g_fallback_log_file == NULL) {
        return;
    }
    
    time_t now;
    time(&now);
    struct tm* timeinfo = localtime(&now);
    char time_str[64];
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", timeinfo);
    
    fprintf(g_fallback_log_file, "[%s] [%s] ", time_str, level);
    vfprintf(g_fallback_log_file, format, args);
    fprintf(g_fallback_log_file, "\n");
    fflush(g_fallback_log_file);
}

/**
 * @brief 加载日志插件 / Load logger plugin / Logger-Plugin laden
 * @param plugin_path 插件路径 / Plugin path / Plugin-Pfad
 * @return 成功返回0，失败返回-1 / Returns 0 on success, -1 on failure / Gibt 0 bei Erfolg zurück, -1 bei Fehler
 * @details 动态加载日志插件库并获取函数指针 / Dynamically loads logger plugin library and obtains function pointers / Lädt Logger-Plugin-Bibliothek dynamisch und erhält Funktionszeiger
 */
static int load_logger_plugin(const char* plugin_path) {
    if (g_logger_plugin_loaded) {
        return 0;
    }
    
    if (plugin_path == NULL || strlen(plugin_path) == 0) {
        return -1;
    }
    
    g_logger_plugin_handle = NULL;
#ifdef _WIN32
    g_logger_plugin_handle = (void*)LoadLibraryA(plugin_path);
#else
    g_logger_plugin_handle = dlopen(plugin_path, RTLD_LAZY);
#endif
    
    if (g_logger_plugin_handle == NULL) {
        return -1;
    }
    
#ifdef _WIN32
    g_logger_plugin_init_func = (int (*)(const char*))GetProcAddress((HMODULE)g_logger_plugin_handle, "logger_plugin_init");
    g_logger_plugin_close_func = (void (*)(void))GetProcAddress((HMODULE)g_logger_plugin_handle, "logger_plugin_close");
    g_logger_plugin_write_func = (void (*)(logger_level_t, const char*, va_list))GetProcAddress((HMODULE)g_logger_plugin_handle, "logger_plugin_write");
#else
    g_logger_plugin_init_func = (int (*)(const char*))dlsym(g_logger_plugin_handle, "logger_plugin_init");
    g_logger_plugin_close_func = (void (*)(void))dlsym(g_logger_plugin_handle, "logger_plugin_close");
    g_logger_plugin_write_func = (void (*)(logger_level_t, const char*, va_list))dlsym(g_logger_plugin_handle, "logger_plugin_write");
#endif
    
    if (g_logger_plugin_init_func == NULL || g_logger_plugin_close_func == NULL || g_logger_plugin_write_func == NULL) {
#ifdef _WIN32
        FreeLibrary((HMODULE)g_logger_plugin_handle);
#else
        dlclose(g_logger_plugin_handle);
#endif
        g_logger_plugin_handle = NULL;
        return -1;
    }
    
    g_logger_plugin_loaded = 1;
    return 0;
}

/**
 * @brief 卸载日志插件 / Unload logger plugin / Logger-Plugin entladen
 * @details 关闭插件并释放动态库句柄 / Closes plugin and releases dynamic library handle / Schließt Plugin und gibt dynamisches Bibliothekshandle frei
 */
static void unload_logger_plugin(void) {
    if (g_logger_plugin_handle != NULL) {
        if (g_logger_plugin_close_func != NULL) {
            g_logger_plugin_close_func();
        }
#ifdef _WIN32
        FreeLibrary((HMODULE)g_logger_plugin_handle);
#else
        dlclose(g_logger_plugin_handle);
#endif
        g_logger_plugin_handle = NULL;
    }
    
    g_logger_plugin_init_func = NULL;
    g_logger_plugin_close_func = NULL;
    g_logger_plugin_write_func = NULL;
    g_logger_plugin_loaded = 0;
}

int nxld_logger_init(const char* log_file_path) {
    const char* actual_log_path = log_file_path != NULL ? log_file_path : "nxld_parser.log";
    
    g_logger_plugin_loaded = 0;
    if (g_fallback_log_file != NULL) {
        fclose(g_fallback_log_file);
    }
    
    g_fallback_log_file = fopen(actual_log_path, "a");
    if (g_fallback_log_file == NULL) {
        return -1;
    }
    
    return 0;
}

void nxld_logger_close(void) {
    if (g_logger_plugin_loaded && g_logger_plugin_close_func != NULL) {
        unload_logger_plugin();
    } else {
        if (g_fallback_log_file != NULL) {
            fclose(g_fallback_log_file);
            g_fallback_log_file = NULL;
        }
    }
}

void nxld_log_error(const char* format, ...) {
    va_list args;
    va_start(args, format);
    if (g_logger_plugin_loaded && g_logger_plugin_write_func != NULL) {
        g_logger_plugin_write_func(LOGGER_LEVEL_ERROR, format, args);
    } else {
        fallback_log_write("ERROR", format, args);
    }
    va_end(args);
}

void nxld_log_warning(const char* format, ...) {
    va_list args;
    va_start(args, format);
    if (g_logger_plugin_loaded && g_logger_plugin_write_func != NULL) {
        g_logger_plugin_write_func(LOGGER_LEVEL_WARNING, format, args);
    } else {
        fallback_log_write("WARNING", format, args);
    }
    va_end(args);
}

void nxld_log_info(const char* format, ...) {
    va_list args;
    va_start(args, format);
    if (g_logger_plugin_loaded && g_logger_plugin_write_func != NULL) {
        g_logger_plugin_write_func(LOGGER_LEVEL_INFO, format, args);
    } else {
        fallback_log_write("INFO", format, args);
    }
    va_end(args);
}

