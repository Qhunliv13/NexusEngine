/**
 * @file logger_plugin_interface.h
 * @brief NXLD日志插件接口定义 / NXLD Logger Plugin Interface Definition / NXLD-Logger-Plugin-Schnittstellendefinition
 * @details 定义日志插件需要实现的函数接口 / Defines function interfaces that logger plugins need to implement / Definiert Funktionsschnittstellen, die Logger-Plugins implementieren müssen
 */

#ifndef LOGGER_PLUGIN_INTERFACE_H
#define LOGGER_PLUGIN_INTERFACE_H

#include <stdarg.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _WIN32
#define LOGGER_PLUGIN_EXPORT __declspec(dllexport)
#else
#define LOGGER_PLUGIN_EXPORT __attribute__((visibility("default")))
#endif

/**
 * @brief 日志级别枚举 / Log level enumeration / Protokollierungsebene-Aufzählung
 */
typedef enum {
    LOGGER_LEVEL_ERROR = 0,                 /**< 错误级别 / Error level / Fehlerebene */
    LOGGER_LEVEL_WARNING,                   /**< 警告级别 / Warning level / Warnungsebene */
    LOGGER_LEVEL_INFO                       /**< 信息级别 / Info level / Informationsebene */
} logger_level_t;

/**
 * @brief 初始化日志插件 / Initialize logger plugin / Logger-Plugin initialisieren
 * @param config 配置字符串（可选，由插件自行解析） / Configuration string (optional, parsed by plugin) / Konfigurationszeichenfolge (optional, vom Plugin geparst)
 * @return 成功返回0，失败返回非0 / Returns 0 on success, non-zero on failure / Gibt 0 bei Erfolg zurück, ungleich 0 bei Fehler
 */
LOGGER_PLUGIN_EXPORT int logger_plugin_init(const char* config);

/**
 * @brief 关闭日志插件 / Close logger plugin / Logger-Plugin schließen
 */
LOGGER_PLUGIN_EXPORT void logger_plugin_close(void);

/**
 * @brief 写入日志 / Write log / Protokoll schreiben
 * @param level 日志级别 / Log level / Protokollierungsebene
 * @param format 格式化字符串 / Format string / Formatzeichenfolge
 * @param args 可变参数列表 / Variable argument list / Variable Argumentenliste
 */
LOGGER_PLUGIN_EXPORT void logger_plugin_write(logger_level_t level, const char* format, va_list args);

#ifdef __cplusplus
}
#endif

#endif /* LOGGER_PLUGIN_INTERFACE_H */

