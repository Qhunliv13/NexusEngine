/**
 * @file nxld_logger.h
 * @brief NXLD配置文件解析器日志系统接口定义 / NXLD Configuration File Parser Logging System Interface Definition / NXLD-Konfigurationsdatei-Parser-Protokollierungssystem-Schnittstellendefinition
 * @details 定义文件读取和解析错误的日志记录接口（插件化实现） / Defines logging interface for file reading and parsing errors (pluginized implementation) / Definiert Protokollierungsschnittstelle für Dateilese- und Parsing-Fehler (pluginisierte Implementierung)
 */

#ifndef NXLD_LOGGER_H
#define NXLD_LOGGER_H

#include <stdio.h>
#include <stdarg.h>

/**
 * @brief 初始化日志系统 / Initialize logging system / Protokollierungssystem initialisieren
 * @param log_file_path 日志文件路径 / Log file path / Protokollierungsdateipfad
 * @return 成功返回0，失败返回-1 / Returns 0 on success, -1 on failure / Gibt 0 bei Erfolg zurück, -1 bei Fehler
 */
int nxld_logger_init(const char* log_file_path);

/**
 * @brief 关闭日志系统 / Close logging system / Protokollierungssystem schließen
 */
void nxld_logger_close(void);

/**
 * @brief 写入错误日志 / Write error log / Fehlerprotokoll schreiben
 * @param format 格式化字符串 / Format string / Formatzeichenfolge
 * @param ... 可变参数 / Variable arguments / Variable Argumente
 */
void nxld_log_error(const char* format, ...);

/**
 * @brief 写入警告日志 / Write warning log / Warnprotokoll schreiben
 * @param format 格式化字符串 / Format string / Formatzeichenfolge
 * @param ... 可变参数 / Variable arguments / Variable Argumente
 */
void nxld_log_warning(const char* format, ...);

/**
 * @brief 写入信息日志 / Write info log / Informationsprotokoll schreiben
 * @param format 格式化字符串 / Format string / Formatzeichenfolge
 * @param ... 可变参数 / Variable arguments / Variable Argumente
 */
void nxld_log_info(const char* format, ...);

#endif /* NXLD_LOGGER_H */

