/**
 * @file nxld_parser.h
 * @brief NXLD配置文件解析器接口定义 / NXLD Configuration File Parser Interface Definition / NXLD-Konfigurationsdatei-Parser-Schnittstellendefinition
 * @details 定义解析.nxld格式配置文件的接口，支持UTF-8编码 / Defines interface for parsing .nxld format configuration files, supports UTF-8 encoding / Definiert Schnittstelle zum Parsen von .nxld-Format-Konfigurationsdateien, unterstützt UTF-8-Kodierung
 */

#ifndef NXLD_PARSER_H
#define NXLD_PARSER_H

#include <stddef.h>

/**
 * @brief 配置结构体 / Configuration structure / Konfigurationsstruktur
 */
typedef struct {
    int lock_mode;                          /**< 锁模式值：0表示关闭，1表示开启 / Lock mode value: 0 indicates off, 1 indicates on / Sperrmoduswert: 0 bedeutet aus, 1 bedeutet ein */
    int max_root_plugins;                   /**< 最大根插件数 / Maximum root plugins / Maximale Stamm-Plugins */
    char** enabled_root_plugins;            /**< 启用的根插件路径列表 / Enabled root plugin paths / Aktivierte Stamm-Plugin-Pfade */
    size_t enabled_root_plugins_count;      /**< 插件路径数量 / Number of plugin paths / Anzahl der Plugin-Pfade */
    char** virtual_parent_keys;            /**< 子插件路径列表 / Child plugin paths / Untergeordnete Plugin-Pfade */
    char** virtual_parent_values;          /**< 父插件路径列表 / Parent plugin paths / Übergeordnete Plugin-Pfade */
    size_t virtual_parent_count;            /**< 虚拟父级映射数量 / Number of virtual parent mappings / Anzahl der virtuellen Elternzuordnungen */
} nxld_config_t;

/**
 * @brief 解析结果枚举 / Parse result enumeration / Parse-Ergebnis-Aufzählung
 */
typedef enum {
    NXLD_PARSE_SUCCESS = 0,                /**< 解析成功 / Parse successful / Parsen erfolgreich */
    NXLD_PARSE_FILE_ERROR,                 /**< 文件读取错误 / File read error / Dateilesefehler */
    NXLD_PARSE_ENCODING_ERROR,             /**< 编码错误 / Encoding error / Kodierungsfehler */
    NXLD_PARSE_MISSING_SECTION,            /**< 缺少必填配置段 / Missing required section / Fehlender erforderlicher Abschnitt */
    NXLD_PARSE_INVALID_LOCK_MODE,          /**< LockMode值非法 / Invalid LockMode value / Ungültiger LockMode-Wert */
    NXLD_PARSE_INVALID_MAX_PLUGINS,        /**< MaxRootPlugins值非法 / Invalid MaxRootPlugins value / Ungültiger MaxRootPlugins-Wert */
    NXLD_PARSE_EMPTY_PLUGINS,              /**< EnabledRootPlugins为空 / EnabledRootPlugins is empty / EnabledRootPlugins ist leer */
    NXLD_PARSE_PLUGIN_NOT_FOUND,           /**< 插件文件未找到 / Plugin file not found / Plugin-Datei nicht gefunden */
    NXLD_PARSE_PLUGIN_INVALID_FORMAT,      /**< 插件文件格式不符合运行系统要求 / Plugin file format does not match running system / Plugin-Dateiformat entspricht nicht dem laufenden System */
    NXLD_PARSE_VIRTUAL_PARENT_INVALID,     /**< 虚拟父级配置中的插件路径不在EnabledRootPlugins中 / Plugin path in virtual parent config is not in EnabledRootPlugins / Plugin-Pfad in virtueller Elternkonfiguration ist nicht in EnabledRootPlugins */
    NXLD_PARSE_MEMORY_ERROR                /**< 内存分配错误 / Memory allocation error / Speicherzuweisungsfehler */
} nxld_parse_result_t;

/**
 * @brief 解析NXLD配置文件 / Parse NXLD config file / NXLD-Konfigurationsdatei analysieren
 * @param file_path 配置文件路径 / Config file path / Konfigurationsdateipfad
 * @param config 输出配置结构体指针 / Output config structure pointer / Ausgabe-Konfigurationsstruktur-Zeiger
 * @return 解析结果 / Parse result / Parse-Ergebnis
 */
nxld_parse_result_t nxld_parse_file(const char* file_path, nxld_config_t* config);

/**
 * @brief 释放配置结构体内存 / Free config structure memory / Konfigurationsstruktur-Speicher freigeben
 * @param config 配置结构体指针 / Config structure pointer / Konfigurationsstruktur-Zeiger
 */
void nxld_config_free(nxld_config_t* config);

/**
 * @brief 获取解析结果错误信息 / Get parse result error message / Parse-Ergebnis-Fehlermeldung abrufen
 * @param result 解析结果 / Parse result / Parse-Ergebnis
 * @return 错误信息字符串 / Error message string / Fehlermeldungszeichenfolge
 */
const char* nxld_get_error_message(nxld_parse_result_t result);

#endif /* NXLD_PARSER_H */

