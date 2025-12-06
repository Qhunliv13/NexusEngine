/**
 * @file nxld_plugin_interface.h
 * @brief NXLD插件接口定义 / NXLD Plugin Interface Definition / NXLD-Plugin-Schnittstellendefinition
 * @details 插件必须导出的函数接口定义 / Required exported function interface definitions for plugins / Erforderliche exportierte Funktionsschnittstellendefinitionen für Plugins
 */

#ifndef NXLD_PLUGIN_INTERFACE_H
#define NXLD_PLUGIN_INTERFACE_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _WIN32
#define NXLD_PLUGIN_EXPORT __declspec(dllexport)
#else
#define NXLD_PLUGIN_EXPORT __attribute__((visibility("default")))
#endif

/**
 * @brief 获取插件名称 / Get plugin name / Plugin-Namen abrufen
 * @param name 输出名称缓冲区 / Output name buffer / Ausgabe-Namen-Puffer
 * @param name_size 缓冲区大小 / Buffer size / Puffergröße
 * @return 成功返回0，失败返回非0 / Returns 0 on success, non-zero on failure / Gibt 0 bei Erfolg zurück, ungleich 0 bei Fehler
 */
NXLD_PLUGIN_EXPORT int nxld_plugin_get_name(char* name, size_t name_size);

/**
 * @brief 获取插件版本 / Get plugin version / Plugin-Version abrufen
 * @param version 输出版本缓冲区 / Output version buffer / Ausgabe-Versions-Puffer
 * @param version_size 缓冲区大小 / Buffer size / Puffergröße
 * @return 成功返回0，失败返回非0 / Returns 0 on success, non-zero on failure / Gibt 0 bei Erfolg zurück, ungleich 0 bei Fehler
 */
NXLD_PLUGIN_EXPORT int nxld_plugin_get_version(char* version, size_t version_size);

/**
 * @brief 获取接口数量 / Get interface count / Schnittstellenanzahl abrufen
 * @param count 输出接口数量指针 / Output interface count pointer / Ausgabe-Schnittstellenanzahl-Zeiger
 * @return 成功返回0，失败返回非0 / Returns 0 on success, non-zero on failure / Gibt 0 bei Erfolg zurück, ungleich 0 bei Fehler
 */
NXLD_PLUGIN_EXPORT int nxld_plugin_get_interface_count(size_t* count);

/**
 * @brief 获取接口信息 / Get interface information / Schnittstelleninformationen abrufen
 * @param index 接口索引 / Interface index / Schnittstellenindex
 * @param name 输出接口名称缓冲区 / Output interface name buffer / Ausgabe-Schnittstellennamen-Puffer
 * @param name_size 名称缓冲区大小 / Name buffer size / Namenspuffergröße
 * @param description 输出接口描述缓冲区 / Output interface description buffer / Ausgabe-Schnittstellenbeschreibungs-Puffer
 * @param desc_size 描述缓冲区大小 / Description buffer size / Beschreibungspuffergröße
 * @param version 输出接口版本缓冲区 / Output interface version buffer / Ausgabe-Schnittstellenversions-Puffer
 * @param version_size 版本缓冲区大小 / Version buffer size / Versionspuffergröße
 * @return 成功返回0，失败返回非0 / Returns 0 on success, non-zero on failure / Gibt 0 bei Erfolg zurück, ungleich 0 bei Fehler
 */
NXLD_PLUGIN_EXPORT int nxld_plugin_get_interface_info(size_t index, 
                                                        char* name, size_t name_size,
                                                        char* description, size_t desc_size,
                                                        char* version, size_t version_size);

/**
 * @brief 参数类型枚举 / Parameter type enumeration / Parametertyp-Aufzählung
 */
typedef enum {
    NXLD_PARAM_TYPE_VOID = 0,              /**< void类型 / void type / void-Typ */
    NXLD_PARAM_TYPE_INT,                   /**< int类型 / int type / int-Typ */
    NXLD_PARAM_TYPE_LONG,                  /**< long类型 / long type / long-Typ */
    NXLD_PARAM_TYPE_FLOAT,                 /**< float类型 / float type / float-Typ */
    NXLD_PARAM_TYPE_DOUBLE,                /**< double类型 / double type / double-Typ */
    NXLD_PARAM_TYPE_CHAR,                  /**< char类型 / char type / char-Typ */
    NXLD_PARAM_TYPE_POINTER,               /**< 指针类型 / pointer type / Zeiger-Typ */
    NXLD_PARAM_TYPE_STRING,                /**< 字符串类型 / string type / Zeichenfolgen-Typ */
    NXLD_PARAM_TYPE_VARIADIC,              /**< 可变参数类型 / variadic type / variabler Parametertyp */
    NXLD_PARAM_TYPE_ANY,                   /**< 任意类型 / any type / beliebiger Typ */
    NXLD_PARAM_TYPE_UNKNOWN                /**< 未知类型 / unknown type / unbekannter Typ */
} nxld_param_type_t;

/**
 * @brief 参数数量类型枚举 / Parameter count type enumeration / Parameteranzahl-Typ-Aufzählung
 */
typedef enum {
    NXLD_PARAM_COUNT_FIXED = 0,            /**< 固定数量 / fixed count / feste Anzahl */
    NXLD_PARAM_COUNT_VARIABLE,             /**< 可变数量 / variable count / variable Anzahl */
    NXLD_PARAM_COUNT_UNKNOWN               /**< 未知数量 / unknown count / unbekannte Anzahl */
} nxld_param_count_type_t;

/**
 * @brief 获取接口参数数量信息 / Get interface parameter count information / Schnittstellenparameteranzahl-Informationen abrufen
 * @param index 接口索引 / Interface index / Schnittstellenindex
 * @param count_type 输出参数数量类型指针 / Output parameter count type pointer / Ausgabe-Parameteranzahl-Typ-Zeiger
 * @param min_count 输出最小参数数量指针（固定数量时等于实际数量） / Output minimum parameter count pointer (equals actual count when fixed) / Ausgabe-Mindestparameteranzahl-Zeiger (gleich tatsächlicher Anzahl bei fester Anzahl)
 * @param max_count 输出最大参数数量指针（固定数量时等于实际数量，可变数量时为-1） / Output maximum parameter count pointer (equals actual count when fixed, -1 when variable) / Ausgabe-Maximalparameteranzahl-Zeiger (gleich tatsächlicher Anzahl bei fester Anzahl, -1 bei variabler Anzahl)
 * @return 成功返回0，失败返回非0 / Returns 0 on success, non-zero on failure / Gibt 0 bei Erfolg zurück, ungleich 0 bei Fehler
 */
NXLD_PLUGIN_EXPORT int nxld_plugin_get_interface_param_count(size_t index,
                                                               nxld_param_count_type_t* count_type,
                                                               int* min_count, int* max_count);

/**
 * @brief 获取接口参数信息 / Get interface parameter information / Schnittstellenparameter-Informationen abrufen
 * @param index 接口索引 / Interface index / Schnittstellenindex
 * @param param_index 参数索引（从0开始，如果参数数量可变，param_index为-1表示获取可变参数信息） / Parameter index (starting from 0, -1 for variadic parameter info when count is variable) / Parameterindex (ab 0, -1 für variablen Parameterinfo bei variabler Anzahl)
 * @param param_name 输出参数名称缓冲区 / Output parameter name buffer / Ausgabe-Parameternamen-Puffer
 * @param name_size 名称缓冲区大小 / Name buffer size / Namenspuffergröße
 * @param param_type 输出参数类型指针 / Output parameter type pointer / Ausgabe-Parametertyp-Zeiger
 * @param type_name 输出类型名称缓冲区（可选，用于自定义类型） / Output type name buffer (optional, for custom types) / Ausgabe-Typnamen-Puffer (optional, für benutzerdefinierte Typen)
 * @param type_name_size 类型名称缓冲区大小 / Type name buffer size / Typnamenpuffergröße
 * @return 成功返回0，失败返回非0 / Returns 0 on success, non-zero on failure / Gibt 0 bei Erfolg zurück, ungleich 0 bei Fehler
 */
NXLD_PLUGIN_EXPORT int nxld_plugin_get_interface_param_info(size_t index, int param_index,
                                                              char* param_name, size_t name_size,
                                                              nxld_param_type_t* param_type,
                                                              char* type_name, size_t type_name_size);

#ifdef __cplusplus
}
#endif

#endif /* NXLD_PLUGIN_INTERFACE_H */

