/**
 * @file nxld_plugin.h
 * @brief NXLD插件加载和管理接口 / NXLD Plugin Loading and Management Interface / NXLD-Plugin-Lade- und Verwaltungsschnittstelle
 * @details 提供动态库加载、插件元数据管理和UID分配功能 / Provides dynamic library loading, plugin metadata management and UID allocation / Bietet dynamische Bibliotheksladung, Plugin-Metadatenverwaltung und UID-Zuweisung
 */

#ifndef NXLD_PLUGIN_H
#define NXLD_PLUGIN_H

#include <stddef.h>
#include "nxld_plugin_interface.h"

/**
 * @brief 参数信息结构体 / Parameter information structure / Parameterinformationsstruktur
 */
typedef struct {
    char* name;                             /**< 参数名称 / Parameter name / Parametername */
    nxld_param_type_t type;                 /**< 参数类型 / Parameter type / Parametertyp */
    char* type_name;                        /**< 类型名称（自定义类型时使用） / Type name (for custom types) / Typname (für benutzerdefinierte Typen) */
} nxld_param_info_t;

/**
 * @brief 插件接口信息结构体 / Plugin interface information structure / Plugin-Schnittstelleninformationsstruktur
 */
typedef struct {
    char* name;                             /**< 接口名称 / Interface name / Schnittstellenname */
    char* description;                      /**< 接口功能描述 / Interface function description / Schnittstellenfunktionsbeschreibung */
    char* version;                          /**< 接口版本 / Interface version / Schnittstellenversion */
    nxld_param_count_type_t param_count_type; /**< 参数数量类型 / Parameter count type / Parameteranzahl-Typ */
    int min_param_count;                    /**< 最小参数数量 / Minimum parameter count / Mindestparameteranzahl */
    int max_param_count;                    /**< 最大参数数量（-1表示无限制） / Maximum parameter count (-1 for unlimited) / Maximalparameteranzahl (-1 für unbegrenzt) */
    nxld_param_info_t* params;               /**< 参数信息数组 / Parameter information array / Parameterinformationsarray */
    size_t param_count;                     /**< 参数数量（固定参数的数量） / Parameter count (count of fixed parameters) / Parameteranzahl (Anzahl der festen Parameter) */
} nxld_interface_info_t;

/**
 * @brief 插件元数据结构体 / Plugin metadata structure / Plugin-Metadatenstruktur
 */
typedef struct {
    char uid[65];                           /**< 唯一标识符（64位随机字符串） / Unique identifier (64-bit random string) / Eindeutiger Bezeichner (64-Bit-Zufallszeichenfolge) */
    char* plugin_name;                      /**< 插件名称 / Plugin name / Plugin-Name */
    char* plugin_version;                  /**< 插件版本 / Plugin version / Plugin-Version */
    char* plugin_path;                     /**< 插件文件路径 / Plugin file path / Plugin-Dateipfad */
    nxld_interface_info_t* interfaces;     /**< 接口信息数组 / Interface information array / Schnittstelleninformationsarray */
    size_t interface_count;                 /**< 接口数量 / Number of interfaces / Anzahl der Schnittstellen */
    void* handle;                           /**< 动态库句柄 / Dynamic library handle / Dynamisches Bibliothekshandle */
} nxld_plugin_t;

/**
 * @brief 插件加载结果枚举 / Plugin load result enumeration / Plugin-Ladeergebnis-Aufzählung
 */
typedef enum {
    NXLD_PLUGIN_LOAD_SUCCESS = 0,          /**< 加载成功 / Load successful / Laden erfolgreich */
    NXLD_PLUGIN_LOAD_FILE_ERROR,           /**< 文件错误 / File error / Dateifehler */
    NXLD_PLUGIN_LOAD_SYMBOL_ERROR,         /**< 符号未找到 / Symbol not found / Symbol nicht gefunden */
    NXLD_PLUGIN_LOAD_METADATA_ERROR,       /**< 元数据错误 / Metadata error / Metadatenfehler */
    NXLD_PLUGIN_LOAD_MEMORY_ERROR          /**< 内存分配错误 / Memory allocation error / Speicherzuweisungsfehler */
} nxld_plugin_load_result_t;

/**
 * @brief 插件导出函数类型定义 / Plugin export function type definition / Plugin-Exportfunktionstypdefinition
 */
typedef int (*nxld_plugin_get_name_func)(char* name, size_t name_size);
typedef int (*nxld_plugin_get_version_func)(char* version, size_t version_size);
typedef int (*nxld_plugin_get_interface_count_func)(size_t* count);
typedef int (*nxld_plugin_get_interface_info_func)(size_t index, char* name, size_t name_size, 
                                                     char* description, size_t desc_size, 
                                                     char* version, size_t version_size);
typedef int (*nxld_plugin_get_interface_param_count_func)(size_t index,
                                                           nxld_param_count_type_t* count_type,
                                                           int* min_count, int* max_count);
typedef int (*nxld_plugin_get_interface_param_info_func)(size_t index, int param_index,
                                                          char* param_name, size_t name_size,
                                                          nxld_param_type_t* param_type,
                                                          char* type_name, size_t type_name_size);

/**
 * @brief 加载插件 / Load plugin / Plugin laden
 * @param plugin_path 插件文件路径 / Plugin file path / Plugin-Dateipfad
 * @param plugin 输出插件结构体指针 / Output plugin structure pointer / Ausgabe-Plugin-Strukturzeiger
 * @return 加载结果 / Load result / Ladeergebnis
 */
nxld_plugin_load_result_t nxld_plugin_load(const char* plugin_path, nxld_plugin_t* plugin);

/**
 * @brief 卸载插件 / Unload plugin / Plugin entladen
 * @param plugin 插件结构体指针 / Plugin structure pointer / Plugin-Strukturzeiger
 */
void nxld_plugin_unload(nxld_plugin_t* plugin);

/**
 * @brief 释放插件结构体内存 / Free plugin structure memory / Plugin-Struktur-Speicher freigeben
 * @param plugin 插件结构体指针 / Plugin structure pointer / Plugin-Strukturzeiger
 */
void nxld_plugin_free(nxld_plugin_t* plugin);

/**
 * @brief 获取插件加载结果错误信息 / Get plugin load result error message / Plugin-Ladeergebnis-Fehlermeldung abrufen
 * @param result 加载结果 / Load result / Ladeergebnis
 * @return 错误信息字符串 / Error message string / Fehlermeldungszeichenfolge
 */
const char* nxld_plugin_get_error_message(nxld_plugin_load_result_t result);

/**
 * @brief 生成插件元数据文件 / Generate plugin metadata file / Plugin-Metadaten-Datei generieren
 * @param plugin 插件结构体指针 / Plugin structure pointer / Plugin-Strukturzeiger
 * @param output_path 输出文件路径（.nxp文件） / Output file path (.nxp file) / Ausgabedateipfad (.nxp-Datei)
 * @return 成功返回0，失败返回非0 / Returns 0 on success, non-zero on failure / Gibt 0 bei Erfolg zurück, ungleich 0 bei Fehler
 */
int nxld_plugin_generate_metadata_file(const nxld_plugin_t* plugin, const char* output_path);

#endif /* NXLD_PLUGIN_H */



