/**
 * @file nxld_plugin_loader.h
 * @brief NXLD插件批量加载器 / NXLD Plugin Batch Loader / NXLD-Plugin-Stapellader
 * @details 根据配置文件顺序批量加载插件 / Batch load plugins according to config file order / Plugins gemäß Konfigurationsdatei-Reihenfolge stapelweise laden
 */

#ifndef NXLD_PLUGIN_LOADER_H
#define NXLD_PLUGIN_LOADER_H

#include "nxld_parser.h"
#include "nxld_plugin.h"

/**
 * @brief 按配置顺序加载所有插件 / Load all plugins in config order / Alle Plugins in Konfigurationsreihenfolge laden
 * @param config 配置结构体指针 / Config structure pointer / Konfigurationsstruktur-Zeiger
 * @param config_file_path 配置文件路径 / Config file path / Konfigurationsdateipfad
 * @param plugins 输出插件数组指针 / Output plugin array pointer / Ausgabe-Plugin-Array-Zeiger
 * @param loaded_count 输出成功加载的插件数量 / Output count of successfully loaded plugins / Ausgabe-Anzahl erfolgreich geladener Plugins
 * @return 成功返回0，失败返回-1 / Returns 0 on success, -1 on failure / Gibt 0 bei Erfolg zurück, -1 bei Fehler
 */
int nxld_load_plugins_from_config(const nxld_config_t* config, const char* config_file_path, 
                                   nxld_plugin_t** plugins, size_t* loaded_count);

/**
 * @brief 释放插件数组内存 / Free plugin array memory / Plugin-Array-Speicher freigeben
 * @param plugins 插件数组指针 / Plugin array pointer / Plugin-Array-Zeiger
 * @param count 插件数量 / Plugin count / Plugin-Anzahl
 */
void nxld_free_plugins(nxld_plugin_t* plugins, size_t count);

#endif /* NXLD_PLUGIN_LOADER_H */

