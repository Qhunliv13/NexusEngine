/**
 * @file nxld_utils.h
 * @brief NXLD工具函数接口定义 / NXLD Utility Functions Interface Definition / NXLD-Hilfsfunktionen-Schnittstellendefinition
 * @details 提供路径处理等公共工具函数 / Provides common utility functions like path handling / Bietet gemeinsame Hilfsfunktionen wie Pfadbehandlung
 */

#ifndef NXLD_UTILS_H
#define NXLD_UTILS_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief 获取配置文件所在目录路径 / Get config file directory path / Konfigurationsdateiverzeichnispfad abrufen
 * @param file_path 配置文件路径 / Config file path / Konfigurationsdateipfad
 * @param dir_path 输出目录路径缓冲区 / Output directory path buffer / Ausgabe-Verzeichnispfad-Puffer
 * @param dir_path_size 缓冲区大小 / Buffer size / Puffergröße
 * @return 成功返回1，失败返回0 / Returns 1 on success, 0 on failure / Gibt 1 bei Erfolg zurück, 0 bei Fehler
 */
int32_t nxld_utils_get_config_dir(const char* file_path, char* dir_path, size_t dir_path_size);

/**
 * @brief 构建插件文件的完整路径 / Build full path for plugin file / Vollständigen Pfad für Plugin-Datei erstellen
 * @param config_dir 配置文件目录 / Config file directory / Konfigurationsdateiverzeichnis
 * @param plugin_path 插件相对路径 / Plugin relative path / Plugin-Relativpfad
 * @param full_path 输出完整路径缓冲区 / Output full path buffer / Ausgabe-Vollpfad-Puffer
 * @param full_path_size 缓冲区大小 / Buffer size / Puffergröße
 * @return 成功返回1，失败返回0 / Returns 1 on success, 0 on failure / Gibt 1 bei Erfolg zurück, 0 bei Fehler
 */
int32_t nxld_utils_build_plugin_full_path(const char* config_dir, const char* plugin_path, char* full_path, size_t full_path_size);

/**
 * @brief 查找路径中最后一个路径分隔符的位置 / Find last path separator in path / Letzten Pfadtrennzeichen in Pfad finden
 * @param file_path 文件路径 / File path / Dateipfad
 * @return 最后一个路径分隔符的指针，未找到返回NULL / Pointer to last path separator, NULL if not found / Zeiger auf letztes Pfadtrennzeichen, NULL wenn nicht gefunden
 * @details 支持Windows的反斜杠和Unix的正斜杠 / Supports Windows backslash and Unix forward slash / Unterstützt Windows-Backslash und Unix-Forward-Slash
 */
const char* nxld_utils_find_last_path_separator(const char* file_path);

#ifdef __cplusplus
}
#endif

#endif /* NXLD_UTILS_H */

