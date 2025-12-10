# SCons构建文件 / SCons Build File / SCons-Builddatei
# NXLD配置文件解析器构建配置 / NXLD config file parser build configuration / NXLD-Konfigurationsdatei-Parser-Build-Konfiguration

import os

env = Environment()

# 编译器设置 / Compiler settings / Compiler-Einstellungen
if os.name == 'nt':
    env['CC'] = 'cl'
    env['CXX'] = 'cl'
    # /W4: 警告级别4 / Warning level 4 / Warnstufe 4
    # /O2: 速度优化 / Speed optimization / Geschwindigkeitsoptimierung
    # /utf-8: UTF-8编码支持 / UTF-8 encoding support / UTF-8-Kodierungsunterstützung
    env['CCFLAGS'] = ['/W4', '/O2', '/utf-8']
    # /OPT:REF: 移除未引用的函数和数据 / Remove unreferenced functions and data / Nicht referenzierte Funktionen und Daten entfernen
    # /OPT:ICF: 合并相同的函数 / Merge identical functions / Identische Funktionen zusammenführen
    env['LINKFLAGS'] = ['/OPT:REF', '/OPT:ICF']
else:
    env['CC'] = 'gcc'
    env['CXX'] = 'g++'
    # -Wall: 启用所有警告 / Enable all warnings / Alle Warnungen aktivieren
    # -Wextra: 额外警告 / Extra warnings / Zusätzliche Warnungen
    # -O2: 优化级别2 / Optimization level 2 / Optimierungsstufe 2
    # -std=c99: C99标准 / C99 standard / C99-Standard
    # -ffunction-sections: 每个函数放在独立段 / Place each function in separate section / Jede Funktion in separaten Abschnitt platzieren
    # -fdata-sections: 每个数据放在独立段 / Place each data in separate section / Jede Daten in separaten Abschnitt platzieren
    env['CCFLAGS'] = ['-Wall', '-Wextra', '-O2', '-std=c99', '-ffunction-sections', '-fdata-sections']
    # -Wl,--gc-sections: 链接时移除未使用的段 / Remove unused sections during linking / Nicht verwendete Abschnitte beim Verlinken entfernen
    env['LINKFLAGS'] = ['-Wl,--gc-sections']

# 主程序源文件 / Main program source files / Hauptprogramm-Quelldateien
main_sources = ['nx_main.c', 'nxld_parser.c', 'nxld_plugin.c', 'nxld_plugin_loader.c', 'nxld_utils.c']

# 创建主程序 / Create main program / Hauptprogramm erstellen
# Windows使用kernel32和advapi32（用于CryptGenRandom等加密函数），Unix系统（Linux/macOS）使用dl库 / Windows uses kernel32 and advapi32 (for CryptGenRandom and other cryptographic functions), Unix systems (Linux/macOS) use dl library / Windows verwendet kernel32 und advapi32 (für CryptGenRandom und andere kryptografische Funktionen), Unix-Systeme (Linux/macOS) verwenden dl-Bibliothek
if os.name == 'nt':
    env.Append(LIBS=['kernel32', 'advapi32'])
else:
    env.Append(LIBS=['dl'])
main_program = env.Program('nx_main', main_sources)

# 默认目标 / Default target / Standardziel
Default(main_program)

