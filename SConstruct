# SCons构建文件 / SCons Build File / SCons-Builddatei
# NXLD配置文件解析器构建配置 / NXLD config file parser build configuration / NXLD-Konfigurationsdatei-Parser-Build-Konfiguration

import os

env = Environment()

# 编译器设置 / Compiler settings / Compiler-Einstellungen
if os.name == 'nt':
    env['CC'] = 'cl'
    env['CXX'] = 'cl'
    env['CCFLAGS'] = ['/W4', '/O2', '/utf-8']
    env['LINKFLAGS'] = []
else:
    env['CC'] = 'gcc'
    env['CXX'] = 'g++'
    env['CCFLAGS'] = ['-Wall', '-Wextra', '-O2', '-std=c99']
    env['LINKFLAGS'] = []

# 主程序源文件 / Main program source files / Hauptprogramm-Quelldateien
main_sources = ['nx_main.c', 'nxld_logger.c', 'nxld_parser.c', 'nxld_plugin.c', 'nxld_plugin_loader.c']

# 创建主程序 / Create main program / Hauptprogramm erstellen
if os.name == 'nt':
    env.Append(LIBS=['kernel32'])
else:
    env.Append(LIBS=['dl'])
main_program = env.Program('nx_main', main_sources)

# 默认目标 / Default target / Standardziel
Default(main_program)

