
ext_config_ifndef(CONFIG_CONTROLLER true)
ext_config_ifndef(CONFIG_UPGRADE true)
ext_config_ifndef(CONFIG_BLUETOOTH false)
ext_config_ifndef(CONFIG_BORDER_ROUTER false)
ext_config_ifndef(CONFIG_ZIGBEE_GW_SERVICE false)
ext_config_ifndef(CONFIG_SUBG_SERVICE false)

ext_config_ifndef(CONFIG_GEN_SYSTEM false)
ext_config_ifndef(CONFIG_PLATEFROM "")
get_platfrom_info(CONFIG_PLATEFROM)

ext_config_ifndef(EZMESHD_VER "1.0.0")
ext_config_ifndef(EZMESHD_LIB "1")
ext_config_ifndef(EZMESHD_POTOCOL "3")

ext_config_ifndef(CONFIG_USE_CROSS_COMPILER false)
ext_config_ifndef(CONFIG_CROSS_COMPILER_SYSTEM_NAME "")
ext_config_ifndef(CONFIG_CROSS_COMPILER_SYSTEM_PROCESSOR "")
ext_config_ifndef(CONFIG_CROSS_COMPILER_PATH "")
ext_config_ifndef(CONFIG_CROSS_COMPILER_PREFIX "")


option(_EXPAT_BUILD_TOOLS_DEFAULT "Build tools" ON)
option(_EXPAT_SHARED_LIBS_DEFAULT "Build shared Lib" ON)
option(protobuf_BUILD_TESTS "Build tests" OFF)
