
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