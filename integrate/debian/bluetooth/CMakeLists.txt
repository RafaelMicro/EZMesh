set(DEFAULT_EZMESH_BLUETOOTH_INSTALL_PATH /var/lib/ezmesh-bluetooth)
set(DEFAULT_EZMESHD_SERVICE_PATH /lib/systemd/system)
if(NOT CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
  install(DIRECTORY DESTINATION ${CMAKE_INSTALL_PREFIX}${DEFAULT_EZMESH_BLUETOOTH_INSTALL_PATH} COMPONENT ezmesh-bluetooth)
  set(EZMESHD_SERVICE_PATH ${CMAKE_INSTALL_PREFIX}${DEFAULT_EZMESHD_SERVICE_PATH})
  set(EZMESH_BLUETOOTH_SERVICE_PATH ${CMAKE_INSTALL_PREFIX}${DEFAULT_EZMESH_BLUETOOTH_INSTALL_PATH})
else()
  install(DIRECTORY DESTINATION ${DEFAULT_EZMESH_BLUETOOTH_INSTALL_PATH} COMPONENT ezmesh-bluetooth)
  set(EZMESHD_SERVICE_PATH ${DEFAULT_EZMESHD_SERVICE_PATH})
  set(EZMESH_BLUETOOTH_SERVICE_PATH ${DEFAULT_EZMESH_BLUETOOTH_INSTALL_PATH})
endif()

ext_set_config_file(debconf/setup)
ext_set_config_file(ez-bluetooth.service)
ext_set_config_file(scripts/ez_bt_kill)
ext_set_config_file(scripts/ez_bt_attach)

ext_install("FILE" ${CMAKE_CURRENT_BINARY_DIR}/ez-bluetooth.service ${EZMESHD_SERVICE_PATH} ezmesh-bluetooth)
ext_install("EXECUTE" ${CMAKE_CURRENT_BINARY_DIR}/scripts/ez_bt_kill ${EZMESH_BLUETOOTH_SERVICE_PATH} ez_bt_kill)
ext_install("EXECUTE" ${CMAKE_CURRENT_BINARY_DIR}/scripts/ez_bt_attach ${EZMESH_BLUETOOTH_SERVICE_PATH} ez_bt_attach)
ext_install("EXECUTE" ${CMAKE_CURRENT_BINARY_DIR}/debconf/setup ${CMAKE_CURRENT_BINARY_DIR} ezmesh-bluetooth)
