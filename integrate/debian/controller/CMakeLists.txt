
if((${CONFIG_BLUETOOTH}) AND (${CONFIG_BORDER_ROUTER})) 
  set(MGMT_POSTFIX -all)
elseif(${CONFIG_BLUETOOTH}) 
  set(MGMT_POSTFIX -bt)
elseif(${CONFIG_BORDER_ROUTER}) 
  set(MGMT_POSTFIX -br)
endif()

# # ext_set_config_file(debconf/config)
# ext_set_config_file(debconf/postinst)
# ext_set_config_file(debconf/prerm)
# ext_set_config_file(debconf/postrm)
ext_set_config_file(debconf/setup)

# ext_set_config_file(debconf/templates)
ext_set_config_file(debconf/conffiles)
ext_set_config_file(ezmeshd.service)
ext_set_config_file(ez-mgmt.service)
ext_set_config_file_to_dst(scripts/ez-mgmt${MGMT_POSTFIX} scripts/ez-mgmt)
# configure_file(${CMAKE_CURRENT_SOURCE_DIR}/scripts/ez-mgmt${MGMT_POSTFIX}.in ${CMAKE_CURRENT_BINARY_DIR}/scripts/ez-mgmt)


set(DEFAULT_EZMESH_SERVICE_PATH lib/systemd/system/)
set(DEFAULT_EZMESH_SCRIPTS_PATH src/scripts/)
if(NOT CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
  install(DIRECTORY DESTINATION ${CMAKE_INSTALL_PREFIX}/${DEFAULT_EZMESH_SCRIPTS_PATH} COMPONENT ez-mgmt)
  set(EZMESH_SCRIPTS_PATH ${CMAKE_INSTALL_PREFIX}/${DEFAULT_EZMESH_SERVICE_PATH})
  set(EZMESH_MGMT_PATH ${CMAKE_INSTALL_PREFIX}/${DEFAULT_EZMESH_SCRIPTS_PATH})
else()
  install(DIRECTORY DESTINATION ${DEFAULT_EZMESH_SCRIPTS_PATH} COMPONENT ez-mgmt)
  set(EZMESH_SCRIPTS_PATH ${DEFAULT_EZMESH_SERVICE_PATH})
  set(EZMESH_MGMT_PATH ${DEFAULT_EZMESH_SCRIPTS_PATH})
endif()

ext_install("FILE" ${CMAKE_CURRENT_BINARY_DIR}/ez-mgmt.service ${EZMESH_SCRIPTS_PATH} ezmesh)
ext_install("EXECUTE" ${CMAKE_CURRENT_BINARY_DIR}/scripts/ez-mgmt ${EZMESH_MGMT_PATH} ez-mgmt)
ext_install("EXECUTE" ${CMAKE_CURRENT_BINARY_DIR}/ezmeshd.service ${EZMESH_SCRIPTS_PATH} ezmesh)


if(EZMESH_LOCATION)
  # Install configuration file
  ext_install( "FILE" ${EZMESH_LOCATION}/etc/ez_config.ini ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_SYSCONFDIR} ezmesh)
else()
  ext_install("TARGET_HEADER" ezmesh ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_INCLUDEDIR} ezmesh)
  ext_install("TARGET_LIBRARY" ezmesh ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR} ezmesh)
  ext_install("TARGET_RUNTIME" ezmesh ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_BINDIR} ezmesh)
  ext_install("FILE" ${EZMESH_SOURCE_DIR}/ez_config.ini ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_SYSCONFDIR} ezmesh)
  ext_install("TARGET_HEADER" ezmesh ${EZMESH_MGMT_PATH} ez-mgmt)
  ext_install( "EXECUTE" ${CMAKE_CURRENT_BINARY_DIR}/debconf/setup ${CMAKE_CURRENT_BINARY_DIR} ezmesh)
endif()

