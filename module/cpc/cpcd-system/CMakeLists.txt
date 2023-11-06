add_executable(cpc-upgrade 
  src/upgrade/cpc-upgrade.c
  src/upgrade/fsm.c)

target_link_libraries(cpc-upgrade
  cpc
  util
  pthread
)

get_target_property(CPC_SOURCE_DIR cpc SOURCE_DIR)
target_include_directories(cpc-upgrade PRIVATE 
  ${CPC_SOURCE_DIR}/lib
  src/upgrade/include)

install(TARGETS cpc-upgrade RUNTIME DESTINATION "bin" COMPONENT cpc-upgrade)

set(DEFAULT_CPC_HCI_BRIDGE_INSTALL_PATH /var/lib/cpc-upgrade)
if(NOT CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
  install(DIRECTORY DESTINATION ${CMAKE_INSTALL_PREFIX}/${DEFAULT_CPC_HCI_BRIDGE_INSTALL_PATH} COMPONENT cpc-upgrade)
else()
  install(DIRECTORY DESTINATION ${DEFAULT_CPC_HCI_BRIDGE_INSTALL_PATH} COMPONENT cpc-upgrade)
endif()

if((${CONFIG_BLUETOOTH}) AND (${CONFIG_BORDER_ROUTER}))
  set(MGMT_POSTFIX -all)
elseif(${CONFIG_BLUETOOTH})
  set(MGMT_POSTFIX -bt)
elseif(${CONFIG_BORDER_ROUTER})
  set(MGMT_POSTFIX -br)
endif()

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/debconf/config.in
               ${CMAKE_CURRENT_BINARY_DIR}/debconf/config)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/debconf/postinst.in
               ${CMAKE_CURRENT_BINARY_DIR}/debconf/postinst)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/debconf/prerm.in
               ${CMAKE_CURRENT_BINARY_DIR}/debconf/prerm)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/debconf/postrm.in
               ${CMAKE_CURRENT_BINARY_DIR}/debconf/postrm)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/debconf/templates.in
               ${CMAKE_CURRENT_BINARY_DIR}/debconf/templates)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/debconf/conffiles.in
               ${CMAKE_CURRENT_BINARY_DIR}/debconf/conffiles)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/debconf/services/cpcd.service.in
               ${CMAKE_CURRENT_BINARY_DIR}/debconf/services/cpcd.service)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/debconf/services/cpc-mgmt.service.in
               ${CMAKE_CURRENT_BINARY_DIR}/debconf/services/cpc-mgmt.service)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/scripts/cpc-mgmt${MGMT_POSTFIX}.in
               ${CMAKE_CURRENT_BINARY_DIR}/scripts/cpc-mgmt)


set(DEFAULT_CPCD_SERVICE_PATH lib/systemd/system/)
set(DEFAULT_CPCD_SCRIPTS_PATH src/scripts/)
if(NOT CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
  install(DIRECTORY DESTINATION ${CMAKE_INSTALL_PREFIX}/${DEFAULT_CPCD_SCRIPTS_PATH} COMPONENT cpc-mgmt)
  set(CPCD_SERVICE_PATH ${CMAKE_INSTALL_PREFIX}/${DEFAULT_CPCD_SERVICE_PATH})
  set(CPC_MGMT_PATH ${CMAKE_INSTALL_PREFIX}/${DEFAULT_CPCD_SCRIPTS_PATH})
else()
  install(DIRECTORY DESTINATION ${DEFAULT_CPCD_SCRIPTS_PATH} COMPONENT cpc-mgmt)
  set(CPCD_SERVICE_PATH ${DEFAULT_CPCD_SERVICE_PATH})
  set(CPC_MGMT_PATH ${DEFAULT_CPCD_SCRIPTS_PATH})
endif()

ext_install(
  "FILE"
  ${CMAKE_CURRENT_BINARY_DIR}/debconf/services/cpc-mgmt.service
  ${CPCD_SERVICE_PATH}
  cpcd
)

ext_install(
  "EXECUTE"
  ${CMAKE_CURRENT_BINARY_DIR}/scripts/cpc-mgmt
  ${CPC_MGMT_PATH}
  cpc-mgmt
)

ext_install(
  "EXECUTE"
  ${CMAKE_CURRENT_BINARY_DIR}/debconf/services/cpcd.service
  ${CPCD_SERVICE_PATH}
  cpcd
)

if(CPCD_LOCATION)
  # Install configuration file
  ext_install(
    "FILE" ${CPCD_LOCATION}/etc/cpcd.conf
    ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_SYSCONFDIR}
    cpcd)
else()
  # Install binaries they come from custom target build_cpcd

  ext_install(
    "TARGET_HEADER" cpc
    ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_INCLUDEDIR}
    cpcd)

  ext_install(
    "TARGET_LIBRARY" cpc
    ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}
    cpcd)

  ext_install(
    "TARGET_RUNTIME" cpc
    ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_BINDIR}
    cpcd)

  ext_install(
    "FILE" ${cpcd_SOURCE_DIR}/cpcd.conf
    ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_SYSCONFDIR}
    cpcd)
  
  
  ext_install(
    "TARGET_HEADER" cpc
    ${CPC_MGMT_PATH}
    cpc-mgmt
  )
endif()

