add_executable(cpc-bluetooth src/cpc-bluetooth.c)
target_link_libraries(cpc-bluetooth
  cpc
  util
  pthread
)

get_target_property(CPC_SOURCE_DIR cpc SOURCE_DIR)
target_include_directories(cpc-bluetooth PRIVATE ${CPC_SOURCE_DIR}/lib)

ext_install( "TARGET_RUNTIME" cpc-bluetooth "bin" cpc-bluetooth)

set(DEFAULT_CPC_BLUETOOTH_INSTALL_PATH /var/lib/cpc-bluetooth)
set(DEFAULT_CPCD_SERVICE_PATH /lib/systemd/system)
if(NOT CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
  install(DIRECTORY DESTINATION ${CMAKE_INSTALL_PREFIX}/${DEFAULT_CPC_BLUETOOTH_INSTALL_PATH} COMPONENT cpc-bluetooth)
  set(CPCD_SERVICE_PATH ${CMAKE_INSTALL_PREFIX}/${DEFAULT_CPCD_SERVICE_PATH})
  set(CPC_BLUETOOTH_SERVICE_PATH ${CMAKE_INSTALL_PREFIX}/${DEFAULT_CPC_BLUETOOTH_INSTALL_PATH})
else()
  install(DIRECTORY DESTINATION ${DEFAULT_CPC_BLUETOOTH_INSTALL_PATH} COMPONENT cpc-bluetooth)
  set(CPCD_SERVICE_PATH ${DEFAULT_CPCD_SERVICE_PATH})
  set(CPC_BLUETOOTH_SERVICE_PATH ${DEFAULT_CPC_BLUETOOTH_INSTALL_PATH})
endif()

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/debconf/postinst.in
               ${CMAKE_CURRENT_BINARY_DIR}/debconf/postinst)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/debconf/prerm.in
               ${CMAKE_CURRENT_BINARY_DIR}/debconf/prerm)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/debconf/services/cpc-bluetooth.service.in
               ${CMAKE_CURRENT_BINARY_DIR}/debconf/services/cpc-bluetooth.service)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/scripts/startpost.in
               ${CMAKE_CURRENT_BINARY_DIR}/scripts/startpost)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/scripts/stop.in
               ${CMAKE_CURRENT_BINARY_DIR}/scripts/stop)

ext_install(
  "FILE"
  ${CMAKE_CURRENT_BINARY_DIR}/debconf/services/cpc-bluetooth.service
  ${CPCD_SERVICE_PATH}
  cpc-bluetooth)

ext_install(
  "EXECUTE"
  ${CMAKE_CURRENT_BINARY_DIR}/cpc-bluetooth
  ${CPC_BLUETOOTH_SERVICE_PATH}
  cpc-bluetooth
)

ext_install(
  "EXECUTE"
  ${CMAKE_CURRENT_BINARY_DIR}/scripts/startpost
  ${CPC_BLUETOOTH_SERVICE_PATH}
  startpost
)

ext_install(
  "EXECUTE"
  ${CMAKE_CURRENT_BINARY_DIR}/scripts/stop
  ${CPC_BLUETOOTH_SERVICE_PATH}
  stop
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
    cpc-bluetooth
  )

  ext_install(
    "TARGET_HEADER" cpc
    ${CPC_BLUETOOTH_SERVICE_PATH}
    startpost
  )

  ext_install(
    "TARGET_HEADER" cpc
    ${CPC_BLUETOOTH_SERVICE_PATH}
    stop
  )
  
  ext_install(
    "FILE" ${cpcd_SOURCE_DIR}/cpcd.conf
    ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_SYSCONFDIR}
    cpcd)
endif()