add_executable(cpc-zbgw 
	src/main.c
	src/Queue.c
	src/C2S.c
	src/S2C.c
	src/server.c
	src/system.c
	src/coordinator.c
	src/M2Z.c
	src/Z2M.c
	)
target_link_libraries(cpc-zbgw
  cpc
  util
  pthread
)

get_target_property(CPC_SOURCE_DIR cpc SOURCE_DIR)
target_include_directories(cpc-zbgw PRIVATE ${CPC_SOURCE_DIR}/lib)

ext_install( "TARGET_RUNTIME" cpc-zbgw "bin" cpc-zbgw)

set(DEFAULT_CPC_ZBGW_INSTALL_PATH /var/lib/cpc-zbgw)
set(DEFAULT_CPCD_SERVICE_PATH /lib/systemd/system)
if(NOT CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
	install(DIRECTORY DESTINATION ${CMAKE_INSTALL_PREFIX}/${DEFAULT_CPC_ZBGW_INSTALL_PATH} COMPONENT cpc-zbgw)
  set(CPCD_SERVICE_PATH ${CMAKE_INSTALL_PREFIX}/${DEFAULT_CPCD_SERVICE_PATH})
  set(CPC_ZBGW_SERVICE_PATH ${CMAKE_INSTALL_PREFIX}/${DEFAULT_CPC_ZBGW_INSTALL_PATH})
else()
	install(DIRECTORY DESTINATION ${DEFAULT_CPC_ZBGW_INSTALL_PATH} COMPONENT cpc-zbgw)
  set(CPCD_SERVICE_PATH ${DEFAULT_CPCD_SERVICE_PATH})
  set(CPC_ZBGW_SERVICE_PATH ${DEFAULT_CPC_ZBGW_INSTALL_PATH})
endif()

ext_install(
  "EXECUTE"
  ${CMAKE_CURRENT_BINARY_DIR}/cpc-zbgw
  ${CPC_ZBGW_SERVICE_PATH}
  cpc-zbgw
)

ext_install(
  "DIRECTORY"
  zbdb
  ${CPC_ZBGW_SERVICE_PATH}
  cpc-zbgw
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
    cpc-zbgw
  )
endif()
