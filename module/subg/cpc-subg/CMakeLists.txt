add_executable(cpc-subg
	src/main.c
	)
target_link_libraries(cpc-subg
  cpc
  util
  pthread
)

get_target_property(CPC_SOURCE_DIR cpc SOURCE_DIR)
target_include_directories(cpc-subg PRIVATE ${CPC_SOURCE_DIR}/lib)

ext_install( "TARGET_RUNTIME" cpc-subg "bin" cpc-subg)

set(DEFAULT_CPC_ZBGW_INSTALL_PATH /var/lib/cpc-subg)
set(DEFAULT_CPCD_SERVICE_PATH /lib/systemd/system)
if(NOT CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
	install(DIRECTORY DESTINATION ${CMAKE_INSTALL_PREFIX}/${DEFAULT_CPC_ZBGW_INSTALL_PATH} COMPONENT cpc-subg)
  set(CPCD_SERVICE_PATH ${CMAKE_INSTALL_PREFIX}/${DEFAULT_CPCD_SERVICE_PATH})
  set(CPC_ZBGW_SERVICE_PATH ${CMAKE_INSTALL_PREFIX}/${DEFAULT_CPC_ZBGW_INSTALL_PATH})
else()
	install(DIRECTORY DESTINATION ${DEFAULT_CPC_ZBGW_INSTALL_PATH} COMPONENT cpc-subg)
  set(CPCD_SERVICE_PATH ${DEFAULT_CPCD_SERVICE_PATH})
  set(CPC_ZBGW_SERVICE_PATH ${DEFAULT_CPC_ZBGW_INSTALL_PATH})
endif()

ext_install(
  "EXECUTE"
  ${CMAKE_CURRENT_BINARY_DIR}/cpc-subg
  ${CPC_ZBGW_SERVICE_PATH}
  cpc-subg
)
