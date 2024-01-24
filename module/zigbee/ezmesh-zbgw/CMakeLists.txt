add_executable(ezmesh-zbgw 
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
target_link_libraries(ezmesh-zbgw ezmesh util pthread)

get_target_property(EZMESH_SOURCE_DIR ezmesh SOURCE_DIR)
target_include_directories(ezmesh-zbgw PRIVATE ${EZMESH_SOURCE_DIR}/library)

ext_install( "TARGET_RUNTIME" ezmesh-zbgw "bin" ezmesh-zbgw)

set(DEFAULT_EZMESH_ZBGW_INSTALL_PATH /var/lib/ezmesh-zbgw)
set(DEFAULT_EZMESHD_SERVICE_PATH /lib/systemd/system)
if(NOT CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
  install(DIRECTORY DESTINATION ${CMAKE_INSTALL_PREFIX}/${DEFAULT_EZMESH_ZBGW_INSTALL_PATH} COMPONENT ezmesh-zbgw)
  set(EZMESHD_SERVICE_PATH ${CMAKE_INSTALL_PREFIX}/${DEFAULT_EZMESHD_SERVICE_PATH})
  set(EZMESH_ZBGW_SERVICE_PATH ${CMAKE_INSTALL_PREFIX}/${DEFAULT_EZMESH_ZBGW_INSTALL_PATH})
else()
  install(DIRECTORY DESTINATION ${DEFAULT_EZMESH_ZBGW_INSTALL_PATH} COMPONENT ezmesh-zbgw)
  set(EZMESHD_SERVICE_PATH ${DEFAULT_EZMESHD_SERVICE_PATH})
  set(EZMESH_ZBGW_SERVICE_PATH ${DEFAULT_EZMESH_ZBGW_INSTALL_PATH})
endif()

ext_install("EXECUTE" ${CMAKE_CURRENT_BINARY_DIR}/ezmesh-zbgw ${EZMESH_ZBGW_SERVICE_PATH} ezmesh-zbgw)
ext_install("DIRECTORY" zbdb ${EZMESH_ZBGW_SERVICE_PATH} ezmesh-zbgw)

if(EZMESHD_LOCATION)
  # Install configuration file
  ext_install("FILE" ${EZMESHD_LOCATION}/etc/config.ini ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_SYSCONFDIR} ezmeshd)
else()
  # Install binaries they come from custom target build_ezmeshd
  ext_install("TARGET_HEADER" ezmesh ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_INCLUDEDIR} ezmesh-zbgw)
endif()
