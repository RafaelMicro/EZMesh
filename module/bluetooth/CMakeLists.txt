add_executable(ez-bluetooth ezmesh-bluetooth.c)
target_link_libraries(ez-bluetooth ezmesh util pthread)

get_target_property(EZMESH_SOURCE_DIR ezmesh SOURCE_DIR)
target_include_directories(ez-bluetooth PRIVATE ${EZMESH_SOURCE_DIR}/library)

ext_install("TARGET_RUNTIME" ez-bluetooth "bin" ez-bluetooth)


if(${CONFIG_GEN_SYSTEM})
    set(DEFAULT_EZMESH_BLUETOOTH_INSTALL_PATH /var/lib/ezmesh-bluetooth)
    set(DEFAULT_EZMESHD_SERVICE_PATH /lib/systemd/system)
    if(NOT CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
    install(DIRECTORY DESTINATION ${CMAKE_INSTALL_PREFIX}${DEFAULT_EZMESH_BLUETOOTH_INSTALL_PATH} COMPONENT ezmesh-bluetooth)
    set(EZMESH_BLUETOOTH_SERVICE_PATH ${CMAKE_INSTALL_PREFIX}${DEFAULT_EZMESH_BLUETOOTH_INSTALL_PATH})
    else()
    install(DIRECTORY DESTINATION ${DEFAULT_EZMESH_BLUETOOTH_INSTALL_PATH} COMPONENT ezmesh-bluetooth)
    set(EZMESH_BLUETOOTH_SERVICE_PATH ${DEFAULT_EZMESH_BLUETOOTH_INSTALL_PATH})
    endif()

    ext_install("EXECUTE" ${CMAKE_CURRENT_BINARY_DIR}/ez-bluetooth ${EZMESH_BLUETOOTH_SERVICE_PATH} ez-bluetooth)
endif()

