if(OTBR_OPENWRT)
    configure_file(ezmesh.init.in ezmesh.init)
    message("CMAKE_CURRENT_BINARY_DIR: ${CMAKE_CURRENT_BINARY_DIR}")
    message("CMAKE_INSTALL_FULL_SYSCONFDIR: ${CMAKE_INSTALL_FULL_SYSCONFDIR}")
    install(FILES ${CMAKE_CURRENT_BINARY_DIR}/ezmesh.init
        DESTINATION ${CMAKE_INSTALL_FULL_SYSCONFDIR}/etc/init.d
        RENAME ezmesh)

    configure_file(ezmesh_ble.init.in ezmesh_ble.init)
    message("CMAKE_CURRENT_BINARY_DIR: ${CMAKE_CURRENT_BINARY_DIR}")
    message("CMAKE_INSTALL_FULL_SYSCONFDIR: ${CMAKE_INSTALL_FULL_SYSCONFDIR}")
    install(FILES ${CMAKE_CURRENT_BINARY_DIR}/ezmesh_ble.init
        DESTINATION ${CMAKE_INSTALL_FULL_SYSCONFDIR}/etc/init.d
        RENAME ezmesh_ble)
endif(OTBR_OPENWRT=ON)
