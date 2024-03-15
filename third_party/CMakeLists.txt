

if(${CONFIG_USE_CROSS_COMPILER})
    set(protobuf_BUILD_TESTS OFF)
    ext_add_subdirectory_ifdef(CONFIG_BORDER_ROUTER protobuf/cmake)
    ext_add_subdirectory_ifdef(CONFIG_BORDER_ROUTER libexpat/expat)
    ext_add_subdirectory_ifdef(CONFIG_BORDER_ROUTER dbus)
    ext_add_subdirectory_ifdef(CONFIG_BORDER_ROUTER avahi)
endif()
