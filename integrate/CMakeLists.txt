
if(("${CONFIG_PLATEFROM}" STREQUAL "Ubuntu") OR ("${CONFIG_PLATEFROM}" STREQUAL "Debian"))
    ext_add_subdirectory_ifdef(CONFIG_GEN_SYSTEM debian)
endif()