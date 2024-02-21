
set(EZMESHD_VER "2.0.0")
set(EZMESHD_LIB "1")
set(EZMESHD_POTOCOL "3")

show_banner(${EZMESHD_VER})
show_config(${EZMESHD_VER})

ext_add_compile_options(
    -Wno-dev
    -Wno-psabi
)

set(PROJECT_VER "")
get_git_hash(PROJECT_VER)
message("Current project git version: ${PROJECT_VER}")
find_package(Threads)

if(${CONFIG_USE_CROSS_COMPILER})
    ext_apply_patch("dbus" "third_party/dbus" ${CMAKE_SOURCE_DIR}/cmake/dbus.patch)
endif()