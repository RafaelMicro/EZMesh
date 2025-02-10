# include(FetchContent)

# set(FETCHCONTENT_QUIET False)
set(CMAKE_INSTALL_DEFAULT_COMPONENT_NAME ez-otbr)

# ot-br-posix unfortunately has a variable set but not used, making our compiler fail because of warnings as errors.
add_compile_options(-Wno-unused-but-set-variable)

set(ot-br-posix_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/ot-br-posix)
set(openthread_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/openthread)

set(Protobuf_PROTOC_EXECUTABLE "/usr/local/bin/protoc")

if(${CONFIG_USE_CROSS_COMPILER})
include_directories(
  "${CMAKE_SOURCE_DIR}/third_party/avahi"
  "${CMAKE_SOURCE_DIR}/third_party/protobuf/src"
  "${CMAKE_SOURCE_DIR}/third_party/protobuf/src/google"
)
endif()
# Install compile-time configuration constants header file
file(GLOB POSIX_CONFIG_HEADERS "${CMAKE_CURRENT_SOURCE_DIR}/openthread-core-rafael-posix-config.h")
file(COPY ${POSIX_CONFIG_HEADERS} DESTINATION ${openthread_SOURCE_DIR}/src/posix/platform)
file(COPY ${POSIX_CONFIG_HEADERS} DESTINATION ${ot-br-posix_SOURCE_DIR}/third_party/openthread/repo/src/posix/platform)

# Compilation settings defined
set(OT_CONFIG openthread-core-rafael-posix-config.h CACHE STRING "Project-specific openthread config file")
# set(OT_MULTIPAN_RCP ON CACHE BOOL "enable multi-PAN RCP")
# set(OT_POSIX_CONFIG_RCP_BUS "EZMESH" CACHE STRING "RCP bus type")
set(OT_DIAGNOSTIC ON CACHE BOOL "enable diagnostic support")
set(OT_PACKAGE_NAME "OPENTHREAD" CACHE STRING "OpenThread Package Name")
set(OT_PACKAGE_VERSION "8bc2504" CACHE STRING "OpenThread Package Version")
set(OT_FULL_LOGS ON CACHE BOOL "Enable debug level logging" FORCE)
set(OT_POSIX_RCP_VENDOR_BUS ON CACHE BOOL "enable RCP vendor bus")

if(NOT BUILD_TESTING)
  set(ENABLE_CJSON_TEST OFF CACHE BOOL "ENABLE CJSON tests")
  set(ENABLE_TESTING OFF CACHE BOOL "Build mbed TLS tests.")
endif()

#include("${CMAKE_CURRENT_SOURCE_DIR}/cmake/options.cmake")
add_subdirectory(${ot-br-posix_SOURCE_DIR})

ext_install("DIRECTORY" ${ot-br-posix_SOURCE_DIR}/script share/otbr ez-otbr)
