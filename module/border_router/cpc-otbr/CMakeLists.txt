include(FetchContent)

set(FETCHCONTENT_QUIET False)
set(CMAKE_INSTALL_DEFAULT_COMPONENT_NAME cpc-otbr)

# ot-br-posix unfortunately has a variable set but not used, making our compiler fail because of warnings as errors.
add_compile_options(-Wno-unused-but-set-variable)

FetchContent_Declare(
  ot-br-posix
  URL ${CMAKE_CURRENT_SOURCE_DIR}/third_party/ot-br-posix
  SOURCE_DIR "${CMAKE_CURRENT_BINARY_DIR}/ot-br-posix"
)
FetchContent_GetProperties(ot-br-posix)
FetchContent_Populate(ot-br-posix)

FetchContent_Declare(
  openthread
  URL ${CMAKE_CURRENT_SOURCE_DIR}/third_party/openthread
  SOURCE_DIR "${CMAKE_CURRENT_BINARY_DIR}/openthread"
)

FetchContent_Populate(openthread)


# Install compile-time configuration constants header file
file(GLOB POSIX_CONFIG_HEADERS "${CMAKE_CURRENT_SOURCE_DIR}/openthread-core-rafael-posix-config.h")
file(COPY ${POSIX_CONFIG_HEADERS} DESTINATION ${openthread_SOURCE_DIR}/src/posix/platform)
file(COPY ${POSIX_CONFIG_HEADERS} DESTINATION ${ot-br-posix_SOURCE_DIR}/third_party/openthread/repo/src/posix/platform)


# Compilation settings defined
set(OT_CONFIG openthread-core-rafael-posix-config.h CACHE STRING "Project-specific openthread config file")
set(OT_MULTIPAN_RCP ON CACHE BOOL "enable multi-PAN RCP")
set(OT_POSIX_CONFIG_RCP_BUS "CPC" CACHE STRING "RCP bus type")
set(OT_DIAGNOSTIC ON CACHE BOOL "enable diagnostic support")
set(OT_PACKAGE_NAME "OPENTHREAD" CACHE STRING "OpenThread Package Name")
set(OT_FULL_LOGS OFF CACHE BOOL "Enable debug level logging" FORCE)


if(NOT BUILD_TESTING)
  set(ENABLE_CJSON_TEST OFF CACHE BOOL "ENABLE CJSON tests")
  set(ENABLE_TESTING OFF CACHE BOOL "Build mbed TLS tests.")
endif()

include("${CMAKE_CURRENT_SOURCE_DIR}/cmake/options.cmake")

add_subdirectory(${ot-br-posix_SOURCE_DIR} ${ot-br-posix_BINARY_DIR})

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/debconf/prerm.in
               ${CMAKE_CURRENT_BINARY_DIR}/debconf/prerm.in)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/debconf/postinst.in
               ${CMAKE_CURRENT_BINARY_DIR}/debconf/postinst.in)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/debconf/services/cpc-otbr.in
               ${CMAKE_CURRENT_BINARY_DIR}/debconf/services/cpc-otbr.in)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/debconf/postrm.in
               ${CMAKE_CURRENT_BINARY_DIR}/debconf/postrm)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/debconf/services/cpc-otbr.service.in
               ${CMAKE_CURRENT_BINARY_DIR}/debconf/services/cpc-otbr.service)

# Second stage scriptlet configuration - evaluate generator expressions
file(GENERATE OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/debconf/prerm
              INPUT  ${CMAKE_CURRENT_BINARY_DIR}/debconf/prerm.in)

file(GENERATE OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/debconf/postinst
              INPUT  ${CMAKE_CURRENT_BINARY_DIR}/debconf/postinst.in)

file(GENERATE OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/debconf/services/cpc-otbr
              INPUT  ${CMAKE_CURRENT_BINARY_DIR}/debconf/services/cpc-otbr.in)

# Remove otbr compilation for target setup
# Update otbr-agent config with spinel url
execute_process(
  COMMAND sed -i "/otbr/d" ${ot-br-posix_SOURCE_DIR}/script/setup
  COMMAND sed -i "s/set -euxo pipefail/set -euo pipefail/g" ${ot-br-posix_SOURCE_DIR}/script/_initrc
  COMMAND sed -i "s|spinel.* |${OTBR_RADIO_URL} |" ${ot-br-posix_BINARY_DIR}/src/agent/otbr-agent.default
  COMMAND_ERROR_IS_FATAL ANY
)

ext_install(
  "DIRECTORY"
  ${ot-br-posix_SOURCE_DIR}/script
  share/otbr
  cpc-otbr
)

ext_install(
  "DIRECTORY"
  ${CMAKE_CURRENT_SOURCE_DIR}/debconf/services/otbr-agent.service.d
  /etc/systemd/system
  cpc-otbr
)

ext_install(
  "DIRECTORY"
  ${CMAKE_CURRENT_SOURCE_DIR}/debconf/services/otbr-nat44.service.d
  /etc/systemd/system
  cpc-otbr
)

ext_install(
  "DIRECTORY"
  ${CMAKE_CURRENT_SOURCE_DIR}/debconf/services/otbr-firewall.service.d
  /etc/systemd/system
  cpc-otbr
)

ext_install(
  "FILE"
  ${CMAKE_CURRENT_BINARY_DIR}/debconf/services/cpc-otbr.service
  ${OTBR_SYSTEMD_UNIT_DIR}
  cpc-otbr
)


ext_install(
  "FILE"
  ${CMAKE_CURRENT_BINARY_DIR}/debconf/services/cpc-otbr
  /etc/default
  cpc-otbr
)
