add_subdirectory(openwrt)

project(EZMESH VERSION "${EZMESHD_VER}" LANGUAGES C)
set(EZMESH_LIBRARY_API_VERSION "${EZMESHD_LIB}")
set(EZMESH_PROTOCOL_VERSION "${EZMESHD_POTOCOL}")

# Options
set(TARGET_GROUP release CACHE STRING "Group to build")
option(WARN_AS_ERROR "Treat warnings as errors")

set(EZMESH_CRC_0 0)
if (DEFINED EZMESH_CRC_0)
  message(STATUS "Using EZMESH_CRC_0")
  add_definitions(-DEZMESH_CRC_0=${EZMESH_CRC_0})
endif()

# Includes
include(cmake/GetGitRevisionDescription.cmake)
include(cmake/TargetStds.cmake)
include(cmake/Warnings.cmake)
include(GNUInstallDirs)

# Dependencies
find_package(Threads REQUIRED)
find_path(Linux_INCLUDE_DIR "linux/version.h")

ext_config(GIT_SHA1 "Unknown")
ext_config(GIT_REFSPEC "Unknown")
get_git_head_revision(GIT_REFSPEC GIT_SHA1 ALLOW_LOOKING_ABOVE_CMAKE_SOURCE_DIR)
add_definitions("-DGIT_SHA1=\"${GIT_SHA1}\"")
add_definitions("-DGIT_REFSPEC=\"${GIT_REFSPEC}\"")

if(WARN_AS_ERROR)
  target_compile_options(_Warnings INTERFACE -Werror)
endif()

add_library(ezmesh SHARED)
target_stds(ezmesh C 99 POSIX 2008)
target_link_libraries(ezmesh PRIVATE Interface::Warnings)
target_sources(ezmesh PRIVATE host/hal_sleep.c)
target_sources(ezmesh PRIVATE library/libezmesh.c)

target_include_directories(ezmesh PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
target_include_directories(ezmesh PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/autogen")
set_target_properties(ezmesh PROPERTIES VERSION "${PROJECT_VERSION}")
set_target_properties(ezmesh PROPERTIES SOVERSION "${EZMESH_LIBRARY_API_VERSION}")
set_target_properties(ezmesh PROPERTIES PUBLIC_HEADER "${CMAKE_CURRENT_SOURCE_DIR}/library/libezmesh.h")

# EZMESHd Config file path
if(NOT DEFINED EZMESHD_CONFIG_FILE_PATH)
  set(EZMESHD_CONFIG_FILE_PATH ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_SYSCONFDIR}/config.ini)
endif()
add_definitions(-DEZMESHD_CONFIG_FILE_PATH="${EZMESHD_CONFIG_FILE_PATH}")
message(STATUS "EZMESHD_CONFIG_FILE_PATH=${EZMESHD_CONFIG_FILE_PATH}")

# EZMESHd minimum reboot time
if(NOT DEFINED EZMESHD_REBOOT_TIME_MS)
  set(EZMESHD_REBOOT_TIME_MS 2000)
endif()
add_definitions(-DEZMESHD_REBOOT_TIME_MS=${EZMESHD_REBOOT_TIME_MS})
message(STATUS "EZMESHD_REBOOT_TIME_MS=${EZMESHD_REBOOT_TIME_MS}")

# EZMESH Socket directory
if(NOT DEFINED EZMESH_SOCKET_DIR)
  set(EZMESH_SOCKET_DIR /dev/shm/ezmesh)
endif()
add_definitions(-DEZMESH_SOCKET_DIR="${EZMESH_SOCKET_DIR}")
message(STATUS "EZMESH_SOCKET_DIR=${EZMESH_SOCKET_DIR}")


# Build EZMESH Daemon if building for release or debug
if((TARGET_GROUP STREQUAL release) OR (TARGET_GROUP STREQUAL debug))
  message(STATUS "Building EZMESH Daemon")

  # CMake<3.11 requires two arguments
  add_executable(ezmeshd main.c)
  target_stds(ezmeshd C 99 POSIX 2008)
  target_link_libraries(ezmeshd PRIVATE Interface::Warnings)
  target_include_directories(ezmeshd PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/autogen")
  target_include_directories(ezmeshd PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
  target_include_directories(ezmeshd PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/library")
  target_sources(ezmeshd PRIVATE
                main.c
                daemon/hdlc/core.c
                daemon/primary/primary.c
                daemon/controller.c
                host/hal_epoll.c
                host/hal_kill.c
                host/hal_sleep.c
                host/hal_uart.c
                utility/config.c
                utility/list.c
                utility/log.c
                utility/utility.c)

  target_link_libraries(ezmeshd PRIVATE Threads::Threads)

  # Hash all files except those in the output folder
  get_target_property(EZMESHD_SOURCES ezmeshd SOURCES)
  foreach(file ${EZMESHD_SOURCES})
    file(SHA256 "${CMAKE_CURRENT_SOURCE_DIR}/${file}" FILE_HASH)
    string(APPEND SOURCES_HASH "${FILE_HASH}")
    string(SHA256 SOURCES_HASH "${SOURCES_HASH}")
  endforeach()
  message(STATUS "Sources hash: ${SOURCES_HASH}")

  install(TARGETS ezmesh ezmeshd
          LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
          RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
          PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
          PRIVATE_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
  install(FILES ez_config.ini DESTINATION ${CMAKE_INSTALL_SYSCONFDIR} COMPONENT config)
endif()

# Configure the version header file
configure_file(utility/version.h.in autogen/version.h)
