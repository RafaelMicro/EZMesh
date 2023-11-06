cmake_minimum_required(VERSION 3.10)

project(cpcd
  VERSION "${CPCD_VER}"
  LANGUAGES C)
set(CPC_LIBRARY_API_VERSION "${CPCD_LIB}")
set(CPC_PROTOCOL_VERSION "${CPCD_POTOCOL}")

# Options
set(TARGET_GROUP release CACHE STRING "Group to build")
option(WARN_AS_ERROR "Treat warnings as errors")

#set(CPC_CRC_0 1)
if (DEFINED CPC_CRC_0)
  message(STATUS "Using CPC_CRC_0")
  add_definitions(-DCPC_CRC_0=${CPC_CRC_0})
endif()

# Includes
include(cmake/GetGitRevisionDescription.cmake)
include(cmake/TargetStds.cmake)
include(cmake/Warnings.cmake)
include(GNUInstallDirs)

# Dependencies
find_package(Threads REQUIRED)

find_path(Linux_INCLUDE_DIR "linux/version.h")


set(GIT_SHA1 "Unknown")
set(GIT_REFSPEC "Unknown")
get_git_head_revision(GIT_REFSPEC GIT_SHA1 ALLOW_LOOKING_ABOVE_CMAKE_SOURCE_DIR)
add_definitions("-DGIT_SHA1=\"${GIT_SHA1}\"")
add_definitions("-DGIT_REFSPEC=\"${GIT_REFSPEC}\"")

if(WARN_AS_ERROR)
  target_compile_options(_Warnings INTERFACE -Werror)
endif()

add_library(cpc SHARED)
target_stds(cpc C 99 POSIX 2008)
target_link_libraries(cpc PRIVATE Interface::Warnings)
target_sources(cpc PRIVATE utility/sleep.c)
target_sources(cpc PRIVATE lib/libcpc.c)

target_include_directories(cpc PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
target_include_directories(cpc PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/autogen")
set_target_properties(cpc PROPERTIES VERSION "${PROJECT_VERSION}")
set_target_properties(cpc PROPERTIES SOVERSION "${CPC_LIBRARY_API_VERSION}")
set_target_properties(cpc PROPERTIES PUBLIC_HEADER "${CMAKE_CURRENT_SOURCE_DIR}/lib/libcpc.h")

# CPCd Config file path
if(NOT DEFINED CPCD_CONFIG_FILE_PATH)
  set(CPCD_CONFIG_FILE_PATH ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_SYSCONFDIR}/cpcd.conf)
endif()
add_definitions(-DCPCD_CONFIG_FILE_PATH="${CPCD_CONFIG_FILE_PATH}")
message(STATUS "CPCD_CONFIG_FILE_PATH=${CPCD_CONFIG_FILE_PATH}")

# CPCd minimum reboot time
if(NOT DEFINED CPCD_REBOOT_TIME_MS)
  set(CPCD_REBOOT_TIME_MS 2000)
endif()
add_definitions(-DCPCD_REBOOT_TIME_MS=${CPCD_REBOOT_TIME_MS})
message(STATUS "CPCD_REBOOT_TIME_MS=${CPCD_REBOOT_TIME_MS}")

# CPC Socket directory
if(NOT DEFINED CPC_SOCKET_DIR)
  set(CPC_SOCKET_DIR /dev/shm)
endif()
add_definitions(-DCPC_SOCKET_DIR="${CPC_SOCKET_DIR}")
message(STATUS "CPC_SOCKET_DIR=${CPC_SOCKET_DIR}")


# Build CPC Daemon if building for release or debug
if((TARGET_GROUP STREQUAL release) OR
   (TARGET_GROUP STREQUAL debug))
  message(STATUS "Building CPC Daemon")

  # CMake<3.11 requires two arguments
  add_executable(cpcd main.c)
  target_stds(cpcd C 99 POSIX 2008)
  target_link_libraries(cpcd PRIVATE Interface::Warnings)
  target_include_directories(cpcd PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/autogen")
  target_include_directories(cpcd PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
  target_include_directories(cpcd PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/lib")
  target_sources(cpcd PRIVATE
                      primary/primary_cpcd.c
                      primary/epoll_port/epoll_port.c
                      primary/cpcd/cpcd.c
                      primary/cpcd/crc.c
                      primary/cpcd/hdlc.c
                      primary/primary/primary.c
                      primary/system/system.c
                      primary/system/callbacks.c
                      hal/hal_uart.c
                      hal/hal_kill.c
                      utility/errcode.c
                      utility/logs.c
                      utility/config.c
                      utility/utils.c
                      utility/slist.c
                      utility/sleep.c)

  target_include_directories(cpcd PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/autogen")
  target_include_directories(cpcd PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
  target_include_directories(cpcd PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/lib")
  target_link_libraries(cpcd PRIVATE Threads::Threads)

  # Hash all files except those in the output folder
  get_target_property(CPCD_SOURCES cpcd SOURCES)
  foreach(file ${CPCD_SOURCES})
    file(SHA256 "${CMAKE_CURRENT_SOURCE_DIR}/${file}" FILE_HASH)
    string(APPEND SOURCES_HASH "${FILE_HASH}")
    string(SHA256 SOURCES_HASH "${SOURCES_HASH}")
  endforeach()
  message(STATUS "Sources hash: ${SOURCES_HASH}")

  install(TARGETS cpc cpcd
          LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
          RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
          PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
          PRIVATE_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

  install(FILES cpcd.conf DESTINATION ${CMAKE_INSTALL_SYSCONFDIR} COMPONENT config)
endif()

# Configure the version header file
configure_file(utility/version.h.in autogen/version.h)

