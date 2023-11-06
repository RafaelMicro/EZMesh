cmake_minimum_required(VERSION 3.21)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake")
include(project.conf)

include(extension)
include(project)
set(PROJECT_VER "")
get_git_hash(PROJECT_VER)
message("Current project git information: ${PROJECT_VER}")

project(RAFAEL_HOST_SDK LANGUAGES C CXX)
add_subdirectory(module)