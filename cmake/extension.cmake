
function(show_banner var)
  message("")
  message("") 
  message("  8888888888 8888888888P 888b     d888                   888        .d8888b.  8888888b.  888    d8P    ")
  message("  888              d88P  8888b   d8888                   888       d88P  Y88b 888  \"Y88b 888   d8P    ")
  message("  888             d88P   88888b.d88888                   888       Y88b.      888    888 888  d8P      ")
  message("  888888888      d88P    888Y88888P888  .d88b.  .d8888b  88888b.    \"Y888b.   888    888 888d88K      ")
  message("  888           d88P     888 Y888P 888 d8P  Y8b 88K      888 \"88b      \"Y88b. 888    888 8888888b    ")
  message("  888          d88P      888  Y8P  888 88888888 \"Y8888b. 888  888  Y88b  \"888 888    888 888  Y88b   ")
  message("  888         d88P       888   \"   888 Y8b.          X88 888  888   Y8888888P 88888888P\" 888   Y88b  ")
  message("  8888888888 d8888888888 888       888  \"Y8888   88888P' 888  888   v${var} Powered By Rafael Micro  ")
  message("")
  message("")
endfunction()

function(show_config)
  message("\t\t---- EZMesh Setup Config ----\n")
  message("\tBUILD CONFIG LIST:")
  message("\t - CONFIG_CONTROLLER: ${CONFIG_CONTROLLER}")
  message("\t - CONFIG_UPGRADE: ${CONFIG_UPGRADE}")
  message("\t - CONFIG_BLUETOOTH: ${CONFIG_BLUETOOTH}")
  message("\t - CONFIG_BORDER_ROUTER: ${CONFIG_BORDER_ROUTER}")
  message("\t - CONFIG_ZIGBEE_GW_SERVICE: ${CONFIG_ZIGBEE_GW_SERVICE}")
  message("\t - CONFIG_SUBG_SERVICE: ${CONFIG_SUBG_SERVICE}")
  message("\t - CONFIG_GEN_SYSTEM: ${CONFIG_GEN_SYSTEM}")

  message("\tEZMESH VERSION:")
  message("\t - EZMESHD_VER: ${EZMESHD_VER}")
  message("\t - EZMESHD_LIB: ${EZMESHD_LIB}")
  message("\t - EZMESHD_POTOCOL: ${EZMESHD_POTOCOL}")

  if(${CONFIG_USE_CROSS_COMPILER})
      message("\tCROSS COMPILER INFORMATION:")
      message("\t - CONFIG_CROSS_COMPILER_SYSTEM_NAME: ${CONFIG_CROSS_COMPILER_SYSTEM_NAME}")
      message("\t - CONFIG_CROSS_COMPILER_SYSTEM_PROCESSOR: ${CONFIG_CROSS_COMPILER_SYSTEM_PROCESSOR}")
      message("\t - CONFIG_CROSS_COMPILER_PATH: ${CONFIG_CROSS_COMPILER_PATH}")
      message("\t - CONFIG_CROSS_COMPILER_PREFIX: ${CONFIG_CROSS_COMPILER_PREFIX}")
  endif()
  message("\n\t\t---- EZMesh Setup Config End----\n\n")
endfunction()

macro(get_git_hash _git_hash)   
    find_package(Git QUIET)
    if(GIT_FOUND)
      execute_process(
        COMMAND ${GIT_EXECUTABLE} describe --tags --dirty
        OUTPUT_VARIABLE ${_git_hash}
        OUTPUT_STRIP_TRAILING_WHITESPACE
        # ERROR_QUIET
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        )
    endif()
endmacro() 

macro(get_platfrom_info platfrom) 
  if(${CONFIG_GEN_SYSTEM})
    message("Target os info: " ${CMAKE_SYSTEM} ", Processor: " ${CMAKE_SYSTEM_PROCESSOR})
    find_program(LSB_RELEASE_EXEC lsb_release)
    execute_process(COMMAND ${LSB_RELEASE_EXEC} -is OUTPUT_VARIABLE ${platfrom} OUTPUT_STRIP_TRAILING_WHITESPACE)
  endif()
endmacro() 

function(ext_set_config_file src)
  configure_file(${CMAKE_CURRENT_SOURCE_DIR}/${src}.in ${CMAKE_CURRENT_BINARY_DIR}/${src})
endfunction()

function(ext_set_config_file_to_dst src dst)
  configure_file(${CMAKE_CURRENT_SOURCE_DIR}/${src}.in ${CMAKE_CURRENT_BINARY_DIR}/${dst})
endfunction()

function(ext_set_config_file_with_gen src)
  configure_file(${CMAKE_CURRENT_SOURCE_DIR}/${src}.in ${CMAKE_CURRENT_BINARY_DIR}/${src}.in)
  file(GENERATE OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/${src} INPUT  ${CMAKE_CURRENT_BINARY_DIR}/${src}.in)
endfunction()

function(ext_set_config_file_to_dst_with_gen src dst)
  configure_file(${CMAKE_CURRENT_SOURCE_DIR}/${src}.in ${CMAKE_CURRENT_BINARY_DIR}/${dst}.in)
  file(GENERATE OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/${dst} INPUT  ${CMAKE_CURRENT_BINARY_DIR}/${src}.in)
endfunction()

function(ext_add_subdirectory_ifdef feature dir)
  if(${${feature}})
    add_subdirectory(${dir})
  endif()
endfunction()

function(ext_add_subdirectory dir)
  add_subdirectory(${dir})
endfunction()

function(ext_add_compile_options)
  add_compile_options(${ARGV})
endfunction()

function(ext_add_compile_options_ifdef feature)
  if(${${feature}})
    ext_add_compile_options(${ARGN})
  endif()
endfunction()

macro(ext_include pkg)
  include(${pkg})
endmacro()

macro(ext_include_ifdef define pkg)
  if(${${define}})
    include(${pkg})
  endif()
endmacro()

macro(ext_config define val)
  set(${define} ${val})
endmacro()

macro(ext_config_ifndef define val)
  if(NOT DEFINED ${define})
    set(${define} ${val})
  endif()
endmacro()

function(ext_install type src dest component)
  if("${type}" STREQUAL "EXECUTE")
    install(
      FILES "${src}"
      DESTINATION "${dest}"
      PERMISSIONS
        OWNER_READ OWNER_WRITE OWNER_EXECUTE
        GROUP_EXECUTE GROUP_READ
        WORLD_READ WORLD_EXECUTE
      COMPONENT "${component}")
  elseif("${type}" STREQUAL "TARGET_HEADER")
    install(
      TARGETS "${src}" PUBLIC_HEADER 
      DESTINATION "${dest}"
      PERMISSIONS
        OWNER_READ OWNER_WRITE OWNER_EXECUTE
        GROUP_READ GROUP_EXECUTE
        WORLD_READ WORLD_EXECUTE
      COMPONENT "${component}")
  elseif("${type}" STREQUAL "TARGET_LIBRARY")
    install(
      TARGETS "${src}" LIBRARY 
      DESTINATION "${dest}"
      PERMISSIONS
        OWNER_READ OWNER_WRITE OWNER_EXECUTE
        GROUP_READ GROUP_EXECUTE
        WORLD_READ WORLD_EXECUTE
      COMPONENT "${component}")
  elseif("${type}" STREQUAL "TARGET_RUNTIME")
    install(
      TARGETS "${src}" RUNTIME 
      DESTINATION "${dest}"
      PERMISSIONS
        OWNER_READ OWNER_WRITE OWNER_EXECUTE
        GROUP_READ GROUP_EXECUTE
        WORLD_READ WORLD_EXECUTE
      COMPONENT "${component}")
  elseif("${type}" STREQUAL "FILE")
    install(
      FILES "${src}"
      DESTINATION "${dest}"
      COMPONENT "${component}")
  elseif("${type}" STREQUAL "DIRECTORY")
    install(
      DIRECTORY "${src}"
      COMPONENT "${component}"
      DESTINATION "${dest}"
      FILES_MATCHING
      PATTERN *
      PERMISSIONS
        OWNER_READ OWNER_WRITE OWNER_EXECUTE
        GROUP_READ GROUP_EXECUTE
        WORLD_READ WORLD_EXECUTE)
  endif()
endfunction()

macro(ext_apply_patch proj_name proj_path patch_file)

  execute_process(
    COMMAND ${CMAKE_COMMAND} -E echo "Checking if ${proj_name} patch needs to be applied..." 
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/${proj_path}
  )

  execute_process(
    COMMAND git apply --ignore-space-change --ignore-whitespace ${patch_file}
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/${proj_path}
  )

  execute_process(
    COMMAND echo "${proj_name} Patch applied."
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/${proj_path}
  )

endmacro()
