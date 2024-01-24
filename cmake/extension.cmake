
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

function(ext_config define val)
  set(${define} ${val})
endfunction()

function(ext_config_ifndef define val)
  if(NOT DEFINED ${define})
    set(${define} ${val})
  endif()
endfunction()

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
