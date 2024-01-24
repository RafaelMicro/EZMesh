add_executable(ezmesh-zbbackup src/ezmesh-zbbackup.c src/fsm.c)
target_link_libraries(ezmesh-zbbackup ezmesh util pthread)

get_target_property(EZMESH_SOURCE_DIR ezmesh SOURCE_DIR)
target_include_directories(ezmesh-zbbackup PRIVATE 
  ${EZMESH_SOURCE_DIR}/library
  src/include
)

ext_install("TARGET_RUNTIME" ezmesh-zbbackup "bin" ezmesh-zbbackup)

# set(DEFAULT_EZMESH_ZBBU_INSTALL_PATH /var/lib/ezmesh-zbbackup)
# if(NOT CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
#   install(DIRECTORY DESTINATION ${CMAKE_INSTALL_PREFIX}/${DEFAULT_EZMESH_ZBBU_INSTALL_PATH} COMPONENT ezmesh-zbbackup)
# else()
#   install(DIRECTORY DESTINATION ${DEFAULT_EZMESH_ZBBU_INSTALL_PATH} COMPONENT ezmesh-zbbackup)
# endif()