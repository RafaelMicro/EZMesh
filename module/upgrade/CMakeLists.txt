add_executable(ezmesh-upgrade 
  src/ezmesh-upgrade.c 
  src/fsm.c 
  src/progressbar/progressbar.c 
  src/progressbar/statusbar.c
  src/termcap/termcap.c
)

target_link_libraries(ezmesh-upgrade
  ezmesh
  util
  pthread
  # ncurses
)

get_target_property(EZMESH_SOURCE_DIR ezmesh SOURCE_DIR)
target_include_directories(ezmesh-upgrade PRIVATE 
  ${EZMESH_SOURCE_DIR}/library
  src/include
  src/include/progressbar
  src/include/termcap
)

ext_install( "TARGET_RUNTIME" ezmesh-upgrade "bin" ezmesh-upgrade)

# set(DEFAULT_EZMESH_INSTALL_PATH /var/lib/ezmesh)
# if(NOT CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
#   install(DIRECTORY DESTINATION ${CMAKE_INSTALL_PREFIX}/${DEFAULT_EZMESH_INSTALL_PATH} COMPONENT ezmesh-upgrade)
# else()
#   install(DIRECTORY DESTINATION ${DEFAULT_EZMESH_INSTALL_PATH} COMPONENT ezmesh-upgrade)
# endif()