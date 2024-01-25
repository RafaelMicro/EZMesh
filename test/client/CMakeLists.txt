add_executable(ez-client client.c)
target_link_libraries(ez-client ezmesh util pthread)

get_target_property(EZMESH_SOURCE_DIR ezmesh SOURCE_DIR)
target_include_directories(ez-client PRIVATE ${EZMESH_SOURCE_DIR}/library)

ext_install("TARGET_RUNTIME" ez-client "bin" ez-client)

