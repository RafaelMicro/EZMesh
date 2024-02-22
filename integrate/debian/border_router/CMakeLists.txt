set(CMAKE_INSTALL_DEFAULT_COMPONENT_NAME ez-otbr)
include("${CMAKE_CURRENT_SOURCE_DIR}/cmake/options.cmake")

ext_set_config_file_with_gen(debconf/setup)
ext_set_config_file_with_gen(debconf/services/ez-otbr)
ext_set_config_file(debconf/services/ez-otbr.service)

ext_install("DIRECTORY" ${CMAKE_CURRENT_SOURCE_DIR}/debconf/services/otbr-agent.service.d /etc/systemd/system ez-otbr)
ext_install("DIRECTORY" ${CMAKE_CURRENT_SOURCE_DIR}/debconf/services/otbr-nat44.service.d /etc/systemd/system ez-otbr)
ext_install("DIRECTORY" ${CMAKE_CURRENT_SOURCE_DIR}/debconf/services/otbr-firewall.service.d /etc/systemd/system ez-otbr)
ext_install("FILE" ${CMAKE_CURRENT_BINARY_DIR}/debconf/services/ez-otbr.service ${OTBR_SYSTEMD_UNIT_DIR} ez-otbr)
ext_install("FILE" ${CMAKE_CURRENT_BINARY_DIR}/debconf/services/ez-otbr /etc/default ez-otbr)
ext_install("EXECUTE" ${CMAKE_CURRENT_BINARY_DIR}/debconf/setup ${CMAKE_CURRENT_BINARY_DIR} ez-otbr)
