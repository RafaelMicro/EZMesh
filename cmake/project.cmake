set(EZMESHD_VER "1.0.0")
set(EZMESHD_LIB "1")
set(EZMESHD_POTOCOL "3")

show_banner(${EZMESHD_VER})

set(PROJECT_VER "")
get_git_hash(PROJECT_VER)
message("Current project git version: ${PROJECT_VER}")
project(RAFAEL_HOST_SDK LANGUAGES C CXX)
