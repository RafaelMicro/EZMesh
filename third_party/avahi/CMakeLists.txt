
add_library(avahi-client SHARED)
# target_stds(avahi-client C 99 POSIX 2008)
target_link_libraries(avahi-client PRIVATE Interface::Warnings)
target_include_directories(avahi-client PRIVATE 
    "${CMAKE_BINARY_DIR}/third_party/dbus"
    "${CMAKE_SOURCE_DIR}/third_party/dbus"
    "${CMAKE_CURRENT_SOURCE_DIR}"
)
target_compile_definitions(avahi-client  PRIVATE -DHAVE_DBUS_CONNECTION_CLOSE=1)
target_sources(avahi-client PRIVATE 
    avahi-client/browser.c
    avahi-client/client.h
    avahi-client/entrygroup.c
    avahi-client/lookup.h
    avahi-client/publish.h
    avahi-client/xdg-config.c 
    avahi-client/check-nss.c
    avahi-client/client.c
    avahi-client/internal.h
    avahi-client/resolver.c
    avahi-client/xdg-config.h
    "${CMAKE_BINARY_DIR}/third_party/dbus/config.h")

set_target_properties(avahi-client PROPERTIES PUBLIC_HEADER 
    "${CMAKE_CURRENT_SOURCE_DIR}/avahi-client/client.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/avahi-client/lookup.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/avahi-client/publish.h")

add_library(avahi-common SHARED)
# target_stds(avahi-common C 99 POSIX 2008)
target_link_libraries(avahi-common PRIVATE Interface::Warnings)
target_include_directories(avahi-common PRIVATE 
    "${CMAKE_BINARY_DIR}/third_party/dbus"
    "${CMAKE_SOURCE_DIR}/third_party/dbus"
    "${CMAKE_CURRENT_SOURCE_DIR}"
)
target_sources(avahi-common PRIVATE 
    avahi-common/address.h
    avahi-common/address.c
    avahi-common/dbus-watch-glue.h
    avahi-common/dbus-watch-glue.c
    avahi-common/simple-watch.h
    avahi-common/simple-watch.c
    avahi-common/domain.h
    avahi-common/domain.c
    avahi-common/rlist.h
    avahi-common/rlist.c
    avahi-common/strlst.h
    avahi-common/strlst.c
    avahi-common/timeval.h
    avahi-common/timeval.c
    avahi-common/utf8.h
    avahi-common/utf8.c
    avahi-common/i18n.h
    avahi-common/i18n.c
    avahi-common/malloc.h
    avahi-common/malloc.c
    avahi-common/alternative.h
    avahi-common/alternative.c
    avahi-common/dbus.h
    avahi-common/dbus.c
    avahi-common/error.h
    avahi-common/error.c
    avahi-common/thread-watch.h
    avahi-common/thread-watch.c
    avahi-common/watch.h
    avahi-common/llist.h
    avahi-common/defs.h
    avahi-common/cdecl.h
    avahi-common/gccmacro.h
    "${CMAKE_BINARY_DIR}/third_party/dbus/config.h")

set_target_properties(avahi-common PROPERTIES PUBLIC_HEADER 
    "${CMAKE_CURRENT_SOURCE_DIR}/avahi-common/strlst.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/avahi-common/address.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/avahi-common/alternative.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/avahi-common/domain.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/avahi-common/cdecl.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/avahi-common/defs.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/avahi-common/malloc.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/avahi-common/watch.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/avahi-common/timeval.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/avahi-common/simple-watch.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/avahi-common/thread-watch.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/avahi-common/gccmacro.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/avahi-common/error.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/avahi-common/llist.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/avahi-common/rlist.h")

