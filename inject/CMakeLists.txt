SET(CMAKE_SKIP_RPATH true)
cmake_minimum_required(VERSION 3.0)

include(FindPkgConfig)

pkg_check_modules(LIBNL REQUIRED libnl-3.0>=3.0)
link_directories(${LIBNL_LIBRARY_DIRS})
include_directories(${LIBNL_INCLUDE_DIRS})

pkg_check_modules(LIBNL_ROUTE REQUIRED libnl-route-3.0>=3.0)
link_directories(${LIBNL_ROUTE_LIBRARY_DIRS})
include_directories(${LIBNL_ROUTE_INCLUDE_DIRS})

SET(CMAKE_BUILD_TYPE RELWITHDEBINFO)
SET(CMAKE_C_FLAGS "-Wall -Werror -D_GNU_SOURCE=1")
SET(CMAKE_C_STANDARD 11)

add_executable(titus-inject-metadataproxy titus-inject-metadataproxy.c)
target_link_libraries(titus-inject-metadataproxy "libnl-3.a" "libnl-route-3.a" pthread)

add_executable(titus-nsenter titus-nsenter.c ../tini/src/seccomp_fd_notify.c)
target_link_libraries(titus-nsenter pthread)
