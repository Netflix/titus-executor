SET(CMAKE_SKIP_RPATH true)
cmake_minimum_required(VERSION 3.0)

include(FindPkgConfig)

link_directories($ENV{TINI_LIBRARY_DIR})
include_directories($ENV{TINI_INCLUDE_DIR})

SET(CMAKE_BUILD_TYPE RELWITHDEBINFO)
SET(CMAKE_C_FLAGS "-Wall -Werror -D_GNU_SOURCE=1")
SET(CMAKE_C_STANDARD 11)

add_executable(titus-nsenter titus-nsenter.c)
target_link_libraries(titus-nsenter pthread seccomp-fd-notify cap)

add_executable(titus-mnt titus-mnt.c)
