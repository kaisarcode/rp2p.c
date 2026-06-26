# rp2p - RedP2P
# KaisarCode - CMake build configuration
# SPDX-License-Identifier: GPL-3.0-or-later

cmake_minimum_required(VERSION 3.14)
project(rp2p LANGUAGES C)
set(CMAKE_C_STANDARD 11)

if(NOT DEFINED RP2P_BUILD_VERSION)
    set(RP2P_BUILD_VERSION 0)
endif()

if(NOT MSVC)
    add_compile_options(-O3 -Wall -Wextra -Werror)
    if(CMAKE_SYSTEM_NAME STREQUAL "iOS")
        add_compile_options(-Wno-unused-command-line-argument)
    endif()
    add_definitions(-D_GNU_SOURCE)
else()
    add_compile_options(/O2 /W3 /WX)
endif()

# Shared library (for external use)
set(RP2P_SOURCES
    src/librp2p.c
    lib/monocypher/monocypher.c
)

set_source_files_properties(src/librp2p.c PROPERTIES
    COMPILE_DEFINITIONS RP2P_BUILD_VERSION=${RP2P_BUILD_VERSION}
)

add_library(rp2p_shared SHARED ${RP2P_SOURCES})
set_target_properties(rp2p_shared PROPERTIES OUTPUT_NAME "rp2p")
target_include_directories(rp2p_shared PRIVATE src lib/monocypher)

# Static library (for external use)
add_library(rp2p_static STATIC ${RP2P_SOURCES})
set_target_properties(rp2p_static PROPERTIES OUTPUT_NAME "rp2p")
target_include_directories(rp2p_static PRIVATE src lib/monocypher)

# Binary: rp2p
add_executable(rp2p src/rp2p.c ${RP2P_SOURCES})
target_include_directories(rp2p PRIVATE src lib/monocypher)

if(UNIX AND NOT ANDROID AND NOT APPLE)
    target_link_libraries(rp2p_shared pthread m)
    target_link_libraries(rp2p_static pthread m)
    target_link_libraries(rp2p pthread m)
elseif(MINGW)
    target_link_libraries(rp2p_shared ws2_32 bcrypt)
    target_link_libraries(rp2p_static ws2_32 bcrypt)
    target_link_libraries(rp2p ws2_32 bcrypt)
elseif(MSVC)
    target_link_libraries(rp2p_shared ws2_32 bcrypt)
    target_link_libraries(rp2p_static ws2_32 bcrypt)
    target_link_libraries(rp2p ws2_32 bcrypt)
endif()
