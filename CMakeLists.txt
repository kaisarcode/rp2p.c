# p2p — KaisarCode P2P
# KaisarCode — CMake build configuration
# SPDX-License-Identifier: GPL-3.0-or-later

cmake_minimum_required(VERSION 3.14)
project(p2p LANGUAGES C)
set(CMAKE_C_STANDARD 11)

if(NOT DEFINED P2P_BUILD_VERSION)
    set(P2P_BUILD_VERSION 0)
endif()

if(NOT MSVC)
    add_compile_options(-O3 -Wall -Wextra -Werror)
    add_definitions(-D_GNU_SOURCE)
else()
    add_compile_options(/O2 /W3 /WX)
endif()

# Shared library (for external use)
set(P2P_SOURCES
    src/libkcp2p.c
    lib/monocypher/monocypher.c
)

set_source_files_properties(src/libkcp2p.c PROPERTIES
    COMPILE_DEFINITIONS KC_P2P_BUILD_VERSION=${P2P_BUILD_VERSION}
)

add_library(kcp2p_shared SHARED ${P2P_SOURCES})
set_target_properties(kcp2p_shared PROPERTIES OUTPUT_NAME "kcp2p")
target_include_directories(kcp2p_shared PRIVATE src lib/monocypher)

# Static library (for external use)
add_library(kcp2p_static STATIC ${P2P_SOURCES})
set_target_properties(kcp2p_static PROPERTIES OUTPUT_NAME "kcp2p")
target_include_directories(kcp2p_static PRIVATE src lib/monocypher)

# Binary: p2p
add_executable(p2p src/p2p.c ${P2P_SOURCES})
target_include_directories(p2p PRIVATE src lib/monocypher)

if(UNIX AND NOT ANDROID)
    target_link_libraries(kcp2p_shared pthread m)
    target_link_libraries(kcp2p_static pthread m)
    target_link_libraries(p2p pthread m)
elseif(MINGW)
    target_link_libraries(kcp2p_shared ws2_32 bcrypt)
    target_link_libraries(kcp2p_static ws2_32 bcrypt)
    target_link_libraries(p2p ws2_32 bcrypt)
elseif(MSVC)
    target_link_libraries(kcp2p_shared bcrypt)
    target_link_libraries(kcp2p_static bcrypt)
    target_link_libraries(p2p bcrypt)
endif()
