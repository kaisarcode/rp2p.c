# rp2p - RedP2P
# KaisarCode - CMake build configuration
# SPDX-License-Identifier: GPL-3.0-or-later

cmake_minimum_required(VERSION 3.14)
project(rp2p LANGUAGES C)
set(CMAKE_C_STANDARD 11)

if(NOT DEFINED RP2P_BUILD_VERSION)
    set(RP2P_BUILD_VERSION 0)
endif()

option(RP2P_BUILD_TESTS "Build rp2p tests" OFF)

set(RP2P_TEST_EXTERNAL_ARTIFACTS OFF)
if(RP2P_BUILD_TESTS AND RP2P_TEST_SHARED_LIBRARY)
    set(RP2P_TEST_EXTERNAL_ARTIFACTS ON)
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

# Shared library
set(RP2P_SOURCES
    src/librp2p.c
    lib/monocypher/monocypher.c
    lib/kcp/ikcp.c
)

set_source_files_properties(src/librp2p.c PROPERTIES
    COMPILE_DEFINITIONS RP2P_BUILD_VERSION=${RP2P_BUILD_VERSION}
)

if(NOT RP2P_TEST_EXTERNAL_ARTIFACTS)
    add_library(rp2p_shared SHARED ${RP2P_SOURCES})
    set_target_properties(rp2p_shared PROPERTIES OUTPUT_NAME "rp2p")
    target_include_directories(rp2p_shared PRIVATE src lib/monocypher lib/kcp)

    # Static library
    add_library(rp2p_static STATIC ${RP2P_SOURCES})
    set_target_properties(rp2p_static PROPERTIES OUTPUT_NAME "rp2p")
    target_include_directories(rp2p_static PRIVATE src lib/monocypher lib/kcp)

    # Binary: rp2p
    if(APPLE)
        add_executable(rp2p src/rp2p.c ${RP2P_SOURCES})
    else()
        add_executable(rp2p src/rp2p.c)
        target_link_libraries(rp2p PRIVATE rp2p_static)
    endif()
    target_include_directories(rp2p PRIVATE src lib/monocypher lib/kcp)

    if(UNIX AND NOT ANDROID AND NOT APPLE)
        target_link_libraries(rp2p_shared pthread m)
        target_link_libraries(rp2p_static pthread m)
        target_link_libraries(rp2p PRIVATE pthread m)
    elseif(MINGW)
        target_link_libraries(rp2p_shared ws2_32 bcrypt)
        target_link_libraries(rp2p_static ws2_32 bcrypt)
        target_link_libraries(rp2p PRIVATE ws2_32 bcrypt)
    elseif(MSVC)
        target_link_libraries(rp2p_shared ws2_32 bcrypt)
        target_link_libraries(rp2p_static ws2_32 bcrypt)
        target_link_libraries(rp2p PRIVATE ws2_32 bcrypt)
    endif()
endif()

if(RP2P_BUILD_TESTS)
    enable_testing()

    if(RP2P_TEST_SHARED_LIBRARY)
        add_library(rp2p_test_shared SHARED IMPORTED)
        set_target_properties(rp2p_test_shared PROPERTIES
            IMPORTED_LOCATION "${RP2P_TEST_SHARED_LIBRARY}"
        )
        if(RP2P_TEST_IMPORT_LIBRARY)
            set_target_properties(rp2p_test_shared PROPERTIES
                IMPORTED_IMPLIB "${RP2P_TEST_IMPORT_LIBRARY}"
            )
        endif()
    else()
        set(RP2P_TEST_SHARED_TARGET rp2p_shared)
    endif()

    if(TARGET rp2p_test_shared)
        set(RP2P_TEST_SHARED_TARGET rp2p_test_shared)
    endif()

    add_executable(rp2p_contract_test src/test.c)
    target_include_directories(rp2p_contract_test PRIVATE src)
    target_link_libraries(rp2p_contract_test PRIVATE ${RP2P_TEST_SHARED_TARGET})

    if(UNIX AND NOT ANDROID AND NOT APPLE)
        target_link_libraries(rp2p_contract_test PRIVATE pthread m)
    elseif(MINGW)
        target_link_libraries(rp2p_contract_test PRIVATE ws2_32 bcrypt)
    elseif(MSVC)
        target_link_libraries(rp2p_contract_test PRIVATE ws2_32 bcrypt)
    endif()

    add_custom_command(TARGET rp2p_contract_test POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            $<TARGET_FILE:${RP2P_TEST_SHARED_TARGET}>
            $<TARGET_FILE_DIR:rp2p_contract_test>
    )

    add_test(NAME library-rp2p_options_default COMMAND rp2p_contract_test rp2p_options_default)
    add_test(NAME library-rp2p_options_load_env COMMAND rp2p_contract_test rp2p_options_load_env)
    add_test(NAME library-rp2p_options_load_env_invalid COMMAND rp2p_contract_test rp2p_options_load_env_invalid)
    add_test(NAME library-rp2p_options_free COMMAND rp2p_contract_test rp2p_options_free)
    add_test(NAME library-rp2p_open COMMAND rp2p_contract_test rp2p_open)
    add_test(NAME library-rp2p_close COMMAND rp2p_contract_test rp2p_close)
    add_test(NAME library-rp2p_stop COMMAND rp2p_contract_test rp2p_stop)
    add_test(NAME library-rp2p_version COMMAND rp2p_contract_test rp2p_version)
    add_test(NAME library-rp2p_strerror COMMAND rp2p_contract_test rp2p_strerror)
    add_test(NAME library-rp2p_is_valid_id COMMAND rp2p_contract_test rp2p_is_valid_id)
    add_test(NAME library-rp2p_is_valid_pass_token COMMAND rp2p_contract_test rp2p_is_valid_pass_token)
    add_test(NAME library-rp2p_serve_index COMMAND rp2p_contract_test rp2p_serve_index)
    add_test(NAME library-rp2p_wait COMMAND rp2p_contract_test rp2p_wait)
    add_test(NAME library-rp2p_connect COMMAND rp2p_contract_test rp2p_connect)
    add_test(NAME library-rp2p_udp_tunnel COMMAND rp2p_contract_test rp2p_udp_tunnel)
    add_test(NAME library-rp2p_tcp_stream COMMAND rp2p_contract_test rp2p_tcp_stream)
    add_test(NAME library-rp2p_deregister COMMAND rp2p_contract_test rp2p_deregister)
    add_test(NAME library-rp2p_list_publishers COMMAND rp2p_contract_test rp2p_list_publishers)
    add_test(NAME library-rp2p_get_error COMMAND rp2p_contract_test rp2p_get_error)
    add_test(NAME library-rp2p_set_seats COMMAND rp2p_contract_test rp2p_set_seats)
    add_test(NAME library-rp2p_set_pow COMMAND rp2p_contract_test rp2p_set_pow)
    add_test(NAME library-rp2p_set_port COMMAND rp2p_contract_test rp2p_set_port)
    add_test(NAME library-rp2p_set_protocol COMMAND rp2p_contract_test rp2p_set_protocol)
    add_test(NAME library-rp2p_set_pass COMMAND rp2p_contract_test rp2p_set_pass)
    add_test(NAME library-rp2p_set_vip COMMAND rp2p_contract_test rp2p_set_vip)
    add_test(NAME library-rp2p_set_sweep COMMAND rp2p_contract_test rp2p_set_sweep)
    add_test(NAME library-rp2p_set_stun_url COMMAND rp2p_contract_test rp2p_set_stun_url)
    set_tests_properties(library-rp2p_serve_index PROPERTIES TIMEOUT 30)
    set_tests_properties(library-rp2p_wait PROPERTIES TIMEOUT 30)
    set_tests_properties(library-rp2p_connect PROPERTIES TIMEOUT 30)
    set_tests_properties(
        library-rp2p_udp_tunnel
        library-rp2p_tcp_stream
        PROPERTIES TIMEOUT 45
    )
    set_tests_properties(library-rp2p_deregister PROPERTIES TIMEOUT 30)
    set_tests_properties(library-rp2p_list_publishers PROPERTIES TIMEOUT 30)
endif()
