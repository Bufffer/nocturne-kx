cmake_minimum_required(VERSION 3.20)
project(nocturne-kx VERSION 3.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Compiler flags
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Wpedantic")
# Debug flags are set per-target to avoid conflicts with memory sanitizer
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O3 -DNDEBUG")

# Platform-specific flags for side-channel protection
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|i386")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -msse2")
    endif()
endif()

# Find libsodium
find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED libsodium)

# Main executable (only build when not building fuzzer)
if(NOT BUILD_FUZZER)
    add_executable(nocturne-kx nocturne-kx.cpp src/double_ratchet.hpp src/handshake.hpp src/transport.hpp src/pkcs11_wrapper.cpp)
    target_include_directories(nocturne-kx PRIVATE ${SODIUM_INCLUDE_DIRS})
    target_link_libraries(nocturne-kx ${SODIUM_LIBRARIES})
    target_compile_options(nocturne-kx PRIVATE ${SODIUM_CFLAGS_OTHER})
endif()

# Tests
option(BUILD_TESTS "Build tests" OFF)
if(BUILD_TESTS)
    enable_testing()
    
    # Find Catch2
    find_package(Catch2 3 QUIET)
    if(Catch2_FOUND)
        # Test executable
        add_executable(nocturne-tests tests/test_main.cpp)
        target_link_libraries(nocturne-tests PRIVATE Catch2::Catch2 ${SODIUM_LIBRARIES})
        target_include_directories(nocturne-tests PRIVATE ${SODIUM_INCLUDE_DIRS})
        
        # Include test files
        include(CTest)
        catch_discover_tests(nocturne-tests)
    else()
        message(WARNING "Catch2 not found, tests will be disabled")
    endif()
endif()

# Installation
if(NOT BUILD_FUZZER)
    install(TARGETS nocturne-kx DESTINATION bin)
endif()
if(BUILD_TESTS)
    install(TARGETS nocturne-tests DESTINATION bin)
endif()

# Fuzzing target
option(BUILD_FUZZER "Build fuzzer" OFF)
if(BUILD_FUZZER)
    # Disable compiler test for fuzzer to avoid main() conflicts
    set(CMAKE_CXX_COMPILER_WORKS TRUE)
    
    add_executable(nocturne-fuzzer tests/fuzzer_main.cpp)
    target_link_libraries(nocturne-fuzzer ${SODIUM_LIBRARIES})
    target_include_directories(nocturne-fuzzer PRIVATE ${SODIUM_INCLUDE_DIRS})
    # Fuzzer sanitizer flags are set via CMAKE_CXX_FLAGS in workflow
endif()
