cmake_minimum_required(VERSION 3.20)
project(nocturne-kx VERSION 3.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Compiler flags
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Wpedantic")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -g -O0 -fsanitize=address,undefined")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O3 -DNDEBUG")

# Find libsodium
find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED libsodium)

# Main executable
add_executable(nocturne-kx nocturne-kx.cpp)
target_include_directories(nocturne-kx PRIVATE ${SODIUM_INCLUDE_DIRS})
target_link_libraries(nocturne-kx ${SODIUM_LIBRARIES})
target_compile_options(nocturne-kx PRIVATE ${SODIUM_CFLAGS_OTHER})

# Tests
option(BUILD_TESTS "Build tests" ON)
if(BUILD_TESTS)
    enable_testing()
    
    # Find Catch2
    find_package(Catch2 3 REQUIRED)
    
    # Test executable
    add_executable(nocturne-tests tests/test_main.cpp)
    target_link_libraries(nocturne-tests PRIVATE Catch2::Catch2 ${SODIUM_LIBRARIES})
    target_include_directories(nocturne-tests PRIVATE ${SODIUM_INCLUDE_DIRS})
    
    # Include test files
    include(CTest)
    catch_discover_tests(nocturne-tests)
endif()

# Installation
install(TARGETS nocturne-kx DESTINATION bin)
if(BUILD_TESTS)
    install(TARGETS nocturne-tests DESTINATION bin)
endif()

# Fuzzing target
option(BUILD_FUZZER "Build fuzzer" OFF)
if(BUILD_FUZZER)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=fuzzer,address,undefined")
    add_executable(nocturne-fuzzer tests/fuzzer_main.cpp)
    target_link_libraries(nocturne-fuzzer ${SODIUM_LIBRARIES})
    target_include_directories(nocturne-fuzzer PRIVATE ${SODIUM_INCLUDE_DIRS})
endif()
