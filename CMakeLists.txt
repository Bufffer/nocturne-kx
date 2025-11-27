cmake_minimum_required(VERSION 3.20)
project(nocturne-kx VERSION 4.0.0 LANGUAGES CXX C)  # Added C for liboqs

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ============================================================================
# OPTIONS
# ============================================================================
option(ENABLE_PQC "Enable Post-Quantum Cryptography support" ON)
option(BUILD_TESTS "Build tests" OFF)
option(BUILD_FUZZER "Build fuzzer" OFF)
option(BUILD_LIBOQS "Build liboqs from source (auto-detected)" OFF)

# ============================================================================
# COMPILER FLAGS
# ============================================================================
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Wpedantic")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O3 -DNDEBUG")

# Platform-specific flags for side-channel protection
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|i386")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -msse2")
    endif()
endif()

# ============================================================================
# DEPENDENCIES
# ============================================================================

# libsodium (required)
if(WIN32)
    # Windows: Try vcpkg or manual paths
    find_library(SODIUM_LIBRARY NAMES sodium libsodium PATHS
        "C:/vcpkg/installed/x64-windows/lib"
        "$ENV{VCPKG_ROOT}/installed/x64-windows/lib"
    )
    find_path(SODIUM_INCLUDE_DIR sodium.h PATHS
        "C:/vcpkg/installed/x64-windows/include"
        "$ENV{VCPKG_ROOT}/installed/x64-windows/include"
    )

    if(SODIUM_LIBRARY AND SODIUM_INCLUDE_DIR)
        set(SODIUM_LIBRARIES ${SODIUM_LIBRARY})
        set(SODIUM_INCLUDE_DIRS ${SODIUM_INCLUDE_DIR})
        message(STATUS "Found libsodium: ${SODIUM_LIBRARY}")
    else()
        message(WARNING "libsodium not found on Windows. Install via vcpkg:")
        message(WARNING "  vcpkg install libsodium:x64-windows")
    endif()
else()
    # Unix: Use pkg-config
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(SODIUM REQUIRED libsodium)
endif()

# liboqs (Post-Quantum Cryptography) - optional but recommended
if(ENABLE_PQC)
    # First try to find system-installed liboqs
    find_library(LIBOQS_LIBRARY NAMES oqs PATHS
        "C:/Users/Maxval/Desktop/liboqs/build/lib/Release"
        "C:/Users/Maxval/Desktop/liboqs/build/lib"
        "/usr/local/lib"
        "/usr/lib"
    )

    find_path(LIBOQS_INCLUDE_DIR oqs/oqs.h PATHS
        "C:/Users/Maxval/Desktop/liboqs/build/include"
        "/usr/local/include"
        "/usr/include"
    )

    if(LIBOQS_LIBRARY AND LIBOQS_INCLUDE_DIR)
        message(STATUS "Found liboqs: ${LIBOQS_LIBRARY}")
        message(STATUS "liboqs include: ${LIBOQS_INCLUDE_DIR}")
        set(LIBOQS_FOUND TRUE)
    else()
        message(WARNING "liboqs not found. PQC support will be disabled.")
        message(WARNING "To enable PQC, install liboqs or set BUILD_LIBOQS=ON")
        set(ENABLE_PQC OFF)
    endif()
endif()

# ============================================================================
# SOURCE FILES
# ============================================================================

# Core sources
set(NOCTURNE_CORE_SOURCES
    nocturne-kx.cpp
    src/double_ratchet.hpp
    src/handshake.hpp
    src/transport.hpp
    src/pkcs11_wrapper.cpp
)

# PQC sources (conditionally compiled)
if(ENABLE_PQC)
    set(NOCTURNE_PQC_SOURCES
        src/pqc/kem/kem_interface.cpp
        # ML-KEM wrapper will be added next
        # Hybrid KEM will be added next
    )

    add_compile_definitions(NOCTURNE_ENABLE_PQC)
else()
    set(NOCTURNE_PQC_SOURCES "")
endif()

# ============================================================================
# MAIN EXECUTABLE
# ============================================================================
if(NOT BUILD_FUZZER)
    add_executable(nocturne-kx ${NOCTURNE_CORE_SOURCES} ${NOCTURNE_PQC_SOURCES})

    # Include directories
    target_include_directories(nocturne-kx PRIVATE
        ${SODIUM_INCLUDE_DIRS}
        ${CMAKE_CURRENT_SOURCE_DIR}/src
    )

    if(ENABLE_PQC)
        target_include_directories(nocturne-kx PRIVATE ${LIBOQS_INCLUDE_DIR})
    endif()

    # Link libraries
    target_link_libraries(nocturne-kx ${SODIUM_LIBRARIES})

    if(ENABLE_PQC)
        target_link_libraries(nocturne-kx ${LIBOQS_LIBRARY})

        # Windows: Add bcrypt for liboqs random number generation
        if(WIN32)
            target_link_libraries(nocturne-kx bcrypt)
        endif()
    endif()

    # Compile options
    target_compile_options(nocturne-kx PRIVATE ${SODIUM_CFLAGS_OTHER})
endif()

# ============================================================================
# TESTS
# ============================================================================
if(BUILD_TESTS)
    enable_testing()

    # Find Catch2
    find_package(Catch2 3 QUIET)
    if(Catch2_FOUND)
        # Test executable
        add_executable(nocturne-tests tests/test_main.cpp)
        target_link_libraries(nocturne-tests PRIVATE Catch2::Catch2 ${SODIUM_LIBRARIES})
        target_include_directories(nocturne-tests PRIVATE ${SODIUM_INCLUDE_DIRS})

        # Register tests
        include(CTest)
        if(COMMAND catch_discover_tests)
            catch_discover_tests(nocturne-tests)
        else()
            add_test(NAME nocturne-tests COMMAND nocturne-tests)
        endif()
    else()
        message(WARNING "Catch2 not found, tests will be disabled")
    endif()

    # PQC-specific tests
    if(ENABLE_PQC)
        add_executable(pqc-basic-test tests/pqc/test_liboqs_basic.cpp)
        target_include_directories(pqc-basic-test PRIVATE ${LIBOQS_INCLUDE_DIR})
        target_link_libraries(pqc-basic-test ${LIBOQS_LIBRARY})

        if(WIN32)
            target_link_libraries(pqc-basic-test bcrypt)
        endif()

        add_test(NAME pqc-basic-test COMMAND pqc-basic-test)

        message(STATUS "PQC tests enabled")
    endif()
endif()

# ============================================================================
# FUZZING
# ============================================================================
if(BUILD_FUZZER)
    set(CMAKE_CXX_COMPILER_WORKS TRUE)

    add_executable(nocturne-fuzzer tests/fuzzer_main.cpp)
    target_link_libraries(nocturne-fuzzer ${SODIUM_LIBRARIES})
    target_include_directories(nocturne-fuzzer PRIVATE ${SODIUM_INCLUDE_DIRS})
endif()

# ============================================================================
# INSTALLATION
# ============================================================================
if(NOT BUILD_FUZZER)
    install(TARGETS nocturne-kx DESTINATION bin)

    # Install PQC headers for library usage
    if(ENABLE_PQC)
        install(DIRECTORY src/pqc/
                DESTINATION include/nocturne/pqc
                FILES_MATCHING PATTERN "*.hpp")
    endif()
endif()

if(BUILD_TESTS)
    if(TARGET nocturne-tests)
        install(TARGETS nocturne-tests DESTINATION bin)
    endif()
    if(ENABLE_PQC AND TARGET pqc-basic-test)
        install(TARGETS pqc-basic-test DESTINATION bin)
    endif()
endif()

# ============================================================================
# BUILD SUMMARY
# ============================================================================
message(STATUS "")
message(STATUS "╔═══════════════════════════════════════════════════════╗")
message(STATUS "║          Nocturne-KX Build Configuration             ║")
message(STATUS "╚═══════════════════════════════════════════════════════╝")
message(STATUS "Version:           ${PROJECT_VERSION}")
message(STATUS "Build Type:        ${CMAKE_BUILD_TYPE}")
message(STATUS "Compiler:          ${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}")
message(STATUS "")
message(STATUS "Features:")
message(STATUS "  Post-Quantum:    ${ENABLE_PQC}")
if(ENABLE_PQC)
    message(STATUS "  liboqs:          ${LIBOQS_LIBRARY}")
endif()
message(STATUS "  Tests:           ${BUILD_TESTS}")
message(STATUS "  Fuzzer:          ${BUILD_FUZZER}")
message(STATUS "")
message(STATUS "═══════════════════════════════════════════════════════")
