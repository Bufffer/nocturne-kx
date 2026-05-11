cmake_minimum_required(VERSION 3.20)
project(nocturne-kx VERSION 4.0.0 LANGUAGES CXX C)  # Added C for liboqs

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ============================================================================
# OPTIONS
# ============================================================================
option(ENABLE_PQC "Enable Post-Quantum Cryptography support" ON)
option(ENABLE_TLS_TRANSPORT "Enable TCP/TLS transport adapter (OpenSSL)" ON)
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

# OpenSSL (TLS transport adapter) - optional
# When found, src/tcp_tls_transport.hpp can be used and the
# tcp-tls-transport-test target is wired up. The main CLI does not yet
# import the TLS transport, so OpenSSL is not linked into nocturne-kx.
if(ENABLE_TLS_TRANSPORT)
    find_package(OpenSSL QUIET)
    if(OpenSSL_FOUND)
        message(STATUS "Found OpenSSL: ${OPENSSL_VERSION} (${OPENSSL_SSL_LIBRARY})")
        add_compile_definitions(NOCTURNE_ENABLE_TLS_TRANSPORT)
    else()
        message(STATUS "OpenSSL not found; TLS transport adapter disabled.")
        set(ENABLE_TLS_TRANSPORT OFF)
    endif()
endif()

# liboqs (Post-Quantum Cryptography) - optional but recommended
# Override discovery with -DLIBOQS_ROOT=<path> or the LIBOQS_ROOT env var.
if(ENABLE_PQC)
    set(LIBOQS_ROOT "" CACHE PATH "Optional root of a prebuilt liboqs install (contains include/ and lib/)")
    if(NOT LIBOQS_ROOT AND DEFINED ENV{LIBOQS_ROOT})
        set(LIBOQS_ROOT "$ENV{LIBOQS_ROOT}")
    endif()

    set(_LIBOQS_HINT_LIB_DIRS "")
    set(_LIBOQS_HINT_INC_DIRS "")
    if(LIBOQS_ROOT)
        list(APPEND _LIBOQS_HINT_LIB_DIRS
            "${LIBOQS_ROOT}/lib"
            "${LIBOQS_ROOT}/lib/Release"
            "${LIBOQS_ROOT}/build/lib"
            "${LIBOQS_ROOT}/build/lib/Release"
        )
        list(APPEND _LIBOQS_HINT_INC_DIRS
            "${LIBOQS_ROOT}/include"
            "${LIBOQS_ROOT}/build/include"
        )
    endif()

    # First try to find system-installed (or LIBOQS_ROOT-pointed) liboqs.
    find_library(LIBOQS_LIBRARY NAMES oqs
        HINTS ${_LIBOQS_HINT_LIB_DIRS}
        PATHS "/usr/local/lib" "/usr/lib"
    )

    find_path(LIBOQS_INCLUDE_DIR oqs/oqs.h
        HINTS ${_LIBOQS_HINT_INC_DIRS}
        PATHS "/usr/local/include" "/usr/include"
    )

    if(LIBOQS_LIBRARY AND LIBOQS_INCLUDE_DIR)
        message(STATUS "Found system liboqs: ${LIBOQS_LIBRARY}")
        message(STATUS "liboqs include: ${LIBOQS_INCLUDE_DIR}")
        set(LIBOQS_FOUND TRUE)
    else()
        # If not found, build liboqs from source using FetchContent
        message(STATUS "System liboqs not found. Building from source...")
        include(FetchContent)

        FetchContent_Declare(
            liboqs
            GIT_REPOSITORY https://github.com/open-quantum-safe/liboqs.git
            GIT_TAG        0.12.0  # Latest stable release
            GIT_SHALLOW    TRUE
        )

        # Configure liboqs build options
        set(OQS_USE_OPENSSL OFF CACHE BOOL "Use OpenSSL" FORCE)
        set(OQS_BUILD_ONLY_LIB ON CACHE BOOL "Build only library" FORCE)
        set(OQS_DIST_BUILD OFF CACHE BOOL "Distribution build" FORCE)
        set(OQS_ENABLE_TEST_CONSTANT_TIME OFF CACHE BOOL "Disable constant time tests" FORCE)

        # Fetch and build liboqs
        FetchContent_MakeAvailable(liboqs)

        # Set variables for linking
        set(LIBOQS_LIBRARY oqs)
        # Include both build directory (generated headers) and source directory
        set(LIBOQS_INCLUDE_DIR ${liboqs_BINARY_DIR}/include ${liboqs_SOURCE_DIR}/src)
        set(LIBOQS_FOUND TRUE)

        message(STATUS "liboqs built from source successfully")
    endif()
endif()

# ============================================================================
# SOURCE FILES
# ============================================================================

# Core sources
# Note: kem_interface.cpp and kem_factory.cpp are always compiled because the
# CLI links against KEMFactory unconditionally (it's the dispatch point for
# --kem x25519|hybrid|mlkem). The factory itself gates the PQC backends with
# #ifdef NOCTURNE_ENABLE_PQC and throws a clear error if a PQC algorithm is
# requested in a non-PQC build, so the X25519-only build still works.
set(NOCTURNE_CORE_SOURCES
    nocturne-kx.cpp
    src/double_ratchet.hpp
    src/handshake.hpp
    src/transport.hpp
    src/pkcs11_wrapper.cpp
    src/core/side_channel.cpp
    src/pqc/kem/kem_interface.cpp
    src/pqc/kem/kem_factory.cpp
)

# PQC backend headers are header-only and pulled in via NOCTURNE_ENABLE_PQC.
if(ENABLE_PQC)
    set(NOCTURNE_PQC_SOURCES "")  # mlkem_wrapper.hpp / hybrid_kem.hpp are header-only
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

    # PKCS#11 HSM backend uses dlopen/dlsym (Linux) or LoadLibrary (Windows).
    # CMAKE_DL_LIBS resolves to "dl" on Linux/Alpine and "" on Windows
    # (where kernel32 is auto-linked by MSVC).
    target_link_libraries(nocturne-kx ${CMAKE_DL_LIBS})

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
        # Test executable. Like the fuzzer, test_main.cpp #includes nocturne-kx.cpp
        # whole, so it inherits the encrypt_packet_kem / decrypt_packet_kem
        # references to KEMFactory and needs the KEM sources linked in.
        add_executable(nocturne-tests
            tests/test_main.cpp
            src/core/side_channel.cpp
            src/pqc/kem/kem_interface.cpp
            src/pqc/kem/kem_factory.cpp
        )
        target_link_libraries(nocturne-tests PRIVATE Catch2::Catch2 ${SODIUM_LIBRARIES} ${CMAKE_DL_LIBS})
        target_include_directories(nocturne-tests PRIVATE
            ${SODIUM_INCLUDE_DIRS}
            ${CMAKE_CURRENT_SOURCE_DIR}/src
        )

        # When PQC is on, kem_factory.cpp pulls in mlkem_wrapper.hpp, which
        # includes <oqs/oqs.h>. Mirror the main target's PQC wiring so the
        # test binary can compile and link the PQC backends.
        if(ENABLE_PQC)
            target_include_directories(nocturne-tests PRIVATE ${LIBOQS_INCLUDE_DIR})
            target_link_libraries(nocturne-tests PRIVATE ${LIBOQS_LIBRARY})
            if(WIN32)
                target_link_libraries(nocturne-tests PRIVATE bcrypt)
            endif()
        endif()

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

    # Additional comprehensive test suites
    if(Catch2_FOUND)
        # HSM comprehensive tests
        add_executable(hsm-comprehensive-test
            tests/hsm/test_hsm_comprehensive.cpp
            src/core/side_channel.cpp
        )
        target_link_libraries(hsm-comprehensive-test PRIVATE
            Catch2::Catch2WithMain
            ${SODIUM_LIBRARIES}
        )
        target_include_directories(hsm-comprehensive-test PRIVATE
            ${SODIUM_INCLUDE_DIRS}
            ${CMAKE_CURRENT_SOURCE_DIR}/src
        )
        add_test(NAME hsm-comprehensive-test COMMAND hsm-comprehensive-test)

        # Side-channel protection tests
        add_executable(side-channel-test
            tests/core/test_side_channel.cpp
            src/core/side_channel.cpp
        )
        target_link_libraries(side-channel-test PRIVATE
            Catch2::Catch2WithMain
            ${SODIUM_LIBRARIES}
        )
        target_include_directories(side-channel-test PRIVATE
            ${SODIUM_INCLUDE_DIRS}
            ${CMAKE_CURRENT_SOURCE_DIR}/src
        )
        add_test(NAME side-channel-test COMMAND side-channel-test)

        # Protocol integration tests
        add_executable(protocol-integration-test
            tests/protocol/test_integration.cpp
            src/core/side_channel.cpp
        )
        target_link_libraries(protocol-integration-test PRIVATE
            Catch2::Catch2WithMain
            ${SODIUM_LIBRARIES}
        )
        target_include_directories(protocol-integration-test PRIVATE
            ${SODIUM_INCLUDE_DIRS}
            ${CMAKE_CURRENT_SOURCE_DIR}/src
        )
        add_test(NAME protocol-integration-test COMMAND protocol-integration-test)

        # SIEM connector network transport tests (P2.6) — UDP/TCP loopback
        # round-trip plus stub assertions for unwired transports.
        add_executable(security-siem-test
            tests/security/test_siem_connector.cpp
        )
        target_link_libraries(security-siem-test PRIVATE
            Catch2::Catch2WithMain
            ${SODIUM_LIBRARIES}
        )
        target_include_directories(security-siem-test PRIVATE
            ${SODIUM_INCLUDE_DIRS}
            ${CMAKE_CURRENT_SOURCE_DIR}/src
        )
        if(WIN32)
            target_link_libraries(security-siem-test PRIVATE Ws2_32)
        endif()
        add_test(NAME security-siem-test COMMAND security-siem-test)

        # TCP/TLS transport adapter tests (P2.5) — self-signed cert loopback,
        # mTLS handshake, and clean-close detection.
        if(ENABLE_TLS_TRANSPORT)
            add_executable(tcp-tls-transport-test
                tests/protocol/test_tcp_tls_transport.cpp
            )
            target_link_libraries(tcp-tls-transport-test PRIVATE
                Catch2::Catch2WithMain
                OpenSSL::SSL
                OpenSSL::Crypto
            )
            target_include_directories(tcp-tls-transport-test PRIVATE
                ${CMAKE_CURRENT_SOURCE_DIR}/src
            )
            if(WIN32)
                target_link_libraries(tcp-tls-transport-test PRIVATE Ws2_32)
            endif()
            add_test(NAME tcp-tls-transport-test COMMAND tcp-tls-transport-test)
        endif()

        message(STATUS "Comprehensive test suites enabled")
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

        # PQC comprehensive tests with Catch2
        if(Catch2_FOUND)
            add_executable(pqc-comprehensive-test
                tests/pqc/test_pqc_vectors.cpp
                src/core/side_channel.cpp
                src/pqc/kem/kem_interface.cpp
                src/pqc/kem/kem_factory.cpp
            )
            target_link_libraries(pqc-comprehensive-test PRIVATE
                Catch2::Catch2WithMain
                ${SODIUM_LIBRARIES}
                ${LIBOQS_LIBRARY}
            )
            target_include_directories(pqc-comprehensive-test PRIVATE
                ${SODIUM_INCLUDE_DIRS}
                ${LIBOQS_INCLUDE_DIR}
                ${CMAKE_CURRENT_SOURCE_DIR}/src
            )

            if(WIN32)
                target_link_libraries(pqc-comprehensive-test bcrypt)
            endif()

            add_test(NAME pqc-comprehensive-test COMMAND pqc-comprehensive-test)
            message(STATUS "PQC comprehensive tests enabled")
        endif()

        message(STATUS "PQC tests enabled")
    endif()
endif()

# ============================================================================
# FUZZING
# ============================================================================
if(BUILD_FUZZER)
    # The fuzzer #includes nocturne-kx.cpp wholesale (NOCTURNE_FUZZER_BUILD
    # macro guards the main()), so it pulls in the encrypt_packet_kem /
    # decrypt_packet_kem references to KEMFactory. Those symbols live in
    # kem_interface.cpp and kem_factory.cpp — link them explicitly here.
    # The factory's PQC backends are gated by #ifdef NOCTURNE_ENABLE_PQC, so
    # this stays compatible with the fuzzer's ENABLE_PQC=OFF build.
    add_executable(nocturne-fuzzer
        tests/fuzzer_main.cpp
        src/core/side_channel.cpp
        src/pqc/kem/kem_interface.cpp
        src/pqc/kem/kem_factory.cpp
    )
    target_include_directories(nocturne-fuzzer PRIVATE
        ${SODIUM_INCLUDE_DIRS}
        ${CMAKE_CURRENT_SOURCE_DIR}/src
    )

    # Link libraries
    target_link_libraries(nocturne-fuzzer ${SODIUM_LIBRARIES})

    # Use Clang's default stdlib (libstdc++ on Ubuntu/Debian). libFuzzer's
    # runtime is shipped pre-built against libstdc++, so forcing -stdlib=libc++
    # produces undefined references to std::__cxx11::* symbols at link time.
    # If a future need for libc++ arises, both libFuzzer AND our code must be
    # rebuilt against it together.
    if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        target_compile_options(nocturne-fuzzer PRIVATE -fsanitize=fuzzer)
        target_link_options(nocturne-fuzzer PRIVATE -fsanitize=fuzzer)
    else()
        # GCC doesn't ship libFuzzer; fall back to AddressSanitizer.
        target_compile_options(nocturne-fuzzer PRIVATE -fsanitize=address,undefined)
        target_link_options(nocturne-fuzzer PRIVATE -fsanitize=address,undefined)
        message(WARNING "libFuzzer requires Clang. Using AddressSanitizer with GCC instead.")
    endif()

    message(STATUS "Fuzzer target configured with compiler: ${CMAKE_CXX_COMPILER_ID}")
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
