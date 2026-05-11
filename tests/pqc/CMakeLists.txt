cmake_minimum_required(VERSION 3.20)
project(nocturne_pqc_tests)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# liboqs discovery. Override with -DLIBOQS_ROOT=<path> or the LIBOQS_ROOT env var.
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

find_library(LIBOQS_LIBRARY NAMES oqs
    HINTS ${_LIBOQS_HINT_LIB_DIRS}
    PATHS "/usr/local/lib" "/usr/lib"
)
find_path(LIBOQS_INCLUDE_DIR oqs/oqs.h
    HINTS ${_LIBOQS_HINT_INC_DIRS}
    PATHS "/usr/local/include" "/usr/include"
)

if(NOT LIBOQS_LIBRARY OR NOT LIBOQS_INCLUDE_DIR)
    message(FATAL_ERROR
        "liboqs not found. Install it system-wide (e.g. apt install liboqs-dev) "
        "or pass -DLIBOQS_ROOT=<path-to-liboqs-install>.")
endif()

message(STATUS "liboqs library: ${LIBOQS_LIBRARY}")
message(STATUS "liboqs include: ${LIBOQS_INCLUDE_DIR}")

# Test executable
add_executable(test_liboqs_basic test_liboqs_basic.cpp)

target_include_directories(test_liboqs_basic PRIVATE ${LIBOQS_INCLUDE_DIR})
target_link_libraries(test_liboqs_basic ${LIBOQS_LIBRARY})

# Windows specific: Add bcrypt (for random number generation)
if(WIN32)
    target_link_libraries(test_liboqs_basic bcrypt)
endif()
