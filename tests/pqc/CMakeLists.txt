cmake_minimum_required(VERSION 3.20)
project(nocturne_pqc_tests)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# liboqs paths
set(LIBOQS_INCLUDE_DIR "C:/Users/Maxval/Desktop/liboqs/build/include")
set(LIBOQS_LIBRARY "C:/Users/Maxval/Desktop/liboqs/build/lib/Release/oqs.lib")

# Test executable
add_executable(test_liboqs_basic test_liboqs_basic.cpp)

target_include_directories(test_liboqs_basic PRIVATE ${LIBOQS_INCLUDE_DIR})
target_link_libraries(test_liboqs_basic ${LIBOQS_LIBRARY})

# Windows specific: Add bcrypt (for random number generation)
if(WIN32)
    target_link_libraries(test_liboqs_basic bcrypt)
endif()
