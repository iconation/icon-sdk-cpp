cmake_minimum_required (VERSION 3.0)
project (ICON_SDK_CPP)

# === GLOBAL =======================================================================================================
# --- Directories
set (ROOTDIR ${PROJECT_SOURCE_DIR})
set (LIBDIR ${ROOTDIR}/lib/${CMAKE_ARCHITECTURE}/)
set (RELEASE_DIR ${ROOTDIR}/release/${CMAKE_ARCHITECTURE}/)
set (VCPKG_ROOT $ENV{VCPKG_ROOT})

# --- Linker Paths
link_directories (${LIBDIR})
if (MSVC)
    # VCPKG directories on Windows
    link_directories (${VCPKG_ROOT}/installed/${CMAKE_ARCHITECTURE}-windows/lib/)
    link_directories (${VCPKG_ROOT}/installed/${CMAKE_ARCHITECTURE}-windows/lib/manual-link/)
endif (MSVC)

# --- Includes Paths
include_directories (${ROOTDIR}/third_party)
if (MSVC)
    # VCPKG directories on Windows
    include_directories (${VCPKG_ROOT}/installed/${CMAKE_ARCHITECTURE}-windows/include/)
endif (MSVC)

# --- Packages
find_package (GTest REQUIRED)
find_package (spdlog CONFIG REQUIRED)
find_package (OpenSSL REQUIRED)
find_package (CURL REQUIRED)

# --- Dependency : common lib
add_subdirectory (common-lib-cpp)
include_directories (common-lib-cpp/src)

# --- CMAKE Configs
set (CMAKE_RUNTIME_OUTPUT_DIRECTORY ${RELEASE_DIR})
if (MSVC)
    set (CMAKE_CXX_FLAGS_RELEASE "/std:c++17 /MD /O2")
    set (CMAKE_CXX_FLAGS_DEBUG "/std:c++17 /MDd /Od /Zi")
else ()
    # Assume g++
    set (CMAKE_CXX_FLAGS_RELEASE "-std=c++17 -O2")
    set (CMAKE_CXX_FLAGS_DEBUG "-std=c++17 -g")
endif (MSVC)

# --- Librairies definition
if (MSVC)
    set (MPIR_LIBRARIES mpir)
else ()
    set (MPIR_LIBRARIES mpir mpirxx)
endif (MSVC)
set (SECP256K1_LIBRAIRIES secp256k1)
set (OPENSSL_LIBRAIRIES OpenSSL::SSL OpenSSL::Crypto)
set (GTEST_LIBRARIES GTest::GTest GTest::Main)
if (MSVC)
    # Don't need pthread
else ()
    set (PTHREAD_LIBRARIES pthread)
endif (MSVC)

# === SDK =======================================================================================================
# --- Directories
set (SDK_ROOT ${ROOTDIR})
set (SDK_SRCDIR ${SDK_ROOT}/src)
set (SDK_TESTDIR ${SDK_ROOT}/tests)

# --- SPDLOG defines
add_definitions (-DSPDLOG_FMT_EXTERNAL)
add_definitions (-DFMT_HEADER_ONLY)

# --- SDK source code
file (GLOB_RECURSE SDK_SRC
    ${SDK_SRCDIR}/*.cpp     ${SDK_SRCDIR}/*.h
)

# --- Tests source code
file (GLOB_RECURSE SDK_TESTS_SRC
    ${SDK_TESTDIR}/main.cpp
)

# --- SDK Library
add_library (SDK_lib STATIC ${SDK_SRC})
target_include_directories (SDK_lib PRIVATE ${SDK_SRCDIR})
target_include_directories (SDK_lib PRIVATE ${COMMON_SRCDIR})
target_link_libraries (SDK_lib ${MPIR_LIBRARIES} ${SECP256K1_LIBRAIRIES} ${OPENSSL_LIBRAIRIES})

# --- SDK Tests executable
add_executable (SDK_Tests ${SDK_TESTS_SRC})
target_include_directories (SDK_Tests PRIVATE ${SDK_SRCDIR})
target_include_directories (SDK_Tests PRIVATE ${COMMON_SRCDIR})
target_link_libraries(SDK_Tests SDK_lib common_lib ${GTEST_LIBRARIES} ${PTHREAD_LIBRARIES})
set_target_properties(SDK_Tests PROPERTIES RUNTIME_OUTPUT_DIRECTORY_DEBUG ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})
set_target_properties(SDK_Tests PROPERTIES RUNTIME_OUTPUT_DIRECTORY_RELEASE ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})
