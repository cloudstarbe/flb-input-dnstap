cmake_minimum_required(VERSION 3.12)
project(fluent-bit-plugin C)

# Compiler hardening flags — this plugin runs in a privileged process
# processing untrusted data, so defence-in-depth is critical.
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -fPIC -Wno-sign-compare -Wno-unused-parameter")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fstack-protector-strong")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wformat -Wformat-security")
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -O2 -D_FORTIFY_SOURCE=2")
set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -Wl,-z,relro,-z,now")

# ---------------------------------------------------------------
# Static dependency discovery (libldns.a, libprotobuf-c.a)
# These are built from source via scripts/build-static-deps.sh
# and eliminate runtime SONAME dependencies on the target system.
# ---------------------------------------------------------------

# Allow overriding the search prefix (defaults to /usr/local)
set(STATIC_DEPS_PREFIX "/usr/local" CACHE PATH "Prefix where static libs are installed")

# Find static archives — require .a files specifically
set(_ORIG_SUFFIXES ${CMAKE_FIND_LIBRARY_SUFFIXES})
set(CMAKE_FIND_LIBRARY_SUFFIXES .a)

find_library(LDNS_STATIC_LIB NAMES ldns
  PATHS ${STATIC_DEPS_PREFIX}/lib
  NO_DEFAULT_PATH)
find_library(PROTOBUF_C_STATIC_LIB NAMES protobuf-c
  PATHS ${STATIC_DEPS_PREFIX}/lib
  NO_DEFAULT_PATH)

set(CMAKE_FIND_LIBRARY_SUFFIXES ${_ORIG_SUFFIXES})

if(NOT LDNS_STATIC_LIB)
  message(FATAL_ERROR "libldns.a not found in ${STATIC_DEPS_PREFIX}/lib. "
    "Run scripts/build-static-deps.sh first.")
endif()
if(NOT PROTOBUF_C_STATIC_LIB)
  message(FATAL_ERROR "libprotobuf-c.a not found in ${STATIC_DEPS_PREFIX}/lib. "
    "Run scripts/build-static-deps.sh first.")
endif()

message(STATUS "Static ldns:       ${LDNS_STATIC_LIB}")
message(STATUS "Static protobuf-c: ${PROTOBUF_C_STATIC_LIB}")

# OpenSSL is required by ldns (linked dynamically — available on all targets)
find_package(OpenSSL REQUIRED)

# Macro to build plugin source code
macro(FLB_PLUGIN name src deps)
  add_library(flb-${name} SHARED ${src})
  set_target_properties(flb-${name} PROPERTIES PREFIX "")
  set_target_properties(flb-${name} PROPERTIES
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
  target_include_directories(flb-${name} PRIVATE
    ${STATIC_DEPS_PREFIX}/include
  )
  target_link_libraries(flb-${name}
    ${deps}
    ${LDNS_STATIC_LIB}
    ${PROTOBUF_C_STATIC_LIB}
    OpenSSL::SSL
    OpenSSL::Crypto
  )
endmacro()

# Fluent Bit source code environment
if(NOT DEFINED FLB_SOURCE OR FLB_SOURCE STREQUAL "")
  message(FATAL_ERROR "No Fluent Bit source directory has been defined")
endif()

# Validate plugin name
if(NOT DEFINED PLUGIN_NAME OR PLUGIN_NAME STREQUAL "")
  message(FATAL_ERROR "Plugin name is not defined")
endif()

# Info
message(STATUS "Fluent Bit source code: " ${FLB_SOURCE})

# Include Headers
set(FLB_PATH_ROOT_SOURCE ${FLB_SOURCE})
include(${FLB_SOURCE}/cmake/libraries.cmake)
include(${FLB_SOURCE}/cmake/headers.cmake)

# Include Fluent Bit headers
include_directories(
    ${FLB_SOURCE}/include
    ${FLB_SOURCE}/lib
)

# Include Fluent Bit build-generated and vendored headers
include_directories(
    ${FLB_SOURCE}/build/include
    ${FLB_SOURCE}/lib/msgpack/include
    ${FLB_SOURCE}/lib/msgpack-c/include
    ${FLB_SOURCE}/lib/flb_libco
    ${FLB_SOURCE}/lib/monkey/include
    ${FLB_SOURCE}/build/lib/monkey/include
    ${FLB_SOURCE}/build/lib/monkey/include/monkey
    ${FLB_SOURCE}/lib/monkey/include/monkey/mk_core
    ${FLB_SOURCE}/lib/cmetrics/include
    ${FLB_SOURCE}/lib/ctraces/include
    ${FLB_SOURCE}/lib/ctraces/lib/mpack/src
    ${FLB_SOURCE}/lib/cprofiles/include
    ${FLB_SOURCE}/build/lib/cprofiles/include
    ${FLB_SOURCE}/lib/cfl/include
    ${FLB_SOURCE}/lib/cfl/lib/xxhash
)

# Build plugin
add_subdirectory(${PLUGIN_NAME})

# ------------------------------------------------------------------
# Unit tests (standalone, no Fluent Bit source needed)
# Usage: cmake -DENABLE_TESTS=ON ../  &&  make  &&  ctest
# ------------------------------------------------------------------
option(ENABLE_TESTS "Build unit tests (uses stub FLB headers)" OFF)
if(ENABLE_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()
