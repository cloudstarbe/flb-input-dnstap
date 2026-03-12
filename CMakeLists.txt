cmake_minimum_required(VERSION 3.12)
project(fluent-bit-plugin C)

# Compiler hardening flags — this plugin runs in a privileged process
# processing untrusted data, so defence-in-depth is critical.
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -fPIC -Wno-sign-compare -Wno-unused-parameter")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fstack-protector-strong")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wformat -Wformat-security")
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -O2 -D_FORTIFY_SOURCE=2")
set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -Wl,-z,relro,-z,now")

# Find required libraries via pkg-config
find_package(PkgConfig REQUIRED)

pkg_check_modules(PROTOBUF_C REQUIRED libprotobuf-c)
pkg_check_modules(LDNS REQUIRED ldns)

# Macro to build source code
macro(FLB_PLUGIN name src deps)
  add_library(flb-${name} SHARED ${src})
  set_target_properties(flb-${name} PROPERTIES PREFIX "")
  set_target_properties(flb-${name} PROPERTIES
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
  target_include_directories(flb-${name} PRIVATE

    ${PROTOBUF_C_INCLUDE_DIRS}
    ${LDNS_INCLUDE_DIRS}
  )
  target_link_libraries(flb-${name}
    ${deps}

    ${PROTOBUF_C_LIBRARIES}
    ${LDNS_LIBRARIES}
  )
  target_link_directories(flb-${name} PRIVATE

    ${PROTOBUF_C_LIBRARY_DIRS}
    ${LDNS_LIBRARY_DIRS}
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
