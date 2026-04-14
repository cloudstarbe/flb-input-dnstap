cmake_minimum_required(VERSION 3.12)
project(dnstap_tests C)

find_package(PkgConfig REQUIRED)

# ---------------------------------------------------------------
# Tests use system dynamic libraries, NOT the static archives in
# /usr/local that were built for plugin .so embedding.
# We find the .so files explicitly to avoid the linker picking up
# /usr/local/lib/libldns.a from the default search path.
# ---------------------------------------------------------------
set(CMAKE_FIND_LIBRARY_SUFFIXES .so)
find_library(LDNS_DYNAMIC_LIB NAMES ldns
  PATHS /usr/lib/x86_64-linux-gnu /usr/lib
  NO_DEFAULT_PATH)
find_library(PROTOBUF_C_DYNAMIC_LIB NAMES protobuf-c
  PATHS /usr/lib/x86_64-linux-gnu /usr/lib
  NO_DEFAULT_PATH)

if(NOT LDNS_DYNAMIC_LIB)
  message(FATAL_ERROR "System libldns.so not found. Install libldns-dev.")
endif()
if(NOT PROTOBUF_C_DYNAMIC_LIB)
  message(FATAL_ERROR "System libprotobuf-c.so not found. Install libprotobuf-c-dev.")
endif()

# Use system include dirs from pkg-config
pkg_check_modules(PROTOBUF_C_PC REQUIRED libprotobuf-c)
pkg_check_modules(LDNS_PC REQUIRED ldns)

enable_testing()

# --- test_dnstap_decode ---
add_executable(test_dnstap_decode test_dnstap_decode.c)

target_include_directories(test_dnstap_decode PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/stubs
  ${PROTOBUF_C_PC_INCLUDE_DIRS}
  ${LDNS_PC_INCLUDE_DIRS}
)

target_link_libraries(test_dnstap_decode PRIVATE
  ${PROTOBUF_C_DYNAMIC_LIB}
  ${LDNS_DYNAMIC_LIB}
)

target_compile_options(test_dnstap_decode PRIVATE -Wall -Wextra -Wno-sign-compare)

add_test(NAME dnstap_decode_tests COMMAND test_dnstap_decode)

# --- test_dnstap_parser ---
add_executable(test_dnstap_parser
  test_dnstap_parser.c
  ../in_dnstap/dnstap_parser.c
  ../in_dnstap/dnstap_decode.c
  ../in_dnstap/dnstap.pb-c.c
)

target_include_directories(test_dnstap_parser PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/stubs
  ${CMAKE_CURRENT_SOURCE_DIR}/../in_dnstap
  ${PROTOBUF_C_PC_INCLUDE_DIRS}
  ${LDNS_PC_INCLUDE_DIRS}
)

target_link_libraries(test_dnstap_parser PRIVATE
  ${PROTOBUF_C_DYNAMIC_LIB}
  ${LDNS_DYNAMIC_LIB}
)

target_compile_options(test_dnstap_parser PRIVATE -Wall -Wextra -Wno-sign-compare)

add_test(NAME dnstap_parser_tests COMMAND test_dnstap_parser)
