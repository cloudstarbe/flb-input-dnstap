cmake_minimum_required(VERSION 3.12)
project(dnstap_tests C)

find_package(PkgConfig REQUIRED)
pkg_check_modules(PROTOBUF_C REQUIRED libprotobuf-c)
pkg_check_modules(LDNS REQUIRED ldns)

enable_testing()

# --- test_dnstap_decode ---
add_executable(test_dnstap_decode test_dnstap_decode.c)

target_include_directories(test_dnstap_decode PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/stubs
  ${PROTOBUF_C_INCLUDE_DIRS}
  ${LDNS_INCLUDE_DIRS}
)

target_link_libraries(test_dnstap_decode PRIVATE
  ${PROTOBUF_C_LIBRARIES}
  ${LDNS_LIBRARIES}
)

target_link_directories(test_dnstap_decode PRIVATE
  ${PROTOBUF_C_LIBRARY_DIRS}
  ${LDNS_LIBRARY_DIRS}
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
  ${PROTOBUF_C_INCLUDE_DIRS}
  ${LDNS_INCLUDE_DIRS}
)

target_link_libraries(test_dnstap_parser PRIVATE
  ${PROTOBUF_C_LIBRARIES}
  ${LDNS_LIBRARIES}
)

target_compile_options(test_dnstap_parser PRIVATE -Wall -Wextra -Wno-sign-compare)

add_test(NAME dnstap_parser_tests COMMAND test_dnstap_parser)
