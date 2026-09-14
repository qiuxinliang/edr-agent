cmake_minimum_required(VERSION 3.19)
cmake_policy(SET CMP0091 NEW)
project(edr_agent
  VERSION 0.1.0
  DESCRIPTION "EDR endpoint agent"
  LANGUAGES C CXX
)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Strict C11 mode intentionally disables compiler extensions.  On Linux,
# glibc only declares the POSIX clock/environment APIs used by the Agent when
# their feature-test contract is supplied before every system header.
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  add_compile_definitions(_POSIX_C_SOURCE=200809L _GNU_SOURCE=1)
endif()

if(MSVC)
  add_compile_definitions(_CRT_SECURE_NO_WARNINGS _CRT_NONSTDC_NO_WARNINGS)
  if(WIN32)
    set(EDR_WINDOWS_TARGET_ARCH "" CACHE STRING "Explicit Windows target architecture: amd64 or arm64")
    string(TOLOWER "${EDR_WINDOWS_TARGET_ARCH}" _edr_windows_target_arch_lc)
    string(TOLOWER "${CMAKE_SYSTEM_PROCESSOR}" _edr_system_processor_lc)
    if(_edr_windows_target_arch_lc STREQUAL "arm64" OR
       (_edr_windows_target_arch_lc STREQUAL "" AND _edr_system_processor_lc MATCHES "arm64|aarch64"))
      set(_edr_msvc_win_arch_define _ARM64_=1)
    elseif(_edr_windows_target_arch_lc STREQUAL "amd64" OR
           (_edr_windows_target_arch_lc STREQUAL "" AND CMAKE_SIZEOF_VOID_P EQUAL 8))
      set(_edr_msvc_win_arch_define _AMD64_=1)
    elseif(NOT _edr_windows_target_arch_lc STREQUAL "")
      message(FATAL_ERROR "EDR_WINDOWS_TARGET_ARCH must be amd64 or arm64")
    else()
      set(_edr_msvc_win_arch_define _X86_=1)
    endif()
    add_compile_definitions(${_edr_msvc_win_arch_define})
    message(STATUS "MSVC Windows SDK target architecture macro: ${_edr_msvc_win_arch_define}")
  endif()
endif()

function(edr_apply_common_warnings target_name)
  if(MSVC)
    # Current C11 atomic use stays within MSVC's <=8-byte lock-free builtin scope.
    target_compile_options(${target_name} PRIVATE
      /W4 /WX-
      "$<$<COMPILE_LANGUAGE:C,CXX>:/utf-8>"
      "$<$<COMPILE_LANGUAGE:C>:/experimental:c11atomics>")
  else()
    target_compile_options(${target_name} PRIVATE -Wall -Wextra -Wno-unused-parameter)
  endif()
endfunction()

function(edr_apply_test_warnings target_name)
  edr_apply_common_warnings(${target_name})
  if(MSVC)
    # Undeclared POSIX calls must fail at compilation, not reach the linker.
    target_compile_options(${target_name} PRIVATE /UNDEBUG
      "$<$<COMPILE_LANGUAGE:C>:/we4013>")
  else()
    target_compile_options(${target_name} PRIVATE -UNDEBUG)
  endif()
endfunction()

option(EDR_BUILD_TESTS "Build CTest smoke/regression targets" ON)
option(EDR_WITH_LINUX_COLLECTOR "On Linux, build collector_linux.c instead of collector_stub.c" ON)
set(EDR_AGENT_VERSION_STRING
  "${PROJECT_VERSION}"
  CACHE STRING "Agent version string reported to the platform")
message(STATUS "gRPC client removed from product build; HTTP ingest/control only")

option(EDR_BUILD_AVE_SHARED_LIB "Build standalone edr_ave_shared (AVE DLL/so for embedding)" OFF)
option(EDR_CREATE_LEGACY_AGENT_ALIAS "Create legacy edr_agent.exe alias next to FDSensor.exe on Windows" OFF)
option(EDR_WITH_YARA "Enable libyara for known exploit rules" ON)
option(EDR_REQUIRE_YARA "Fail configure when libyara is unavailable" OFF)
option(EDR_REQUIRE_SQLITE "Fail configure when SQLite3 is unavailable" OFF)
option(EDR_REQUIRE_PCRE2 "Fail configure when PCRE2 is unavailable for the P0 matcher" ON)
set(EDR_PCRE2_PRODUCER_TARGET "" CACHE STRING
  "Fresh static PCRE2 target (linux/amd64, linux/arm64, windows/amd64, windows/arm64)")
set(EDR_PCRE2_VCPKG_ROOT "" CACHE PATH
  "Clean locked vcpkg checkout used to rebuild the production PCRE2 matcher")
option(EDR_P0_RULE_IR_ALLOW_TEST_STUB
  "Allow p0_rule_ir_stub.c only in an explicit non-production CTest build" OFF)
option(EDR_WITH_FORENSIC_COLLECTOR "Build the standalone forensic_collector binary" ON)
if(EDR_REQUIRE_YARA AND NOT EDR_WITH_YARA)
  message(FATAL_ERROR "EDR_REQUIRE_YARA=ON requires EDR_WITH_YARA=ON")
endif()

set(_edr_p0_rule_ir_release_or_production FALSE)
if(CMAKE_CONFIGURATION_TYPES)
  foreach(_edr_p0_rule_ir_config IN LISTS CMAKE_CONFIGURATION_TYPES)
    string(TOLOWER "${_edr_p0_rule_ir_config}" _edr_p0_rule_ir_config_lc)
    if(_edr_p0_rule_ir_config_lc MATCHES "^(release|relwithdebinfo|minsizerel|production)$")
      set(_edr_p0_rule_ir_release_or_production TRUE)
    endif()
  endforeach()
else()
  string(TOLOWER "${CMAKE_BUILD_TYPE}" _edr_p0_rule_ir_config_lc)
  if(_edr_p0_rule_ir_config_lc MATCHES "^(release|relwithdebinfo|minsizerel|production)$")
    set(_edr_p0_rule_ir_release_or_production TRUE)
  endif()
endif()

set(_edr_pcre2_explicit_test_stub FALSE)
if(EDR_BUILD_TESTS AND EDR_P0_RULE_IR_ALLOW_TEST_STUB AND NOT EDR_REQUIRE_PCRE2 AND
   NOT _edr_p0_rule_ir_release_or_production)
  set(_edr_pcre2_explicit_test_stub TRUE)
endif()

set(EDR_PCRE2_AVAILABLE 0)
set(EDR_PCRE2_TARGET "")

function(_edr_pcre2_require_below root_path candidate_path label output_variable)
  file(TO_CMAKE_PATH "${candidate_path}" _edr_pcre2_candidate_cmake_path)
  if(NOT EXISTS "${_edr_pcre2_candidate_cmake_path}")
    message(FATAL_ERROR "Production PCRE2 ${label} does not exist")
  endif()
  get_filename_component(_edr_pcre2_root_real "${root_path}" REALPATH)
  get_filename_component(_edr_pcre2_candidate_real "${_edr_pcre2_candidate_cmake_path}" REALPATH)
  file(RELATIVE_PATH _edr_pcre2_relative
    "${_edr_pcre2_root_real}" "${_edr_pcre2_candidate_real}")
  if(_edr_pcre2_relative STREQUAL "" OR
     _edr_pcre2_relative MATCHES "^\\.\\.($|[/\\\\])" OR
     IS_ABSOLUTE "${_edr_pcre2_relative}")
    message(FATAL_ERROR "Production PCRE2 ${label} escapes the build-owned producer root")
  endif()
  set(${output_variable} "${_edr_pcre2_candidate_real}" PARENT_SCOPE)
endfunction()

function(_edr_pcre2_json_member json member output_variable)
  string(JSON _edr_pcre2_member_value ERROR_VARIABLE _edr_pcre2_json_error
    GET "${json}" "${member}")
  if(NOT "${_edr_pcre2_json_error}" STREQUAL "NOTFOUND")
    message(FATAL_ERROR
      "Production PCRE2 producer returned invalid structured result for ${member}: ${_edr_pcre2_json_error}")
  endif()
  set(${output_variable} "${_edr_pcre2_member_value}" PARENT_SCOPE)
endfunction()

if(_edr_pcre2_explicit_test_stub)
  message(WARNING "P0 IR rule engine PCRE2 support: explicit NON-PRODUCTION CTest stub selected; this build cannot publish or enforce P0 rules")
else()
  if(EDR_P0_RULE_IR_ALLOW_TEST_STUB AND NOT EDR_REQUIRE_PCRE2)
    message(FATAL_ERROR
      "p0_rule_ir_stub.c is allowed only with EDR_BUILD_TESTS=ON, "
      "EDR_REQUIRE_PCRE2=OFF, EDR_P0_RULE_IR_ALLOW_TEST_STUB=ON, and a non-production configuration.")
  endif()
  if(NOT EDR_REQUIRE_PCRE2)
    message(FATAL_ERROR
      "PCRE2 8-bit support is required for production/release P0 matcher builds. "
      "p0_rule_ir_stub.c is allowed only with EDR_BUILD_TESTS=ON, "
      "EDR_REQUIRE_PCRE2=OFF, EDR_P0_RULE_IR_ALLOW_TEST_STUB=ON, and a non-production configuration.")
  endif()
  if(DEFINED EDR_PCRE2_MATCHER_CONTRACT_PATH OR DEFINED EDR_PCRE2_STATIC_PREFIX)
    message(FATAL_ERROR
      "Production PCRE2 matcher builds reject caller-supplied "
      "EDR_PCRE2_MATCHER_CONTRACT_PATH and EDR_PCRE2_STATIC_PREFIX. "
      "CMake rebuilds and verifies the static matcher in its build-owned producer root.")
  endif()
  if(NOT EDR_PCRE2_PRODUCER_TARGET OR NOT EDR_PCRE2_VCPKG_ROOT)
    message(FATAL_ERROR
      "Production PCRE2 matcher builds require EDR_PCRE2_PRODUCER_TARGET and "
      "EDR_PCRE2_VCPKG_ROOT. System PCRE2 discovery is not accepted by this production gate.")
  endif()
  if(NOT IS_DIRECTORY "${EDR_PCRE2_VCPKG_ROOT}")
    message(FATAL_ERROR "Production PCRE2 locked vcpkg root does not exist")
  endif()
  find_package(Python3 REQUIRED COMPONENTS Interpreter)

  # This is the only mutable producer root accepted by production CMake.  It
  # is reconstructed on *every* configure, so an archive from a prior
  # invocation cannot be relinked merely by self-reporting matching hashes.
  get_filename_component(_edr_pcre2_binary_dir_real "${CMAKE_BINARY_DIR}" REALPATH)
  set(_edr_pcre2_producer_root "${_edr_pcre2_binary_dir_real}/edr-pcre2-producer")
  get_filename_component(_edr_pcre2_producer_parent "${_edr_pcre2_producer_root}" DIRECTORY)
  if(NOT "${_edr_pcre2_producer_parent}" STREQUAL "${_edr_pcre2_binary_dir_real}")
    message(FATAL_ERROR "Production PCRE2 producer root must be an exact child of CMAKE_BINARY_DIR")
  endif()
  if(EXISTS "${_edr_pcre2_producer_root}" OR IS_SYMLINK "${_edr_pcre2_producer_root}")
    if(IS_SYMLINK "${_edr_pcre2_producer_root}")
      message(FATAL_ERROR "Production PCRE2 producer root must not be a symlink")
    endif()
    get_filename_component(_edr_pcre2_existing_root_real
      "${_edr_pcre2_producer_root}" REALPATH)
    if(NOT "${_edr_pcre2_existing_root_real}" STREQUAL "${_edr_pcre2_producer_root}")
      message(FATAL_ERROR "Production PCRE2 producer root realpath is unsafe")
    endif()
    file(REMOVE_RECURSE "${_edr_pcre2_producer_root}")
  endif()
  file(MAKE_DIRECTORY "${_edr_pcre2_producer_root}")
  if(IS_SYMLINK "${_edr_pcre2_producer_root}")
    message(FATAL_ERROR "Production PCRE2 producer root must not be a symlink")
  endif()
  set(_edr_pcre2_contract_path "${_edr_pcre2_producer_root}/p0_matcher_contract.json")

  execute_process(
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/scripts/produce_pcre2_matcher_contract.py"
      --vcpkg-root "${EDR_PCRE2_VCPKG_ROOT}"
      --producer-root "${_edr_pcre2_producer_root}"
      --output "${_edr_pcre2_contract_path}"
      --target "${EDR_PCRE2_PRODUCER_TARGET}"
    RESULT_VARIABLE _edr_pcre2_produce_result
    OUTPUT_VARIABLE _edr_pcre2_produce_output
    ERROR_VARIABLE _edr_pcre2_produce_error
    OUTPUT_STRIP_TRAILING_WHITESPACE)
  if(NOT _edr_pcre2_produce_result EQUAL 0 OR NOT _edr_pcre2_produce_output)
    message(FATAL_ERROR
      "Production PCRE2 matcher source build failed: ${_edr_pcre2_produce_error}")
  endif()
  _edr_pcre2_json_member("${_edr_pcre2_produce_output}" "schema" _edr_pcre2_produce_schema)
  _edr_pcre2_json_member("${_edr_pcre2_produce_output}" "mode" _edr_pcre2_produce_mode)
  _edr_pcre2_json_member("${_edr_pcre2_produce_output}" "target" _edr_pcre2_produce_target)
  _edr_pcre2_json_member("${_edr_pcre2_produce_output}" "contract_path" _edr_pcre2_result_contract)
  _edr_pcre2_json_member("${_edr_pcre2_produce_output}" "prefix" _edr_pcre2_result_prefix)
  _edr_pcre2_json_member("${_edr_pcre2_produce_output}" "contract_sha256" _edr_pcre2_result_contract_sha256)
  if(NOT "${_edr_pcre2_produce_schema}" STREQUAL "edr.p0.matcher-producer-result.v1" OR
     NOT "${_edr_pcre2_produce_mode}" STREQUAL "build" OR
     NOT "${_edr_pcre2_produce_target}" STREQUAL "${EDR_PCRE2_PRODUCER_TARGET}")
    message(FATAL_ERROR "Production PCRE2 producer returned an unexpected structured build result")
  endif()
  _edr_pcre2_require_below("${_edr_pcre2_producer_root}" "${_edr_pcre2_result_contract}"
    "matcher contract" _edr_pcre2_contract_real)
  _edr_pcre2_require_below("${_edr_pcre2_producer_root}" "${_edr_pcre2_result_prefix}"
    "static prefix" _edr_pcre2_prefix_real)
  if(NOT "${_edr_pcre2_contract_real}" STREQUAL "${_edr_pcre2_contract_path}")
    message(FATAL_ERROR "Production PCRE2 producer returned an unexpected matcher contract path")
  endif()
  file(SHA256 "${_edr_pcre2_contract_real}" _edr_pcre2_contract_sha256)
  if(NOT "${_edr_pcre2_contract_sha256}" STREQUAL "${_edr_pcre2_result_contract_sha256}")
    message(FATAL_ERROR "Production PCRE2 producer result contract hash does not match its build-owned contract")
  endif()

  execute_process(
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/scripts/produce_pcre2_matcher_contract.py"
      --verify-contract "${_edr_pcre2_contract_real}"
      --prefix "${_edr_pcre2_prefix_real}"
      --target "${EDR_PCRE2_PRODUCER_TARGET}"
      --vcpkg-root "${EDR_PCRE2_VCPKG_ROOT}"
    RESULT_VARIABLE _edr_pcre2_verify_result
    OUTPUT_VARIABLE _edr_pcre2_verify_output
    ERROR_VARIABLE _edr_pcre2_verify_error
    OUTPUT_STRIP_TRAILING_WHITESPACE)
  if(NOT _edr_pcre2_verify_result EQUAL 0 OR NOT _edr_pcre2_verify_output)
    message(FATAL_ERROR
      "Production PCRE2 matcher provenance verification failed: ${_edr_pcre2_verify_error}")
  endif()
  _edr_pcre2_json_member("${_edr_pcre2_verify_output}" "schema" _edr_pcre2_verify_schema)
  _edr_pcre2_json_member("${_edr_pcre2_verify_output}" "mode" _edr_pcre2_verify_mode)
  _edr_pcre2_json_member("${_edr_pcre2_verify_output}" "target" _edr_pcre2_verify_target)
  _edr_pcre2_json_member("${_edr_pcre2_verify_output}" "contract_path" _edr_pcre2_verify_contract)
  _edr_pcre2_json_member("${_edr_pcre2_verify_output}" "prefix" _edr_pcre2_verify_prefix)
  _edr_pcre2_json_member("${_edr_pcre2_verify_output}" "library" _edr_pcre2_verify_library)
  _edr_pcre2_json_member("${_edr_pcre2_verify_output}" "contract_sha256" _edr_pcre2_verify_contract_sha256)
  _edr_pcre2_require_below("${_edr_pcre2_producer_root}" "${_edr_pcre2_verify_contract}"
    "verified matcher contract" _edr_pcre2_verify_contract_real)
  _edr_pcre2_require_below("${_edr_pcre2_producer_root}" "${_edr_pcre2_verify_prefix}"
    "verified static prefix" _edr_pcre2_verify_prefix_real)
  if(NOT "${_edr_pcre2_verify_schema}" STREQUAL "edr.p0.matcher-producer-result.v1" OR
     NOT "${_edr_pcre2_verify_mode}" STREQUAL "verify" OR
     NOT "${_edr_pcre2_verify_target}" STREQUAL "${EDR_PCRE2_PRODUCER_TARGET}" OR
     NOT "${_edr_pcre2_verify_contract_real}" STREQUAL "${_edr_pcre2_contract_real}" OR
     NOT "${_edr_pcre2_verify_prefix_real}" STREQUAL "${_edr_pcre2_prefix_real}" OR
     NOT "${_edr_pcre2_verify_contract_sha256}" STREQUAL "${_edr_pcre2_contract_sha256}")
    message(FATAL_ERROR "Production PCRE2 producer returned an unexpected structured verification result")
  endif()
  _edr_pcre2_require_below("${_edr_pcre2_prefix_real}" "${_edr_pcre2_verify_library}"
    "static library" _edr_pcre2_library_real)
  if(NOT EXISTS "${_edr_pcre2_prefix_real}/include/pcre2.h")
    message(FATAL_ERROR "Production PCRE2 producer returned an unsafe static prefix")
  endif()
  add_library(edr_pcre2_static STATIC IMPORTED GLOBAL)
  set_target_properties(edr_pcre2_static PROPERTIES
    IMPORTED_LOCATION "${_edr_pcre2_library_real}"
    INTERFACE_INCLUDE_DIRECTORIES "${_edr_pcre2_prefix_real}/include")
  if(WIN32)
    # The isolated Windows prefix is a static vcpkg archive; avoid importing
    # a similarly named DLL from the ordinary product dependency prefix.
    set_property(TARGET edr_pcre2_static APPEND PROPERTY
      INTERFACE_COMPILE_DEFINITIONS PCRE2_STATIC)
  endif()
  set(EDR_PCRE2_MATCHER_CONTRACT_SHA256 "${_edr_pcre2_contract_sha256}"
    CACHE INTERNAL "Verified producer matcher contract hash bound to this build" FORCE)
  set(EDR_PCRE2_MATCHER_CONTRACT_AUDIT_PATH "${_edr_pcre2_contract_real}"
    CACHE INTERNAL "Build-owned PCRE2 matcher contract audit artifact" FORCE)
  set(EDR_PCRE2_STATIC_PREFIX_AUDIT_PATH "${_edr_pcre2_prefix_real}"
    CACHE INTERNAL "Build-owned static PCRE2 prefix audit artifact" FORCE)
  set(EDR_PCRE2_PRODUCER_ROOT_AUDIT_PATH "${_edr_pcre2_producer_root}"
    CACHE INTERNAL "Build-owned fresh PCRE2 producer root" FORCE)
  set(EDR_PCRE2_AVAILABLE 1)
  set(EDR_PCRE2_TARGET edr_pcre2_static)
  message(STATUS
    "P0 IR rule engine PCRE2 support: fresh build-owned static producer contract "
    "${EDR_PCRE2_MATCHER_CONTRACT_SHA256} (${EDR_PCRE2_PRODUCER_TARGET})")
endif()

if(NOT _edr_pcre2_explicit_test_stub AND NOT EDR_PCRE2_AVAILABLE)
  message(FATAL_ERROR
    "PCRE2 8-bit support is required for production/release P0 matcher builds. "
    "p0_rule_ir_stub.c is allowed only with EDR_BUILD_TESTS=ON, "
    "EDR_REQUIRE_PCRE2=OFF, EDR_P0_RULE_IR_ALLOW_TEST_STUB=ON, and a non-production configuration.")
endif()
if(EDR_PCRE2_AVAILABLE)
  set(EDR_P0_RULE_IR_IMPLEMENTATION_SOURCE
    "${CMAKE_CURRENT_SOURCE_DIR}/src/preprocess/p0_rule_ir.c")
else()
  # This is reachable only through the explicit non-production CTest stub
  # gate above.  Tests must use this same source selector rather than naming
  # the real PCRE2 implementation directly.
  set(EDR_P0_RULE_IR_IMPLEMENTATION_SOURCE
    "${CMAKE_CURRENT_SOURCE_DIR}/src/preprocess/p0_rule_ir_stub.c")
endif()

find_package(OpenSSL QUIET)
if(OpenSSL_FOUND)
  set(_EDR_INGEST_HTTPS_OPENSSL_DEFAULT ON)
else()
  set(_EDR_INGEST_HTTPS_OPENSSL_DEFAULT OFF)
endif()
find_package(CURL QUIET)
if(CURL_FOUND)
  set(_EDR_HTTP2_CURL_DEFAULT ON)
else()
  set(_EDR_HTTP2_CURL_DEFAULT OFF)
endif()
set(EDR_ZSTD_AVAILABLE 0)
set(EDR_ZSTD_TARGET "")
find_package(zstd CONFIG QUIET)
if(TARGET zstd::libzstd_shared)
  set(EDR_ZSTD_AVAILABLE 1)
  set(EDR_ZSTD_TARGET zstd::libzstd_shared)
elseif(TARGET zstd::libzstd_static)
  set(EDR_ZSTD_AVAILABLE 1)
  set(EDR_ZSTD_TARGET zstd::libzstd_static)
elseif(TARGET zstd::zstd)
  set(EDR_ZSTD_AVAILABLE 1)
  set(EDR_ZSTD_TARGET zstd::zstd)
else()
  find_path(EDR_ZSTD_INCLUDE_DIR NAMES zstd.h
    PATHS
      ENV ZSTD_ROOT
      "$ENV{ZSTD_ROOT}/include"
      /opt/homebrew/include
      /usr/local/include
      "C:/vcpkg/installed/x64-windows/include")
  find_library(EDR_ZSTD_LIBRARY NAMES zstd libzstd
    PATHS
      ENV ZSTD_ROOT
      "$ENV{ZSTD_ROOT}/lib"
      /opt/homebrew/lib
      /usr/local/lib
      "C:/vcpkg/installed/x64-windows/lib")
  if(EDR_ZSTD_INCLUDE_DIR AND EDR_ZSTD_LIBRARY)
    set(EDR_ZSTD_AVAILABLE 1)
  endif()
endif()
if(EDR_ZSTD_AVAILABLE)
  set(_EDR_ZSTD_DEFAULT ON)
else()
  set(_EDR_ZSTD_DEFAULT OFF)
endif()
# no-gRPC Windows production builds still use REST ingest/health over HTTPS.
# Default to ON whenever OpenSSL is available; smoke builds without OpenSSL stay
# fast, while release/CI presets explicitly require this option and fail if the
# dependency is missing.
option(EDR_WITH_INGEST_HTTPS_OPENSSL
  "Enable native HTTPS fallback in ingest_http.c through OpenSSL C headers"
  ${_EDR_INGEST_HTTPS_OPENSSL_DEFAULT})
if(WIN32)
  set(_EDR_REQUIRE_HTTPS_REST_DEFAULT ON)
else()
  set(_EDR_REQUIRE_HTTPS_REST_DEFAULT OFF)
endif()
option(EDR_REQUIRE_HTTPS_REST
  "Fail configure when no-gRPC Agent builds cannot use native HTTPS REST ingest"
  ${_EDR_REQUIRE_HTTPS_REST_DEFAULT})
if(EDR_WITH_INGEST_HTTPS_OPENSSL AND NOT OpenSSL_FOUND)
  message(FATAL_ERROR "EDR_WITH_INGEST_HTTPS_OPENSSL=ON but OpenSSL was not found")
endif()
if(EDR_REQUIRE_HTTPS_REST AND NOT EDR_WITH_INGEST_HTTPS_OPENSSL)
  message(FATAL_ERROR "EDR_REQUIRE_HTTPS_REST=ON requires EDR_WITH_INGEST_HTTPS_OPENSSL=ON")
endif()
message(STATUS "HTTP HTTPS ingest OpenSSL support: ${EDR_WITH_INGEST_HTTPS_OPENSSL}")
option(EDR_WITH_HTTP2_CURL
  "Enable real HTTP/2 ingest/control client through libcurl ALPN/nghttp2 when available"
  ${_EDR_HTTP2_CURL_DEFAULT})
if(EDR_WITH_HTTP2_CURL AND NOT CURL_FOUND)
  message(FATAL_ERROR "EDR_WITH_HTTP2_CURL=ON but libcurl was not found")
endif()
option(EDR_REQUIRE_CURL_HTTP2
  "Fail configure when EDR_WITH_HTTP2_CURL=ON but curl headers do not expose HTTP/2 support"
  OFF)
if(EDR_WITH_HTTP2_CURL)
  include(CheckCSourceCompiles)
  set(CMAKE_REQUIRED_INCLUDES ${CURL_INCLUDE_DIRS})
  if(TARGET CURL::libcurl)
    set(CMAKE_REQUIRED_LIBRARIES CURL::libcurl)
  else()
    set(CMAKE_REQUIRED_LIBRARIES ${CURL_LIBRARIES})
  endif()
  check_c_source_compiles("
    #include <curl/curl.h>
    #ifndef CURL_VERSION_HTTP2
    #error CURL_VERSION_HTTP2 missing
    #endif
    int main(void) { return 0; }
  " EDR_CURL_HEADERS_EXPOSE_HTTP2)
  if(EDR_REQUIRE_CURL_HTTP2 AND NOT EDR_CURL_HEADERS_EXPOSE_HTTP2)
    message(FATAL_ERROR "EDR_REQUIRE_CURL_HTTP2=ON but curl headers do not expose CURL_VERSION_HTTP2; install libcurl built with nghttp2")
  endif()
endif()
message(STATUS "HTTP/2 ingest libcurl support: ${EDR_WITH_HTTP2_CURL}")
option(EDR_WITH_ZSTD
  "Enable zstd compression for HTTPS transport v2 report-events envelopes"
  ${_EDR_ZSTD_DEFAULT})
if(EDR_WITH_ZSTD AND NOT EDR_ZSTD_AVAILABLE)
  message(FATAL_ERROR "EDR_WITH_ZSTD=ON but libzstd was not found")
endif()
message(STATUS "HTTPS transport zstd support: ${EDR_WITH_ZSTD}")
option(EDR_WITH_P0_RULES_OPENSSL
  "Enable AES-GCM decrypt support for encrypted P0 rule bundles"
  ${_EDR_INGEST_HTTPS_OPENSSL_DEFAULT})
if(EDR_WITH_P0_RULES_OPENSSL AND NOT OpenSSL_FOUND)
  message(FATAL_ERROR "EDR_WITH_P0_RULES_OPENSSL=ON but OpenSSL was not found")
endif()
message(STATUS "P0 encrypted rule bundle OpenSSL support: ${EDR_WITH_P0_RULES_OPENSSL}")
set(EDR_YARA_AVAILABLE 0)
set(EDR_YARA_TARGET "")
if(EDR_WITH_YARA)
  if(WIN32 AND EDR_REQUIRE_YARA)
    set(_EDR_VCPKG_FEATURES "${VCPKG_MANIFEST_FEATURES}")
    if(NOT _EDR_VCPKG_FEATURES MATCHES "(^|[;,])yara($|[;,])")
      message(FATAL_ERROR "Windows EDR_REQUIRE_YARA=ON requires vcpkg manifest feature 'yara'. Configure with -DVCPKG_MANIFEST_FEATURES=yara and install via vcpkg --x-feature=yara.")
    endif()
    find_package(unofficial-libyara CONFIG REQUIRED)
    if(NOT TARGET unofficial::libyara::libyara)
      message(FATAL_ERROR "Windows EDR_REQUIRE_YARA=ON requires vcpkg target unofficial::libyara::libyara; manual YARA_ROOT fallback is not accepted for release/package builds.")
    endif()
    set(EDR_YARA_AVAILABLE 1)
    set(EDR_YARA_TARGET unofficial::libyara::libyara)
    message(STATUS "libyara support: vcpkg target=${EDR_YARA_TARGET}")
  else()
    find_package(unofficial-libyara CONFIG QUIET)
    if(TARGET unofficial::libyara::libyara)
      set(EDR_YARA_AVAILABLE 1)
      set(EDR_YARA_TARGET unofficial::libyara::libyara)
      message(STATUS "libyara support: target=${EDR_YARA_TARGET}")
    else()
      set(_EDR_YARA_HINTS)
      if(DEFINED ENV{YARA_ROOT})
        list(APPEND _EDR_YARA_HINTS "$ENV{YARA_ROOT}")
      endif()
      if(DEFINED ENV{VCPKG_INSTALLED_X64})
        list(APPEND _EDR_YARA_HINTS "$ENV{VCPKG_INSTALLED_X64}")
      endif()
      if(DEFINED VCPKG_INSTALLED_DIR)
        list(APPEND _EDR_YARA_HINTS "${VCPKG_INSTALLED_DIR}")
        if(DEFINED VCPKG_TARGET_TRIPLET)
          list(APPEND _EDR_YARA_HINTS "${VCPKG_INSTALLED_DIR}/${VCPKG_TARGET_TRIPLET}")
        endif()
      endif()
      if(DEFINED ENV{VCPKG_ROOT} AND DEFINED VCPKG_TARGET_TRIPLET)
        list(APPEND _EDR_YARA_HINTS "$ENV{VCPKG_ROOT}/installed/${VCPKG_TARGET_TRIPLET}")
      endif()
      list(APPEND _EDR_YARA_HINTS /opt/homebrew /usr/local "C:/yara")

      find_path(YARA_INCLUDE_DIR
        NAMES yara.h yara/yara.h
        HINTS ${_EDR_YARA_HINTS}
        PATH_SUFFIXES include)
      find_library(YARA_LIB
        NAMES yara libyara yara64 libyara64
        HINTS ${_EDR_YARA_HINTS}
        PATH_SUFFIXES lib lib64)
      if(YARA_INCLUDE_DIR AND YARA_LIB)
        set(EDR_YARA_AVAILABLE 1)
        message(STATUS "libyara support: include=${YARA_INCLUDE_DIR} lib=${YARA_LIB}")
      elseif(EDR_REQUIRE_YARA)
        message(FATAL_ERROR "EDR_REQUIRE_YARA=ON but libyara was not found; install vcpkg yara feature or set YARA_ROOT (include=${YARA_INCLUDE_DIR}, lib=${YARA_LIB})")
      else()
        message(STATUS "libyara not found, fallback to builtin known-exploit matcher")
      endif()
    endif()
  endif()
endif()

set(EDR_AGENT_SOURCES
  src/main.c
  src/core/agent.c
  src/core/response_capability_manifest.c
  src/core/edr_log.c
  src/core/event_bus.c
  src/core/time_util.c
  src/config/config.c
  src/preprocess/behavior_record.c
  src/preprocess/behavior_from_slot.c
  src/preprocess/adaptive_collection.c
  src/preprocess/dedup.c
  src/preprocess/detection_decision.c
  src/preprocess/detection_profile.c
  src/preprocess/enrich_parent_info.c
  src/preprocess/emit_rules.c
  src/preprocess/encrypt_p0_rules.c
  src/preprocess/p0_source_only_contract.c
  src/preprocess/p0_rule_direct_emit.c
  src/preprocess/p0_deferred_snapshot.c
  src/preprocess/process_create_coalescer.c
  src/preprocess/process_generation.c
  src/preprocess/windows_file_identity.c
  src/preprocess/process_evidence_worker.c
  src/preprocess/process_evidence_pending.c
  src/preprocess/telemetry_admission.c
  src/preprocess/p0_rule_match.c
  src/preprocess/process_chain_depth.c
  src/preprocess/preprocess_env.c
  src/preprocess/sensor_interest.c
  src/preprocess/windows_event_policy.c
  src/preprocess/correlation_engine.c
  src/preprocess/preprocess_pipeline.c
  src/detection/detection_profile.c
  src/detection/policy_enforcement.c
  src/detection/policy_v2.c
  src/forensic/process_tree_cache.c
  src/serialize/behavior_wire.c
  src/serialize/behavior_proto.c
  src/serialize/alert_governor.c
  src/serialize/behavior_alert_emit.c
  src/serialize/behavior_proto_c.c
  src/proto/edr/v1/event.pb.c
  third_party/nanopb/pb_common.c
  third_party/nanopb/pb_encode.c
  third_party/nanopb/pb_decode.c
  src/transport/event_batch.c
  src/transport/command_result_json.c
  src/transport/ingest_http.c
  src/transport/request_signing.c
  src/transport/http_retry.c
  src/transport/transport_v2.c
  src/transport/transport_stub.c
  src/storage/queue_sqlite.c
  src/storage/local_evidence_cache.c
  src/command/command_stub.c
  src/command/command_process.c
  src/command/command_signature.c
  src/command/command_signature_helpers.c
  src/command/forensic_result_contract.c
  src/command/command_cancel.c
  src/command/command_contract.c
  src/command/agent_update_command.c
  src/command/full_installer_readiness.c
  src/command/full_installer_windows_identity.c
  src/command/agent_update_manifest.c
  src/command/agent_lifecycle_command.c
  src/command/agent_update_event.c
  src/command/command_executor.c
  src/command/command_registry.c
  src/command/command_state.c
  src/command/command_util.c
  src/command/pe_verify.c
  src/command/rtq_exec.c
  src/command/shell_exec.c
  src/command/sha256.c
  src/response/response_actions.c
  src/response/response_file.c
  src/response/response_file_security.c
  src/response/response_forensic.c
  src/response/response_utils.c
  src/forensic/deep_collector.c
  src/shell/shell_session.c
  src/pmfe/pmfe_engine.c
  src/pmfe/pmfe_pe_arch.c
  src/pmfe/pmfe_etw_preprocess.c
  src/pmfe/pid_history_pmfe.c
  src/attack_surface/attack_surface_report.c
  src/attack_surface/attack_surface_egress.c
  src/attack_surface/attack_surface_inventory.c
  src/attack_surface/security_policy_collect.c
  src/self_protect/self_protect.c
  src/self_protect/heartbeat.c
  src/self_protect/watchdog.c
  src/detection/net_fanout_core.c
  src/detection/net_fanout_detector.c
  src/resource/resource.c
  src/ave/ave_engine.c
  src/ave/ave_sdk.c
  src/ave/ave_suppression.c
  src/ave/ave_rules_meta.c
  src/ave/ave_behavior_pipeline.c
  src/ave/ave_behavior_features.c
  src/ave/ave_cross_engine_parse.c
  src/ave/ave_cross_engine_feed.c
  src/ave/ave_lf_mpmc.c
  src/ave/ave_db_update.c
  third_party/cjson/cJSON.c
)
list(APPEND EDR_AGENT_SOURCES ${EDR_P0_RULE_IR_IMPLEMENTATION_SOURCE})
if(WIN32)
  list(APPEND EDR_AGENT_SOURCES src/ave/ave_sign_whitelist_win.c)
  list(APPEND EDR_AGENT_SOURCES resources/FDSensor.rc)
  if(MSVC)
    # rc.exe receives definitions through cmcldeps. A single CMake quote escape
    # becomes -DNAME=\"value\"; using the windres form adds a literal backslash
    # and fails with C7772 "invalid string literal".
    set(_EDR_RESOURCE_VERSION_STRING
      "EDR_VERSION_STRING=\"${PROJECT_VERSION}\"")
  else()
    # GNU windres needs escaped quotes to survive its preprocessor command line.
    set(_EDR_RESOURCE_VERSION_STRING
      "EDR_VERSION_STRING=\\\"${PROJECT_VERSION}\\\"")
  endif()
  set(_EDR_RESOURCE_DEFINITIONS
    "EDR_VERSION_MAJOR=${PROJECT_VERSION_MAJOR};EDR_VERSION_MINOR=${PROJECT_VERSION_MINOR};EDR_VERSION_PATCH=${PROJECT_VERSION_PATCH};${_EDR_RESOURCE_VERSION_STRING}")
  if(MSVC)
    list(APPEND _EDR_RESOURCE_DEFINITIONS EDR_VERSION_RESOURCE_ONLY=1)
  endif()
  set_source_files_properties(resources/FDSensor.rc PROPERTIES COMPILE_DEFINITIONS
    "${_EDR_RESOURCE_DEFINITIONS}")
else()
  list(APPEND EDR_AGENT_SOURCES src/ave/ave_sign_whitelist_stub.c)
endif()
if(WIN32)
  list(APPEND EDR_AGENT_SOURCES src/attack_surface/attack_surface_win_util.c)
  list(APPEND EDR_AGENT_SOURCES src/attack_surface/listen_table_win.c)
  list(APPEND EDR_AGENT_SOURCES src/pmfe/pmfe_host_policy_win.c)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  list(APPEND EDR_AGENT_SOURCES src/pmfe/pmfe_host_policy_linux.c)
  list(APPEND EDR_AGENT_SOURCES src/pmfe/pmfe_linux_scan_util.c)
else()
  list(APPEND EDR_AGENT_SOURCES src/pmfe/pmfe_host_policy_stub.c)
endif()

if(WIN32)
  list(APPEND EDR_AGENT_SOURCES
    src/collector/collector_win.c
    src/collector/etw_observability_win.c
    src/collector/edr_a44_split_path_win.c
    src/collector/etw_tdh_win.c
    src/collector/ave_etw_feed_win.c
  )
elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND EDR_WITH_LINUX_COLLECTOR)
  list(APPEND EDR_AGENT_SOURCES src/collector/collector_linux.c)
else()
  list(APPEND EDR_AGENT_SOURCES src/collector/collector_stub.c)
endif()

# §17 Shellcode：运行时 WinDivert DLL/驱动由 x64 安装包随 Agent 目录交付；开发构建可用官方 SDK。
set(EDR_SHELLCODE_SRCS
  src/shellcode_detector/shellcode_entropy.c
  src/shellcode_detector/shellcode_heuristic.c
  src/shellcode_detector/shellcode_known.c
  src/shellcode_detector/proto_parse.c
  src/shellcode_detector/flow_dedup.c
  src/shellcode_detector/tcp_reassembly.c
)
if(WIN32)
  list(APPEND EDR_SHELLCODE_SRCS
    src/shellcode_detector/shellcode_detector_win.c
    src/shellcode_detector/windivert_capture.c
  )
else()
  list(APPEND EDR_SHELLCODE_SRCS src/shellcode_detector/shellcode_detector_none.c)
endif()
list(APPEND EDR_AGENT_SOURCES ${EDR_SHELLCODE_SRCS})

set(EDR_WEBSHELL_SRCS)
list(APPEND EDR_WEBSHELL_SRCS
  src/webshell_detector/webshell_forensic.c
  src/webshell_detector/webshell_semantic.c
)
if(WIN32)
  list(APPEND EDR_WEBSHELL_SRCS src/webshell_detector/webshell_detector_win.c)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  list(APPEND EDR_WEBSHELL_SRCS src/webshell_detector/webshell_detector_linux.c)
else()
  list(APPEND EDR_WEBSHELL_SRCS src/webshell_detector/webshell_detector_none.c)
endif()
list(APPEND EDR_AGENT_SOURCES ${EDR_WEBSHELL_SRCS})
if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/third_party/tomlc99/toml.c")
  message(FATAL_ERROR "tomlc99 required: third_party/tomlc99/toml.c (see third_party/tomlc99/README.txt)")
endif()
list(APPEND EDR_AGENT_SOURCES third_party/tomlc99/toml.c)

if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/third_party/lz4/lz4.c")
  list(APPEND EDR_AGENT_SOURCES third_party/lz4/lz4.c)
endif()

set(EDR_AVE_CORE_SOURCES
  src/ave/ave_engine.c
  src/ave/ave_sdk.c
  src/ave/ave_suppression.c
  src/ave/ave_rules_meta.c
  src/ave/ave_behavior_pipeline.c
  src/ave/ave_behavior_features.c
  src/ave/ave_cross_engine_parse.c
  src/ave/ave_cross_engine_feed.c
  src/ave/ave_lf_mpmc.c
  src/ave/ave_db_update.c
  src/command/sha256.c
)
if(WIN32)
  list(APPEND EDR_AVE_CORE_SOURCES src/ave/ave_sign_whitelist_win.c)
else()
  list(APPEND EDR_AVE_CORE_SOURCES src/ave/ave_sign_whitelist_stub.c)
endif()

add_executable(edr_agent ${EDR_AGENT_SOURCES})
if(WIN32)
  set_target_properties(edr_agent PROPERTIES OUTPUT_NAME "FDSensor")
  if(MSVC)
    # Merge the application settings into MSVC's generated manifest instead of
    # embedding a second resource with the same executable manifest ID.
    target_link_options(edr_agent PRIVATE
      "/MANIFEST:EMBED"
      "/MANIFESTINPUT:${CMAKE_CURRENT_SOURCE_DIR}/resources/FDSensor.manifest")
  endif()
  if(EDR_CREATE_LEGACY_AGENT_ALIAS)
    add_custom_command(TARGET edr_agent POST_BUILD
      COMMAND "${CMAKE_COMMAND}" -E copy_if_different
        "$<TARGET_FILE:edr_agent>"
        "$<TARGET_FILE_DIR:edr_agent>/edr_agent$<TARGET_FILE_SUFFIX:edr_agent>"
      COMMENT "Creating legacy edr_agent.exe alias for compatibility"
      VERBATIM)
  endif()
endif()

if(WIN32)
  add_executable(fd_installer_worker src/installer_worker/installer_worker_win.c)
  set_target_properties(fd_installer_worker PROPERTIES OUTPUT_NAME "FDSecurityInstallerWorker")
  target_compile_definitions(fd_installer_worker PRIVATE UNICODE _UNICODE _CRT_SECURE_NO_WARNINGS)
  target_sources(fd_installer_worker PRIVATE src/platform/windows_spawn_lock.c)
  target_sources(fd_installer_worker PRIVATE src/platform/windows_handoff.c src/platform/windows_spawn.c)
  target_include_directories(fd_installer_worker PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
  target_link_libraries(fd_installer_worker PRIVATE advapi32 shell32 user32)
  if(MSVC)
    # binary_hot requires unchanged lifecycle helpers to retain byte-identical
    # Runtime identity across otherwise source-only releases.
    target_link_options(fd_installer_worker PRIVATE /Brepro)
  endif()
  edr_apply_common_warnings(fd_installer_worker)

  add_executable(fd_headless_uninstaller WIN32 src/installer_worker/headless_uninstaller_win.c)
  set_target_properties(fd_headless_uninstaller PROPERTIES OUTPUT_NAME "uninstall")
  target_compile_definitions(fd_headless_uninstaller PRIVATE UNICODE _UNICODE _CRT_SECURE_NO_WARNINGS)
  target_sources(fd_headless_uninstaller PRIVATE src/platform/windows_handoff.c)
  target_sources(fd_headless_uninstaller PRIVATE src/platform/windows_native_manifest.c)
  target_sources(fd_headless_uninstaller PRIVATE src/command/sha256.c)
  if(MSVC)
    # The dialog text is authored as UTF-8 wide string literals. Without an
    # explicit source charset, MSVC decodes this file through the runner's ACP
    # and the resulting uninstall prompts are permanently mojibaked.
    target_compile_options(fd_headless_uninstaller PRIVATE /utf-8)
    # Keep the detached finalizer byte-identical when its inputs are unchanged;
    # the release gate compares this exact component before binary replacement.
    target_link_options(fd_headless_uninstaller PRIVATE /Brepro)
    # The detached finalizer must remain runnable after it starts deleting the
    # installation directory. A dynamic CRT would keep DLLs in that directory
    # loaded and make the finalizer lock the tree it is responsible for removing.
    set_property(TARGET fd_headless_uninstaller PROPERTY
      MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
  endif()
  target_sources(fd_headless_uninstaller PRIVATE third_party/cjson/cJSON.c)
  target_include_directories(fd_headless_uninstaller PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/cjson)
  target_link_libraries(fd_headless_uninstaller PRIVATE shell32 user32 advapi32 rpcrt4 crypt32 ncrypt winhttp ole32 oleaut32 taskschd)
  edr_apply_common_warnings(fd_headless_uninstaller)
endif()

# C baseline 取证采集器(系统命令级,仅 libc,无第三方依赖)。
# 命名裁决:Go 适配器(forensic-collector/, 封装 Velociraptor)输出规范名 forensic_collector(.exe)为主;
# 本 C target 输出 forensic_collector_builtin(.exe)作兜底,由 agent 在 velo 不可用时回退调用。
# 二者部署到同一目录 C:\Program Files\FDSecurity\collector\,靠文件名区分。
if(EDR_WITH_FORENSIC_COLLECTOR)
  add_executable(forensic_collector tools/forensic_collector/main.c)
  set_target_properties(forensic_collector PROPERTIES OUTPUT_NAME "forensic_collector_builtin")
  if(MSVC)
    target_compile_definitions(forensic_collector PRIVATE _CRT_SECURE_NO_WARNINGS)
  endif()
  edr_apply_common_warnings(forensic_collector)
endif()

target_include_directories(edr_agent PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/include
  ${CMAKE_CURRENT_SOURCE_DIR}/src/ave
  ${CMAKE_CURRENT_SOURCE_DIR}/src/collector
  ${CMAKE_CURRENT_SOURCE_DIR}/src/pmfe
  ${CMAKE_CURRENT_SOURCE_DIR}/third_party/tomlc99
  ${CMAKE_CURRENT_SOURCE_DIR}/third_party/cjson
  ${CMAKE_CURRENT_SOURCE_DIR}/third_party/nanopb
  ${CMAKE_CURRENT_SOURCE_DIR}/third_party/windivert
  ${CMAKE_CURRENT_SOURCE_DIR}/src/proto
)
target_compile_definitions(edr_agent PRIVATE
  EDR_HAVE_NANOPB=1
  "EDR_AGENT_VERSION_STRING=\"${EDR_AGENT_VERSION_STRING}\""
  "EDR_AGENT_UPDATE_SCRIPT_PATH=\"edr_agent_inplace_update.ps1\""
)
if(MSVC)
  target_compile_definitions(edr_agent PRIVATE _CRT_SECURE_NO_WARNINGS _CRT_NONSTDC_NO_WARNINGS)
endif()
if(EDR_PCRE2_AVAILABLE)
  target_compile_definitions(edr_agent PRIVATE EDR_HAVE_PCRE2=1)
  if(EDR_PCRE2_TARGET)
    target_link_libraries(edr_agent PRIVATE ${EDR_PCRE2_TARGET})
  else()
    target_include_directories(edr_agent PRIVATE ${EDR_PCRE2_INCLUDE_DIR})
    target_link_libraries(edr_agent PRIVATE ${EDR_PCRE2_LIBRARY})
  endif()
endif()
if(EDR_WITH_P0_RULES_OPENSSL AND OpenSSL_FOUND)
  target_compile_definitions(edr_agent PRIVATE EDR_HAVE_OPENSSL_FL=1)
  if(TARGET OpenSSL::SSL)
    target_link_libraries(edr_agent PRIVATE OpenSSL::SSL OpenSSL::Crypto)
  else()
    target_link_libraries(edr_agent PRIVATE OpenSSL::Crypto)
  endif()
endif()

if(EDR_WITH_INGEST_HTTPS_OPENSSL AND OpenSSL_FOUND)
  target_compile_definitions(edr_agent PRIVATE EDR_HAVE_OPENSSL_HTTP=1)
  if(TARGET OpenSSL::SSL)
    target_link_libraries(edr_agent PRIVATE OpenSSL::SSL OpenSSL::Crypto)
  else()
    target_link_libraries(edr_agent PRIVATE OpenSSL::Crypto)
  endif()
endif()
if(EDR_WITH_HTTP2_CURL AND CURL_FOUND)
  target_compile_definitions(edr_agent PRIVATE EDR_HAVE_CURL_HTTP2=1)
  if(TARGET CURL::libcurl)
    target_link_libraries(edr_agent PRIVATE CURL::libcurl)
  else()
    target_include_directories(edr_agent PRIVATE ${CURL_INCLUDE_DIRS})
    target_link_libraries(edr_agent PRIVATE ${CURL_LIBRARIES})
  endif()
endif()
if(EDR_WITH_ZSTD AND EDR_ZSTD_AVAILABLE)
  target_compile_definitions(edr_agent PRIVATE EDR_HAVE_ZSTD=1)
  if(EDR_ZSTD_TARGET)
    target_link_libraries(edr_agent PRIVATE ${EDR_ZSTD_TARGET})
  else()
    target_include_directories(edr_agent PRIVATE ${EDR_ZSTD_INCLUDE_DIR})
    target_link_libraries(edr_agent PRIVATE ${EDR_ZSTD_LIBRARY})
  endif()
endif()

if(EDR_YARA_AVAILABLE)
  target_compile_definitions(edr_agent PRIVATE EDR_HAVE_YARA=1)
  if(EDR_YARA_TARGET)
    target_link_libraries(edr_agent PRIVATE ${EDR_YARA_TARGET})
  else()
    target_include_directories(edr_agent PRIVATE ${YARA_INCLUDE_DIR})
    target_link_libraries(edr_agent PRIVATE ${YARA_LIB})
  endif()
endif()

if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/third_party/lz4/lz4.c")
  target_include_directories(edr_agent PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/lz4
  )
  target_compile_definitions(edr_agent PRIVATE EDR_HAVE_LZ4=1)
endif()

edr_apply_common_warnings(edr_agent)

if(WIN32)
  configure_file(${CMAKE_CURRENT_SOURCE_DIR}/scripts/edr_agent_inplace_update.ps1
    ${CMAKE_CURRENT_BINARY_DIR}/edr_agent_inplace_update.ps1 COPYONLY)
  target_compile_definitions(edr_agent PRIVATE EDR_OS_WINDOWS=1)
  target_sources(edr_agent PRIVATE src/platform/windows_spawn_lock.c)
  target_sources(edr_agent PRIVATE src/platform/windows_handoff.c src/platform/windows_spawn.c)
  target_sources(edr_agent PRIVATE src/platform/windows_native_manifest.c)
  target_link_libraries(edr_agent PRIVATE advapi32 shell32 ole32 oleaut32 uuid taskschd tdh ws2_32 iphlpapi psapi crypt32 wintrust wevtapi netapi32 dbghelp)
else()
  target_compile_definitions(edr_agent PRIVATE EDR_OS_POSIX=1)
  if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_compile_definitions(edr_agent PRIVATE EDR_OS_LINUX=1)
  endif()
endif()

find_package(Threads REQUIRED)
target_link_libraries(edr_agent PRIVATE Threads::Threads)
if(UNIX AND NOT WIN32)
  target_link_libraries(edr_agent PRIVATE m)
endif()

find_package(SQLite3 QUIET)
if(SQLite3_FOUND)
  if(TARGET SQLite3::SQLite3)
    target_link_libraries(edr_agent PRIVATE SQLite3::SQLite3)
  else()
    target_link_libraries(edr_agent PRIVATE SQLite::SQLite3)
  endif()
  target_compile_definitions(edr_agent PRIVATE EDR_HAVE_SQLITE=1)
elseif(EDR_REQUIRE_SQLITE)
  message(FATAL_ERROR "EDR_REQUIRE_SQLITE=ON but SQLite3 was not found")
endif()
message(STATUS "SQLite local storage support: ${SQLite3_FOUND}")

if(EDR_BUILD_AVE_SHARED_LIB)
  add_subdirectory(src/ave)
endif()

if(EDR_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()
