cmake_minimum_required(VERSION 3.16)
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

if(MSVC)
  add_compile_definitions(_CRT_SECURE_NO_WARNINGS _CRT_NONSTDC_NO_WARNINGS)
  if(WIN32)
    string(TOLOWER "${CMAKE_SYSTEM_PROCESSOR}" _edr_system_processor_lc)
    if(_edr_system_processor_lc MATCHES "arm64|aarch64")
      set(_edr_msvc_win_arch_define _ARM64_=1)
    elseif(CMAKE_SIZEOF_VOID_P EQUAL 8)
      set(_edr_msvc_win_arch_define _AMD64_=1)
    else()
      set(_edr_msvc_win_arch_define _X86_=1)
    endif()
    add_compile_definitions(${_edr_msvc_win_arch_define})
    message(STATUS "MSVC Windows SDK target architecture macro: ${_edr_msvc_win_arch_define}")
  endif()
endif()

function(edr_apply_common_warnings target_name)
  if(MSVC)
    target_compile_options(${target_name} PRIVATE /W4 /WX-)
  else()
    target_compile_options(${target_name} PRIVATE -Wall -Wextra -Wno-unused-parameter)
  endif()
endfunction()

option(EDR_BUILD_TESTS "Build CTest smoke/regression targets" ON)
option(EDR_WITH_LINUX_COLLECTOR "On Linux, build collector_linux.c instead of collector_stub.c" ON)
set(EDR_P0_RULES_BUNDLE_VERSION
  "edr-dynamic-rules-v1-r268-57605ae1"
  CACHE STRING "P0/dynamic rule bundle version")
set(EDR_AGENT_VERSION_STRING
  "${PROJECT_VERSION}"
  CACHE STRING "Agent version string reported to the platform")
message(STATUS "gRPC client removed from product build; HTTP ingest/control only")

option(EDR_WITH_ONNXRUNTIME "Link ONNX Runtime C API for AVE real inference (optional)" OFF)
option(EDR_WITH_AVE_BEHAVIOR_ONNX "Deprecated: run behavior.onnx on endpoint instead of server-side evaluation" OFF)
set(EDR_ONNXRUNTIME_AVAILABLE 0)
if(EDR_WITH_ONNXRUNTIME)
  find_path(ONNXRUNTIME_INCLUDE_DIR NAMES onnxruntime_c_api.h
    PATHS
      ENV ONNXRUNTIME_ROOT
      "$ENV{ONNXRUNTIME_ROOT}/include"
      /opt/homebrew/opt/onnxruntime/include
      /usr/local/opt/onnxruntime/include
      "C:/onnxruntime/include"
    PATH_SUFFIXES onnxruntime "")
  find_library(ONNXRUNTIME_LIB NAMES onnxruntime
    PATHS
      ENV ONNXRUNTIME_ROOT
      "$ENV{ONNXRUNTIME_ROOT}/lib"
      /opt/homebrew/opt/onnxruntime/lib
      /usr/local/opt/onnxruntime/lib
      "C:/onnxruntime/lib")
  if(ONNXRUNTIME_INCLUDE_DIR AND ONNXRUNTIME_LIB)
    set(EDR_ONNXRUNTIME_AVAILABLE 1)
  else()
    message(WARNING "EDR_WITH_ONNXRUNTIME=ON but onnxruntime not found (install or set ONNXRUNTIME_ROOT)")
  endif()
endif()

option(EDR_BUILD_AVE_SHARED_LIB "Build standalone edr_ave_shared (AVE DLL/so for embedding)" OFF)
option(EDR_WITH_FL_TRAINER "Deprecated: federated learning trainer is removed from endpoint product builds" OFF)
option(EDR_WITH_FL_KAFKA "Deprecated: federated learning Kafka consumer is removed from endpoint product builds" OFF)
option(EDR_CREATE_LEGACY_AGENT_ALIAS "Create legacy edr_agent.exe alias next to FDSensor.exe on Windows" OFF)
set(TORCH_ROOT "" CACHE PATH "Deprecated: LibTorch was used only by the removed endpoint FL trainer")
option(EDR_WITH_LIBTORCH "Deprecated: LibTorch local FL training is removed from endpoint product builds" OFF)
if(EDR_WITH_FL_TRAINER OR EDR_WITH_FL_KAFKA OR EDR_WITH_LIBTORCH)
  message(FATAL_ERROR "Endpoint FL training has been removed from product builds; keep model learning server-side.")
endif()
option(EDR_WITH_YARA "Enable libyara for known exploit rules" ON)
option(EDR_REQUIRE_YARA "Fail configure when libyara is unavailable" OFF)
option(EDR_REQUIRE_SQLITE "Fail configure when SQLite3 is unavailable" OFF)
option(EDR_WITH_FORENSIC_COLLECTOR "Build the standalone forensic_collector binary" ON)
if(EDR_REQUIRE_YARA AND NOT EDR_WITH_YARA)
  message(FATAL_ERROR "EDR_REQUIRE_YARA=ON requires EDR_WITH_YARA=ON")
endif()

set(EDR_PCRE2_AVAILABLE 0)
set(EDR_PCRE2_TARGET "")
find_package(PCRE2 CONFIG QUIET)
if(TARGET PCRE2::8BIT)
  set(EDR_PCRE2_AVAILABLE 1)
  set(EDR_PCRE2_TARGET PCRE2::8BIT)
elseif(TARGET PCRE2::pcre2-8)
  set(EDR_PCRE2_AVAILABLE 1)
  set(EDR_PCRE2_TARGET PCRE2::pcre2-8)
else()
  find_path(EDR_PCRE2_INCLUDE_DIR NAMES pcre2.h
    PATHS
      ENV PCRE2_ROOT
      "$ENV{PCRE2_ROOT}/include"
      /opt/homebrew/include
      /usr/local/include
      "C:/vcpkg/installed/x64-windows/include")
  find_library(EDR_PCRE2_LIBRARY NAMES pcre2-8 pcre2-8-static
    PATHS
      ENV PCRE2_ROOT
      "$ENV{PCRE2_ROOT}/lib"
      /opt/homebrew/lib
      /usr/local/lib
      "C:/vcpkg/installed/x64-windows/lib")
  if(EDR_PCRE2_INCLUDE_DIR AND EDR_PCRE2_LIBRARY)
    set(EDR_PCRE2_AVAILABLE 1)
  endif()
endif()
message(STATUS "P0 IR rule engine PCRE2 support: ${EDR_PCRE2_AVAILABLE}")

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
set(EDR_LIBTORCH_AVAILABLE 0)
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
  src/preprocess/p0_rule_direct_emit.c
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
  src/transport/ingest_http.c
  src/transport/request_signing.c
  src/transport/transport_v2.c
  src/transport/transport_stub.c
  src/storage/queue_sqlite.c
  src/storage/local_evidence_cache.c
  src/command/command_stub.c
  src/command/forensic_result_contract.c
  src/command/command_cancel.c
  src/command/command_contract.c
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
  src/response/response_forensic.c
  src/response/response_utils.c
  src/forensic/deep_collector.c
  src/shell/shell_session.c
  src/pmfe/pmfe_engine.c
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
  src/ave/ave_onnx_infer.c
  src/ave/ave_sdk.c
  src/ave/ave_suppression.c
  src/ave/ave_rules_meta.c
  src/ave/ave_behavior_pipeline.c
  src/ave/ave_behavior_features.c
  src/ave/ave_cross_engine_parse.c
  src/ave/ave_cross_engine_feed.c
  src/ave/ave_lf_mpmc.c
  src/ave/ave_hotfix.c
  src/ave/ave_db_update.c
  src/ave/ave_static_features.c
  third_party/cjson/cJSON.c
)
if(EDR_WITH_AVE_BEHAVIOR_ONNX)
  list(APPEND EDR_AGENT_SOURCES src/ave/edr_onnx_behavior_fl_tensor_export.c)
endif()
if(EDR_PCRE2_AVAILABLE)
  list(APPEND EDR_AGENT_SOURCES
    src/preprocess/p0_rule_ir.c
  )
else()
  list(APPEND EDR_AGENT_SOURCES src/preprocess/p0_rule_ir_stub.c)
endif()
if(WIN32)
  list(APPEND EDR_AGENT_SOURCES src/ave/ave_sign_whitelist_win.c)
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
set(EDR_FL_KAFKA_AVAILABLE 0)

if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/third_party/tomlc99/toml.c")
  message(FATAL_ERROR "tomlc99 required: third_party/tomlc99/toml.c (see third_party/tomlc99/README.txt)")
endif()
list(APPEND EDR_AGENT_SOURCES third_party/tomlc99/toml.c)

if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/third_party/lz4/lz4.c")
  list(APPEND EDR_AGENT_SOURCES third_party/lz4/lz4.c)
endif()

set(EDR_AVE_CORE_SOURCES
  src/ave/ave_engine.c
  src/ave/ave_onnx_infer.c
  src/ave/ave_static_features.c
  src/ave/ave_sdk.c
  src/ave/ave_suppression.c
  src/ave/ave_rules_meta.c
  src/ave/ave_behavior_pipeline.c
  src/ave/ave_behavior_features.c
  src/ave/ave_cross_engine_parse.c
  src/ave/ave_cross_engine_feed.c
  src/ave/ave_lf_mpmc.c
  src/ave/ave_hotfix.c
  src/ave/ave_db_update.c
  src/command/sha256.c
)
if(EDR_WITH_AVE_BEHAVIOR_ONNX)
  list(APPEND EDR_AVE_CORE_SOURCES src/ave/edr_onnx_behavior_fl_tensor_export.c)
endif()
if(WIN32)
  list(APPEND EDR_AVE_CORE_SOURCES src/ave/ave_sign_whitelist_win.c)
else()
  list(APPEND EDR_AVE_CORE_SOURCES src/ave/ave_sign_whitelist_stub.c)
endif()

add_executable(edr_agent ${EDR_AGENT_SOURCES})
if(WIN32)
  set_target_properties(edr_agent PROPERTIES OUTPUT_NAME "FDSensor")
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
  target_link_libraries(fd_installer_worker PRIVATE advapi32 shell32 user32)
  edr_apply_common_warnings(fd_installer_worker)
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
  "EDR_P0_RULES_BUNDLE_VERSION=\"${EDR_P0_RULES_BUNDLE_VERSION}\""
)
if(MSVC)
  target_compile_definitions(edr_agent PRIVATE _CRT_SECURE_NO_WARNINGS _CRT_NONSTDC_NO_WARNINGS)
endif()
if(EDR_WITH_AVE_BEHAVIOR_ONNX)
  target_compile_definitions(edr_agent PRIVATE EDR_WITH_AVE_BEHAVIOR_ONNX=1)
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

if(EDR_ONNXRUNTIME_AVAILABLE)
  target_compile_definitions(edr_agent PRIVATE EDR_HAVE_ONNXRUNTIME=1)
  target_include_directories(edr_agent PRIVATE ${ONNXRUNTIME_INCLUDE_DIR})
  target_link_libraries(edr_agent PRIVATE ${ONNXRUNTIME_LIB})
  if(APPLE)
    get_filename_component(_edr_ort_libdir "${ONNXRUNTIME_LIB}" DIRECTORY)
    set_target_properties(edr_agent PROPERTIES BUILD_RPATH "${_edr_ort_libdir}")
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
  target_compile_definitions(edr_agent PRIVATE EDR_OS_WINDOWS=1)
  target_link_libraries(edr_agent PRIVATE advapi32 tdh ws2_32 iphlpapi psapi crypt32 wintrust wevtapi netapi32 dbghelp)
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
