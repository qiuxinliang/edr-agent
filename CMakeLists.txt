cmake_minimum_required(VERSION 3.16)
project(edr_agent C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
# MSVC：stdatomic.h 需 /experimental:c11atomics 与 /std:c11+。仅用 target 的
# COMPILE_LANGUAGE:C 在 vcpkg 工具链 + VS 下部分 .c 未带上，会 C1189 "C atomic support is not enabled"
if(MSVC)
  string(APPEND CMAKE_C_FLAGS " /experimental:c11atomics /std:c17")
endif()

option(EDR_WITH_GRPC "Build with gRPC++ EventIngest client (mTLS)" ON)
option(EDR_WITH_LINUX_COLLECTOR "On Linux, build collector_linux.c instead of collector_stub.c" ON)
list(APPEND CMAKE_PREFIX_PATH
  /usr/local/opt/grpc
  /opt/homebrew/opt/grpc
  /usr/local
  /opt/homebrew
)
set(EDR_GRPC_CLIENT_AVAILABLE 0)
if(EDR_WITH_GRPC)
  # 只通过 gRPC CONFIG 拉取 protobuf，避免与独立 Protobuf 包重复定义目标
  find_package(gRPC CONFIG QUIET)
  if(TARGET gRPC::grpc++)
    set(EDR_GRPC_CLIENT_AVAILABLE 1)
  endif()
endif()
set(EDR_GRPC_CLIENT_AVAILABLE ${EDR_GRPC_CLIENT_AVAILABLE} CACHE INTERNAL "EDR gRPC client availability")
if(NOT EDR_GRPC_CLIENT_AVAILABLE)
  message(STATUS "gRPC client disabled (install grpc/protobuf or set EDR_WITH_GRPC=OFF)")
else()
  message(STATUS "gRPC client enabled (real EventIngest transport)")
endif()

option(EDR_WITH_ONNXRUNTIME "Link ONNX Runtime C API for AVE real inference (optional)" OFF)
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
option(EDR_WITH_FL_TRAINER "Build federated learning local trainer threads (stub)" OFF)
option(EDR_WITH_FL_KAFKA "FL: consume round announces via librdkafka (requires EDR_WITH_FL_TRAINER)" OFF)
set(TORCH_ROOT "" CACHE PATH "LibTorch 根目录（含 share/cmake/Torch），见 pytorch.org/cppdocs/installing.html")
option(EDR_WITH_LIBTORCH "FL local_train 使用 LibTorch（需 TORCH_ROOT / CMAKE_PREFIX_PATH）" OFF)
option(EDR_WITH_YARA "Enable libyara for known exploit rules" ON)

find_package(OpenSSL QUIET)
set(EDR_LIBTORCH_AVAILABLE 0)
if(EDR_WITH_LIBTORCH)
  list(APPEND CMAKE_PREFIX_PATH "${TORCH_ROOT}" "$ENV{TORCH_ROOT}")
  find_package(Torch QUIET)
  if(Torch_FOUND)
    set(EDR_LIBTORCH_AVAILABLE 1)
    message(STATUS "LibTorch found for FL local_train")
  else()
    message(STATUS "LibTorch not found (set TORCH_ROOT or CMAKE_PREFIX_PATH to libtorch)")
  endif()
endif()
set(EDR_YARA_AVAILABLE 0)
if(EDR_WITH_YARA)
  find_path(YARA_INCLUDE_DIR NAMES yara.h
    PATHS
      ENV YARA_ROOT
      "$ENV{YARA_ROOT}/include"
      /opt/homebrew/include
      /usr/local/include
      "C:/yara/include")
  find_library(YARA_LIB NAMES yara libyara
    PATHS
      ENV YARA_ROOT
      "$ENV{YARA_ROOT}/lib"
      /opt/homebrew/lib
      /usr/local/lib
      "C:/yara/lib")
  if(YARA_INCLUDE_DIR AND YARA_LIB)
    set(EDR_YARA_AVAILABLE 1)
  else()
    message(STATUS "libyara not found, fallback to builtin known-exploit matcher")
  endif()
endif()

set(EDR_AGENT_SOURCES
  src/main.c
  src/core/agent.c
  src/core/event_bus.c
  src/core/time_util.c
  src/config/config.c
  src/preprocess/behavior_record.c
  src/preprocess/process_chain_depth.c
  src/preprocess/behavior_from_slot.c
  src/preprocess/dedup.c
  src/preprocess/emit_rules.c
  src/preprocess/preprocess_pipeline.c
  src/serialize/behavior_wire.c
  src/serialize/behavior_proto.c
  src/serialize/behavior_alert_emit.c
  src/serialize/behavior_proto_c.c
  src/proto/edr/v1/event.pb.c
  third_party/nanopb/pb_common.c
  third_party/nanopb/pb_encode.c
  third_party/nanopb/pb_decode.c
  src/transport/event_batch.c
  src/transport/ingest_http.c
  src/transport/transport_stub.c
  src/storage/queue_sqlite.c
  src/command/command_stub.c
  src/command/sha256.c
  src/pmfe/pmfe_engine.c
  src/pmfe/pmfe_etw_preprocess.c
  src/pmfe/pid_history_pmfe.c
  src/attack_surface/attack_surface_report.c
  src/attack_surface/attack_surface_egress.c
  src/attack_surface/security_policy_collect.c
  src/self_protect/self_protect.c
  src/resource/resource.c
  src/ave/ave_engine.c
  src/ave/ave_onnx_infer.c
  src/ave/edr_onnx_behavior_fl_tensor_export.c
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
  src/ave/fl_feature_provider.c
)
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

# §17 Shellcode：头文件/WinDivert.lib 来自官方 SDK，通过 WINDIVERT_ROOT 传入；运行部署约定见 README（DLL 在 %SystemRoot%\System32）。
set(EDR_SHELLCODE_SRCS
  src/shellcode_detector/shellcode_entropy.c
  src/shellcode_detector/shellcode_heuristic.c
  src/shellcode_detector/shellcode_known.c
  src/shellcode_detector/proto_parse.c
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
list(APPEND EDR_WEBSHELL_SRCS src/webshell_detector/webshell_forensic.c)
if(WIN32)
  list(APPEND EDR_WEBSHELL_SRCS src/webshell_detector/webshell_detector_win.c)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  list(APPEND EDR_WEBSHELL_SRCS src/webshell_detector/webshell_detector_linux.c)
else()
  list(APPEND EDR_WEBSHELL_SRCS src/webshell_detector/webshell_detector_none.c)
endif()
list(APPEND EDR_AGENT_SOURCES ${EDR_WEBSHELL_SRCS})

set(EDR_FL_KAFKA_AVAILABLE 0)
if(EDR_WITH_FL_KAFKA AND NOT EDR_WITH_FL_TRAINER)
  message(FATAL_ERROR "EDR_WITH_FL_KAFKA requires EDR_WITH_FL_TRAINER=ON")
endif()
if(EDR_WITH_FL_TRAINER AND EDR_WITH_FL_KAFKA)
  find_package(PkgConfig QUIET)
  if(PkgConfig_FOUND)
    pkg_check_modules(RDKAFKA QUIET IMPORTED_TARGET rdkafka)
  endif()
  if(RDKAFKA_FOUND AND TARGET PkgConfig::RDKAFKA)
    set(EDR_FL_KAFKA_AVAILABLE 1)
  else()
    find_path(RDKAFKA_INCLUDE_DIR NAMES librdkafka/rdkafka.h
      PATHS
        /opt/homebrew/include
        /usr/local/include
        "$ENV{HOMEBREW_PREFIX}/include"
        "C:/vcpkg/installed/x64-windows/include")
    find_library(RDKAFKA_LIBRARY NAMES rdkafka
      PATHS
        /opt/homebrew/lib
        /usr/local/lib
        "$ENV{HOMEBREW_PREFIX}/lib"
        "C:/vcpkg/installed/x64-windows/lib")
    if(RDKAFKA_INCLUDE_DIR AND RDKAFKA_LIBRARY)
      set(EDR_FL_KAFKA_AVAILABLE 1)
    endif()
  endif()
  if(NOT EDR_FL_KAFKA_AVAILABLE)
    message(FATAL_ERROR "EDR_WITH_FL_KAFKA=ON but librdkafka not found (install librdkafka; pkg-config rdkafka or set CMAKE_PREFIX_PATH)")
  endif()
endif()

set(EDR_FL_TRAINER_SOURCES
  src/fl_trainer/fl_trainer.c
  src/fl_trainer/fl_round.c
  src/fl_trainer/fl_samples_db.c
  src/fl_trainer/local_train_core.c
  src/fl_trainer/fl_dp.c
  src/fl_trainer/fl_privacy_budget.c
  src/fl_trainer/fl_crypto.c
  src/fl_trainer/fl_gradient_upload.c
  src/fl_trainer/fl_frozen_layers.c
  src/fl_trainer/fl_pb_wire.c
  src/fl_trainer/fl_b64.c
  src/fl_trainer/fl_http_upload.c
  src/fl_trainer/fl_kafka_stub.c
)
if(EDR_WITH_FL_TRAINER AND EDR_FL_KAFKA_AVAILABLE)
  list(APPEND EDR_FL_TRAINER_SOURCES src/fl_trainer/fl_kafka_rdkafka.c)
else()
  list(APPEND EDR_FL_TRAINER_SOURCES src/fl_trainer/fl_kafka_poll_noop.c)
endif()
if(EDR_WITH_FL_TRAINER AND EDR_LIBTORCH_AVAILABLE)
  list(APPEND EDR_FL_TRAINER_SOURCES src/fl_trainer/local_train_torch.cpp)
endif()
if(EDR_WITH_FL_TRAINER AND EDR_GRPC_CLIENT_AVAILABLE)
  list(APPEND EDR_FL_TRAINER_SOURCES src/fl_trainer/fl_grpc_upload.cpp)
endif()
if(EDR_WITH_FL_TRAINER)
  list(APPEND EDR_AGENT_SOURCES ${EDR_FL_TRAINER_SOURCES})
endif()

if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/third_party/tomlc99/toml.c")
  message(FATAL_ERROR "tomlc99 required: third_party/tomlc99/toml.c (see third_party/tomlc99/README.txt)")
endif()
list(APPEND EDR_AGENT_SOURCES third_party/tomlc99/toml.c)

if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/third_party/lz4/lz4.c")
  list(APPEND EDR_AGENT_SOURCES third_party/lz4/lz4.c)
endif()

if(EDR_GRPC_CLIENT_AVAILABLE)
  list(APPEND EDR_AGENT_SOURCES
    src/transport/grpc_client_impl.cpp
    src/grpc_gen/edr/v1/ingest.pb.cc
    src/grpc_gen/edr/v1/ingest.grpc.pb.cc
  )
else()
  list(APPEND EDR_AGENT_SOURCES src/transport/grpc_client_stub.c)
endif()

set(EDR_AVE_CORE_SOURCES
  src/ave/ave_engine.c
  src/ave/ave_onnx_infer.c
  src/ave/edr_onnx_behavior_fl_tensor_export.c
  src/ave/ave_static_features.c
  src/ave/ave_sdk.c
  src/ave/fl_feature_provider.c
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
if(WIN32)
  list(APPEND EDR_AVE_CORE_SOURCES src/ave/ave_sign_whitelist_win.c)
else()
  list(APPEND EDR_AVE_CORE_SOURCES src/ave/ave_sign_whitelist_stub.c)
endif()

add_executable(edr_agent ${EDR_AGENT_SOURCES})

target_include_directories(edr_agent PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/include
  ${CMAKE_CURRENT_SOURCE_DIR}/src/ave
  ${CMAKE_CURRENT_SOURCE_DIR}/src/fl_trainer
  ${CMAKE_CURRENT_SOURCE_DIR}/src/collector
  ${CMAKE_CURRENT_SOURCE_DIR}/src/pmfe
  ${CMAKE_CURRENT_SOURCE_DIR}/third_party/tomlc99
  ${CMAKE_CURRENT_SOURCE_DIR}/third_party/nanopb
  ${CMAKE_CURRENT_SOURCE_DIR}/third_party/windivert
  ${CMAKE_CURRENT_SOURCE_DIR}/src/proto
)
target_compile_definitions(edr_agent PRIVATE EDR_HAVE_NANOPB=1)
if(EDR_WITH_FL_TRAINER)
  target_compile_definitions(edr_agent PRIVATE EDR_WITH_FL_TRAINER=1)
endif()
if(EDR_WITH_FL_TRAINER AND EDR_LIBTORCH_AVAILABLE)
  target_compile_definitions(edr_agent PRIVATE EDR_HAVE_LIBTORCH=1)
  target_link_libraries(edr_agent PRIVATE ${TORCH_LIBRARIES})
  if(TORCH_CXX_FLAGS)
    separate_arguments(_edr_torch_cxx_flags UNIX_COMMAND "${TORCH_CXX_FLAGS}")
    set_property(SOURCE src/fl_trainer/local_train_torch.cpp APPEND PROPERTY COMPILE_OPTIONS
                 ${_edr_torch_cxx_flags})
  endif()
endif()
if(EDR_WITH_FL_TRAINER AND OpenSSL_FOUND)
  target_compile_definitions(edr_agent PRIVATE EDR_HAVE_OPENSSL_FL=1)
  if(TARGET OpenSSL::SSL)
    target_link_libraries(edr_agent PRIVATE OpenSSL::SSL OpenSSL::Crypto)
  else()
    target_link_libraries(edr_agent PRIVATE OpenSSL::Crypto)
  endif()
endif()
if(EDR_WITH_FL_TRAINER AND EDR_GRPC_CLIENT_AVAILABLE)
  target_compile_definitions(edr_agent PRIVATE EDR_HAVE_GRPC_FL=1)
endif()

if(EDR_WITH_FL_TRAINER AND EDR_FL_KAFKA_AVAILABLE)
  if(TARGET PkgConfig::RDKAFKA)
    target_link_libraries(edr_agent PRIVATE PkgConfig::RDKAFKA)
  else()
    target_include_directories(edr_agent PRIVATE ${RDKAFKA_INCLUDE_DIR})
    target_link_libraries(edr_agent PRIVATE ${RDKAFKA_LIBRARY})
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
  target_include_directories(edr_agent PRIVATE ${YARA_INCLUDE_DIR})
  target_link_libraries(edr_agent PRIVATE ${YARA_LIB})
endif()

if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/third_party/lz4/lz4.c")
  target_include_directories(edr_agent PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/lz4
  )
  target_compile_definitions(edr_agent PRIVATE EDR_HAVE_LZ4=1)
endif()

if(EDR_GRPC_CLIENT_AVAILABLE)
  target_include_directories(edr_agent PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src/grpc_gen)
  target_compile_definitions(edr_agent PRIVATE EDR_HAVE_GRPC=1)
  target_link_libraries(edr_agent PRIVATE gRPC::grpc++ protobuf::libprotobuf)
  # gRPC / protobuf 生成代码会触发第三方头里的弃用符号告警，仅对这些源文件压掉
  if(MSVC)
    set(_edr_grpc_no_dep_warn /wd4996)
  else()
    set(_edr_grpc_no_dep_warn -Wno-deprecated-declarations)
  endif()
  set_source_files_properties(
    src/transport/grpc_client_impl.cpp
    src/grpc_gen/edr/v1/ingest.pb.cc
    src/grpc_gen/edr/v1/ingest.grpc.pb.cc
    PROPERTIES COMPILE_OPTIONS "${_edr_grpc_no_dep_warn}"
  )
  if(EDR_WITH_FL_TRAINER)
    set_source_files_properties(
      src/fl_trainer/fl_grpc_upload.cpp
      PROPERTIES COMPILE_OPTIONS "${_edr_grpc_no_dep_warn}"
    )
  endif()
endif()

# third_party tomlc99：不修改上游；MSVC /W4 下 C4244/C4267/C4702 在部分 CI（或 /WX）下会当错误
if(MSVC)
  set_source_files_properties(
    "${CMAKE_CURRENT_SOURCE_DIR}/third_party/tomlc99/toml.c"
    PROPERTIES COMPILE_OPTIONS "/wd4244;/wd4267;/wd4702"
  )
endif()

if(MSVC)
  target_compile_options(edr_agent PRIVATE /W4 /WX-)
  # 与 SetConsole*CP(65001) 一致：C/C++ 源与 stderr 中文
  target_compile_options(edr_agent PRIVATE /utf-8)
  # C11 atomics：见 project() 后 CMAKE_C_FLAGS
  target_compile_definitions(edr_agent PRIVATE
    $<$<COMPILE_LANGUAGE:C>:_CRT_SECURE_NO_WARNINGS>
    $<$<COMPILE_LANGUAGE:C>:_CRT_NONSTDC_NO_WARNINGS>)
else()
  target_compile_options(edr_agent PRIVATE -Wall -Wextra -Wno-unused-parameter)
endif()

if(WIN32)
  target_compile_definitions(edr_agent PRIVATE EDR_OS_WINDOWS=1)
  target_link_libraries(edr_agent PRIVATE advapi32 tdh ws2_32 iphlpapi psapi crypt32 wintrust)
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
endif()

if(EDR_BUILD_AVE_SHARED_LIB)
  add_library(edr_ave_shared SHARED ${EDR_AVE_CORE_SOURCES})
  target_include_directories(edr_ave_shared PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src/ave
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/tomlc99
  )
  target_compile_definitions(edr_ave_shared PRIVATE EDR_AVE_BUILD_DLL=1 EDR_HAVE_NANOPB=1)
  target_link_libraries(edr_ave_shared PRIVATE Threads::Threads)
  if(UNIX AND NOT WIN32)
    target_link_libraries(edr_ave_shared PRIVATE m)
  endif()
  if(WIN32)
    target_link_libraries(edr_ave_shared PRIVATE advapi32 ws2_32 crypt32 wintrust)
  endif()
  if(SQLite3_FOUND)
    if(TARGET SQLite3::SQLite3)
      target_link_libraries(edr_ave_shared PRIVATE SQLite3::SQLite3)
    else()
      target_link_libraries(edr_ave_shared PRIVATE SQLite::SQLite3)
    endif()
    target_compile_definitions(edr_ave_shared PRIVATE EDR_HAVE_SQLITE=1)
  endif()
  if(EDR_ONNXRUNTIME_AVAILABLE)
    target_compile_definitions(edr_ave_shared PRIVATE EDR_HAVE_ONNXRUNTIME=1)
    target_include_directories(edr_ave_shared PRIVATE ${ONNXRUNTIME_INCLUDE_DIR})
    target_link_libraries(edr_ave_shared PRIVATE ${ONNXRUNTIME_LIB})
  endif()
  set_target_properties(edr_ave_shared PROPERTIES OUTPUT_NAME "edr_ave")
endif()

# 终端联调：读 agent.toml，按《EDR_端点详细设计》§1.2/§14 对通信 / AVE / 离线队列做黑盒探针（独立进程，不嵌入 Agent）。
add_executable(edr_monitor tools/edr_monitor.c third_party/tomlc99/toml.c)
target_include_directories(edr_monitor PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/third_party/tomlc99)
if(MSVC)
  target_compile_options(edr_monitor PRIVATE /W4 /WX- $<$<COMPILE_LANGUAGE:C>:/std:c17>)
  target_compile_definitions(edr_monitor PRIVATE $<$<COMPILE_LANGUAGE:C>:_CRT_SECURE_NO_WARNINGS>)
else()
  target_compile_options(edr_monitor PRIVATE -Wall -Wextra -Wno-unused-parameter)
endif()
if(WIN32)
  target_compile_definitions(edr_monitor PRIVATE EDR_OS_WINDOWS=1)
  target_link_libraries(edr_monitor PRIVATE ws2_32 winhttp)
else()
  target_compile_definitions(edr_monitor PRIVATE EDR_OS_POSIX=1)
endif()

# 精简仓库未包含 tests/ 时默认关闭单元测试，避免 CMake 找不到 tests/*.c。
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_ave_fp.c")
  set(_EDR_DEFAULT_BUILD_TESTS ON)
else()
  set(_EDR_DEFAULT_BUILD_TESTS OFF)
endif()
option(EDR_BUILD_TESTS "Build CTest targets and tests/*.c executables (requires tests/ tree)" ${_EDR_DEFAULT_BUILD_TESTS})
if(EDR_BUILD_TESTS AND NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_ave_fp.c")
  message(FATAL_ERROR "EDR_BUILD_TESTS=ON but tests/test_ave_fp.c is missing. Add tests/ or configure with -DEDR_BUILD_TESTS=OFF.")
endif()

enable_testing()
add_test(NAME edr_agent_help COMMAND edr_agent --help)

if(EDR_BUILD_TESTS)
add_executable(test_ave_fp tests/test_ave_fp.c src/ave/ave_engine.c src/ave/ave_onnx_infer.c
  src/ave/edr_onnx_behavior_fl_tensor_export.c src/ave/ave_static_features.c)
target_include_directories(test_ave_fp PRIVATE ${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/src/ave)
add_executable(test_ave_infer tests/test_ave_infer.c src/ave/ave_engine.c src/ave/ave_onnx_infer.c
  src/ave/edr_onnx_behavior_fl_tensor_export.c src/ave/ave_static_features.c)
target_include_directories(test_ave_infer PRIVATE ${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/src/ave)
add_executable(test_ave_phase1 tests/test_ave_phase1_contract.c src/ave/ave_engine.c src/ave/ave_onnx_infer.c
  src/ave/edr_onnx_behavior_fl_tensor_export.c src/ave/ave_static_features.c)
target_include_directories(test_ave_phase1 PRIVATE ${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/src/ave)
set(_edr_test_ave_sdk_sources
  src/ave/ave_sdk.c
  src/ave/fl_feature_provider.c
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
  src/ave/ave_engine.c
  src/ave/ave_onnx_infer.c
  src/ave/edr_onnx_behavior_fl_tensor_export.c
  src/config/config.c
  src/command/sha256.c
  third_party/tomlc99/toml.c
)
# 与 `edr_agent` 一致：`ave_behavior_pipeline` → `edr_behavior_alert_emit_to_batch` 的依赖链
set(_edr_test_behavior_emit_sources
  src/serialize/behavior_alert_emit.c
  src/serialize/behavior_proto.c
  src/proto/edr/v1/event.pb.c
  third_party/nanopb/pb_common.c
  third_party/nanopb/pb_encode.c
  third_party/nanopb/pb_decode.c
  src/transport/event_batch.c
  src/transport/ingest_http.c
  src/transport/transport_stub.c
  src/transport/grpc_client_stub.c
  src/core/time_util.c
  src/storage/queue_sqlite.c
  tests/stub_preprocess_agent_ids.c
)
add_executable(test_ave_sdk tests/test_ave_sdk.c ${_edr_test_ave_sdk_sources} ${_edr_test_behavior_emit_sources})
target_include_directories(test_ave_sdk PRIVATE
  ${CMAKE_SOURCE_DIR}/include
  ${CMAKE_SOURCE_DIR}/src/ave
  ${CMAKE_SOURCE_DIR}/third_party/tomlc99
  ${CMAKE_SOURCE_DIR}/third_party/nanopb
  ${CMAKE_SOURCE_DIR}/src/proto
)
target_compile_definitions(test_ave_sdk PRIVATE EDR_HAVE_NANOPB=1)
add_executable(test_ave_fl_abi tests/test_ave_fl_abi.c ${_edr_test_ave_sdk_sources} ${_edr_test_behavior_emit_sources})
target_include_directories(test_ave_fl_abi PRIVATE
  ${CMAKE_SOURCE_DIR}/include
  ${CMAKE_SOURCE_DIR}/src/ave
  ${CMAKE_SOURCE_DIR}/third_party/tomlc99
  ${CMAKE_SOURCE_DIR}/third_party/nanopb
  ${CMAKE_SOURCE_DIR}/src/proto
)
target_compile_definitions(test_ave_fl_abi PRIVATE EDR_HAVE_NANOPB=1)
target_compile_definitions(test_ave_fl_abi PRIVATE
  "EDR_TEST_BEH_ONNX=\"${CMAKE_SOURCE_DIR}/tests/fixtures/behavior_seq128_dual_minimal.onnx\""
)
if(WIN32)
  target_sources(test_ave_sdk PRIVATE src/attack_surface/listen_table_win.c)
  target_sources(test_ave_sdk PRIVATE src/ave/ave_sign_whitelist_win.c)
  target_sources(test_ave_fl_abi PRIVATE src/attack_surface/listen_table_win.c)
  target_sources(test_ave_fl_abi PRIVATE src/ave/ave_sign_whitelist_win.c)
else()
  target_sources(test_ave_sdk PRIVATE src/ave/ave_sign_whitelist_stub.c)
  target_sources(test_ave_fl_abi PRIVATE src/ave/ave_sign_whitelist_stub.c)
endif()
if(SQLite3_FOUND)
  if(TARGET SQLite3::SQLite3)
    target_link_libraries(test_ave_sdk PRIVATE SQLite3::SQLite3)
    target_link_libraries(test_ave_fl_abi PRIVATE SQLite3::SQLite3)
  else()
    target_link_libraries(test_ave_sdk PRIVATE SQLite::SQLite3)
    target_link_libraries(test_ave_fl_abi PRIVATE SQLite::SQLite3)
  endif()
  target_compile_definitions(test_ave_sdk PRIVATE EDR_HAVE_SQLITE=1)
  target_compile_definitions(test_ave_fl_abi PRIVATE EDR_HAVE_SQLITE=1)

  add_executable(test_fl_ave_samples_bridge tests/test_fl_ave_samples_bridge.c
    src/fl_trainer/fl_samples_db.c
    ${_edr_test_ave_sdk_sources} ${_edr_test_behavior_emit_sources})
  target_include_directories(test_fl_ave_samples_bridge PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src/ave
    ${CMAKE_SOURCE_DIR}/src/fl_trainer
    ${CMAKE_SOURCE_DIR}/third_party/tomlc99
    ${CMAKE_SOURCE_DIR}/third_party/nanopb
    ${CMAKE_SOURCE_DIR}/src/proto
  )
  target_compile_definitions(test_fl_ave_samples_bridge PRIVATE EDR_HAVE_NANOPB=1)
  if(WIN32)
    target_sources(test_fl_ave_samples_bridge PRIVATE src/attack_surface/listen_table_win.c)
    target_sources(test_fl_ave_samples_bridge PRIVATE src/ave/ave_sign_whitelist_win.c)
  else()
    target_sources(test_fl_ave_samples_bridge PRIVATE src/ave/ave_sign_whitelist_stub.c)
  endif()
  if(TARGET SQLite3::SQLite3)
    target_link_libraries(test_fl_ave_samples_bridge PRIVATE SQLite3::SQLite3)
  else()
    target_link_libraries(test_fl_ave_samples_bridge PRIVATE SQLite::SQLite3)
  endif()
  target_compile_definitions(test_fl_ave_samples_bridge PRIVATE EDR_HAVE_SQLITE=1)
  if(WIN32)
    target_compile_definitions(test_fl_ave_samples_bridge PRIVATE EDR_OS_WINDOWS=1)
    target_link_libraries(test_fl_ave_samples_bridge PRIVATE advapi32 ws2_32 crypt32 wintrust)
  else()
    target_compile_definitions(test_fl_ave_samples_bridge PRIVATE EDR_OS_POSIX=1)
    target_link_libraries(test_fl_ave_samples_bridge PRIVATE m)
  endif()
  if(MSVC)
    target_compile_options(test_fl_ave_samples_bridge PRIVATE /W4 /WX-)
  else()
    target_compile_options(test_fl_ave_samples_bridge PRIVATE -Wall -Wextra -Wno-unused-parameter)
  endif()
  if(EDR_ONNXRUNTIME_AVAILABLE)
    target_compile_definitions(test_fl_ave_samples_bridge PRIVATE EDR_HAVE_ONNXRUNTIME=1)
    target_include_directories(test_fl_ave_samples_bridge PRIVATE ${ONNXRUNTIME_INCLUDE_DIR})
    target_link_libraries(test_fl_ave_samples_bridge PRIVATE ${ONNXRUNTIME_LIB})
    if(APPLE)
      get_filename_component(_edr_ort_libdir_bridge "${ONNXRUNTIME_LIB}" DIRECTORY)
      set_target_properties(test_fl_ave_samples_bridge PROPERTIES BUILD_RPATH "${_edr_ort_libdir_bridge}")
    endif()
  endif()
endif()

# static + behavior ONNX 同一进程全流程（须 ORT + model_dir 下 release 产物）
add_executable(test_ave_e2e_full tests/test_ave_e2e_full.c ${_edr_test_ave_sdk_sources} ${_edr_test_behavior_emit_sources})
target_include_directories(test_ave_e2e_full PRIVATE
  ${CMAKE_SOURCE_DIR}/include
  ${CMAKE_SOURCE_DIR}/src/ave
  ${CMAKE_SOURCE_DIR}/third_party/tomlc99
  ${CMAKE_SOURCE_DIR}/third_party/nanopb
  ${CMAKE_SOURCE_DIR}/src/proto
)
target_compile_definitions(test_ave_e2e_full PRIVATE EDR_HAVE_NANOPB=1)
if(WIN32)
  target_sources(test_ave_e2e_full PRIVATE src/attack_surface/listen_table_win.c)
  target_sources(test_ave_e2e_full PRIVATE src/ave/ave_sign_whitelist_win.c)
else()
  target_sources(test_ave_e2e_full PRIVATE src/ave/ave_sign_whitelist_stub.c)
endif()
if(SQLite3_FOUND)
  if(TARGET SQLite3::SQLite3)
    target_link_libraries(test_ave_e2e_full PRIVATE SQLite3::SQLite3)
  else()
    target_link_libraries(test_ave_e2e_full PRIVATE SQLite::SQLite3)
  endif()
  target_compile_definitions(test_ave_e2e_full PRIVATE EDR_HAVE_SQLITE=1)
endif()

# P4：AVE_ApplyHotfix + AVE_GetStatus（须 ORT + 双目录 fixture）
add_executable(test_ave_hotfix_smoke tests/test_ave_hotfix_smoke.c ${_edr_test_ave_sdk_sources} ${_edr_test_behavior_emit_sources})
target_include_directories(test_ave_hotfix_smoke PRIVATE
  ${CMAKE_SOURCE_DIR}/include
  ${CMAKE_SOURCE_DIR}/src/ave
  ${CMAKE_SOURCE_DIR}/third_party/tomlc99
  ${CMAKE_SOURCE_DIR}/third_party/nanopb
  ${CMAKE_SOURCE_DIR}/src/proto
)
target_compile_definitions(test_ave_hotfix_smoke PRIVATE EDR_HAVE_NANOPB=1)
if(WIN32)
  target_sources(test_ave_hotfix_smoke PRIVATE src/attack_surface/listen_table_win.c)
  target_sources(test_ave_hotfix_smoke PRIVATE src/ave/ave_sign_whitelist_win.c)
else()
  target_sources(test_ave_hotfix_smoke PRIVATE src/ave/ave_sign_whitelist_stub.c)
endif()
if(SQLite3_FOUND)
  if(TARGET SQLite3::SQLite3)
    target_link_libraries(test_ave_hotfix_smoke PRIVATE SQLite3::SQLite3)
  else()
    target_link_libraries(test_ave_hotfix_smoke PRIVATE SQLite::SQLite3)
  endif()
  target_compile_definitions(test_ave_hotfix_smoke PRIVATE EDR_HAVE_SQLITE=1)
endif()

add_executable(test_ave_suppression tests/test_ave_suppression.c
  src/ave/ave_suppression.c
  src/ave/ave_rules_meta.c
)
target_include_directories(test_ave_suppression PRIVATE ${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/src/ave)
if(SQLite3_FOUND)
  if(TARGET SQLite3::SQLite3)
    target_link_libraries(test_ave_suppression PRIVATE SQLite3::SQLite3)
  else()
    target_link_libraries(test_ave_suppression PRIVATE SQLite::SQLite3)
  endif()
  target_compile_definitions(test_ave_suppression PRIVATE EDR_HAVE_SQLITE=1)
endif()

add_executable(test_ave_pipeline tests/test_ave_pipeline.c
  src/ave/ave_sdk.c
  src/ave/fl_feature_provider.c
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
  src/ave/ave_engine.c
  src/ave/ave_onnx_infer.c
  src/ave/edr_onnx_behavior_fl_tensor_export.c
  src/config/config.c
  src/command/sha256.c
  third_party/tomlc99/toml.c
  ${_edr_test_behavior_emit_sources}
)
target_include_directories(test_ave_pipeline PRIVATE
  ${CMAKE_SOURCE_DIR}/include
  ${CMAKE_SOURCE_DIR}/src/ave
  ${CMAKE_SOURCE_DIR}/third_party/tomlc99
  ${CMAKE_SOURCE_DIR}/third_party/nanopb
  ${CMAKE_SOURCE_DIR}/src/proto
)
target_compile_definitions(test_ave_pipeline PRIVATE EDR_HAVE_NANOPB=1)
if(WIN32)
  target_sources(test_ave_pipeline PRIVATE src/attack_surface/listen_table_win.c)
  target_sources(test_ave_pipeline PRIVATE src/ave/ave_sign_whitelist_win.c)
else()
  target_sources(test_ave_pipeline PRIVATE src/ave/ave_sign_whitelist_stub.c)
endif()
if(SQLite3_FOUND)
  if(TARGET SQLite3::SQLite3)
    target_link_libraries(test_ave_pipeline PRIVATE SQLite3::SQLite3)
  else()
    target_link_libraries(test_ave_pipeline PRIVATE SQLite::SQLite3)
  endif()
  target_compile_definitions(test_ave_pipeline PRIVATE EDR_HAVE_SQLITE=1)
endif()

add_executable(test_ave_behavior_features_m3a tests/test_ave_behavior_features_m3a.c src/ave/ave_behavior_features.c)
target_include_directories(test_ave_behavior_features_m3a PRIVATE ${CMAKE_SOURCE_DIR}/include)
add_executable(test_ave_cross_engine_parse tests/test_ave_cross_engine_parse.c src/ave/ave_cross_engine_parse.c)
target_include_directories(test_ave_cross_engine_parse PRIVATE ${CMAKE_SOURCE_DIR}/include)
if(NOT WIN32)
  target_link_libraries(test_ave_cross_engine_parse PRIVATE m)
endif()
if(NOT WIN32)
  target_link_libraries(test_ave_behavior_features_m3a PRIVATE m)
endif()
add_test(NAME ave_behavior_features_m3a COMMAND test_ave_behavior_features_m3a WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
add_test(NAME ave_cross_engine_parse COMMAND test_ave_cross_engine_parse WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

add_executable(test_ave_behavior_features_m3b tests/test_ave_behavior_features_m3b.c src/ave/ave_behavior_features.c)
target_include_directories(test_ave_behavior_features_m3b PRIVATE ${CMAKE_SOURCE_DIR}/include)
if(NOT WIN32)
  target_link_libraries(test_ave_behavior_features_m3b PRIVATE m)
endif()
add_test(NAME ave_behavior_features_m3b COMMAND test_ave_behavior_features_m3b WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

add_executable(test_ave_behavior_gates tests/test_ave_behavior_gates.c)
target_include_directories(test_ave_behavior_gates PRIVATE ${CMAKE_SOURCE_DIR}/include)
add_test(NAME ave_behavior_gates COMMAND test_ave_behavior_gates WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

find_program(EDR_PYTHON3 python3)
if(EDR_PYTHON3)
  add_test(
    NAME ave_behavior_m3b_python_parity
    COMMAND ${EDR_PYTHON3} "${CMAKE_SOURCE_DIR}/scripts/behavior_encode_m3b.py"
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}")
endif()

if(UNIX)
  add_test(
    NAME ave_behavior_onnx_contract_check
    COMMAND bash "${CMAKE_SOURCE_DIR}/scripts/check_behavior_onnx_contract.sh"
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}")
endif()

add_executable(test_config_fp tests/test_config_fp.c src/config/config.c third_party/tomlc99/toml.c)
target_include_directories(test_config_fp PRIVATE ${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/third_party/tomlc99)

add_executable(test_pmfe_detail tests/test_pmfe_detail.c)
add_test(NAME pmfe_scan_detail_format COMMAND test_pmfe_detail WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  add_executable(test_pmfe_linux_maps tests/test_pmfe_linux_maps.c src/pmfe/pmfe_linux_scan_util.c)
  target_include_directories(test_pmfe_linux_maps PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src/pmfe)
  add_test(NAME pmfe_linux_maps_parse COMMAND test_pmfe_linux_maps WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
endif()

if(EDR_WITH_FL_TRAINER)
  add_executable(test_fl_trainer_smoke tests/test_fl_trainer_smoke.c src/ave/fl_feature_provider.c
                  ${EDR_FL_TRAINER_SOURCES})
  target_include_directories(test_fl_trainer_smoke PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src/fl_trainer
  )
  target_compile_definitions(test_fl_trainer_smoke PRIVATE EDR_WITH_FL_TRAINER=1)
  find_package(Threads REQUIRED)
  target_link_libraries(test_fl_trainer_smoke PRIVATE Threads::Threads)
  if(WIN32)
    target_compile_definitions(test_fl_trainer_smoke PRIVATE EDR_OS_WINDOWS=1)
    target_link_libraries(test_fl_trainer_smoke PRIVATE advapi32 ws2_32 crypt32 wintrust)
  else()
    target_compile_definitions(test_fl_trainer_smoke PRIVATE EDR_OS_POSIX=1)
    target_link_libraries(test_fl_trainer_smoke PRIVATE m)
  endif()
  if(MSVC)
    target_compile_options(test_fl_trainer_smoke PRIVATE /W4 /WX-)
  else()
    target_compile_options(test_fl_trainer_smoke PRIVATE -Wall -Wextra -Wno-unused-parameter)
  endif()
  if(SQLite3_FOUND)
    if(TARGET SQLite3::SQLite3)
      target_link_libraries(test_fl_trainer_smoke PRIVATE SQLite3::SQLite3)
    else()
      target_link_libraries(test_fl_trainer_smoke PRIVATE SQLite::SQLite3)
    endif()
    target_compile_definitions(test_fl_trainer_smoke PRIVATE EDR_HAVE_SQLITE=1)
  endif()
  if(EDR_LIBTORCH_AVAILABLE)
    target_compile_definitions(test_fl_trainer_smoke PRIVATE EDR_HAVE_LIBTORCH=1)
    target_link_libraries(test_fl_trainer_smoke PRIVATE ${TORCH_LIBRARIES})
    if(TORCH_CXX_FLAGS)
      separate_arguments(_edr_torch_test_flags UNIX_COMMAND "${TORCH_CXX_FLAGS}")
      set_property(SOURCE src/fl_trainer/local_train_torch.cpp APPEND PROPERTY COMPILE_OPTIONS
                   ${_edr_torch_test_flags})
    endif()
  endif()
  if(OpenSSL_FOUND)
    target_compile_definitions(test_fl_trainer_smoke PRIVATE EDR_HAVE_OPENSSL_FL=1)
    if(TARGET OpenSSL::SSL)
      target_link_libraries(test_fl_trainer_smoke PRIVATE OpenSSL::SSL OpenSSL::Crypto)
    else()
      target_link_libraries(test_fl_trainer_smoke PRIVATE OpenSSL::Crypto)
    endif()
  endif()
  if(EDR_GRPC_CLIENT_AVAILABLE)
    target_compile_definitions(test_fl_trainer_smoke PRIVATE EDR_HAVE_GRPC_FL=1)
    target_link_libraries(test_fl_trainer_smoke PRIVATE gRPC::grpc++ protobuf::libprotobuf)
    target_include_directories(test_fl_trainer_smoke PRIVATE ${CMAKE_SOURCE_DIR}/src/grpc_gen)
  endif()
  if(OpenSSL_FOUND)
    add_executable(test_fl_crypto_fl3 tests/test_fl_crypto_fl3.c src/fl_trainer/fl_crypto.c)
    target_include_directories(test_fl_crypto_fl3 PRIVATE ${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/src/fl_trainer)
    target_compile_definitions(test_fl_crypto_fl3 PRIVATE EDR_HAVE_OPENSSL_FL=1)
    target_link_libraries(test_fl_crypto_fl3 PRIVATE OpenSSL::Crypto)
    add_test(NAME fl_crypto_fl3 COMMAND test_fl_crypto_fl3 WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
  endif()
  add_executable(test_fl_pb_gradient_chunk tests/test_fl_pb_gradient_chunk.c src/fl_trainer/fl_pb_wire.c)
  target_include_directories(test_fl_pb_gradient_chunk PRIVATE ${CMAKE_SOURCE_DIR}/src/fl_trainer)
  add_test(NAME fl_pb_gradient_chunk COMMAND test_fl_pb_gradient_chunk WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
endif()

if(WIN32)
  target_compile_definitions(test_ave_fp PRIVATE EDR_OS_WINDOWS=1)
  target_compile_definitions(test_ave_infer PRIVATE EDR_OS_WINDOWS=1)
  target_compile_definitions(test_ave_sdk PRIVATE EDR_OS_WINDOWS=1)
  target_compile_definitions(test_ave_fl_abi PRIVATE EDR_OS_WINDOWS=1)
  target_compile_definitions(test_ave_suppression PRIVATE EDR_OS_WINDOWS=1)
  target_compile_definitions(test_ave_pipeline PRIVATE EDR_OS_WINDOWS=1)
  target_compile_definitions(test_ave_e2e_full PRIVATE EDR_OS_WINDOWS=1)
  target_compile_definitions(test_ave_hotfix_smoke PRIVATE EDR_OS_WINDOWS=1)
else()
  target_compile_definitions(test_ave_fp PRIVATE EDR_OS_POSIX=1)
  target_compile_definitions(test_ave_infer PRIVATE EDR_OS_POSIX=1)
  target_compile_definitions(test_ave_sdk PRIVATE EDR_OS_POSIX=1)
  target_compile_definitions(test_ave_fl_abi PRIVATE EDR_OS_POSIX=1)
  target_compile_definitions(test_ave_suppression PRIVATE EDR_OS_POSIX=1)
  target_compile_definitions(test_ave_pipeline PRIVATE EDR_OS_POSIX=1)
  target_compile_definitions(test_ave_e2e_full PRIVATE EDR_OS_POSIX=1)
  target_compile_definitions(test_ave_hotfix_smoke PRIVATE EDR_OS_POSIX=1)
endif()

if(EDR_ONNXRUNTIME_AVAILABLE)
  target_compile_definitions(test_ave_fp PRIVATE EDR_HAVE_ONNXRUNTIME=1)
  target_compile_definitions(test_ave_infer PRIVATE EDR_HAVE_ONNXRUNTIME=1)
  target_compile_definitions(test_ave_sdk PRIVATE EDR_HAVE_ONNXRUNTIME=1)
  target_compile_definitions(test_ave_fl_abi PRIVATE EDR_HAVE_ONNXRUNTIME=1)
  target_compile_definitions(test_ave_pipeline PRIVATE EDR_HAVE_ONNXRUNTIME=1)
  target_compile_definitions(test_ave_e2e_full PRIVATE EDR_HAVE_ONNXRUNTIME=1)
  target_compile_definitions(test_ave_hotfix_smoke PRIVATE EDR_HAVE_ONNXRUNTIME=1)
  target_include_directories(test_ave_fp PRIVATE ${ONNXRUNTIME_INCLUDE_DIR})
  target_include_directories(test_ave_infer PRIVATE ${ONNXRUNTIME_INCLUDE_DIR})
  target_include_directories(test_ave_sdk PRIVATE ${ONNXRUNTIME_INCLUDE_DIR})
  target_include_directories(test_ave_fl_abi PRIVATE ${ONNXRUNTIME_INCLUDE_DIR})
  target_include_directories(test_ave_pipeline PRIVATE ${ONNXRUNTIME_INCLUDE_DIR})
  target_include_directories(test_ave_e2e_full PRIVATE ${ONNXRUNTIME_INCLUDE_DIR})
  target_include_directories(test_ave_hotfix_smoke PRIVATE ${ONNXRUNTIME_INCLUDE_DIR})
  target_link_libraries(test_ave_fp PRIVATE ${ONNXRUNTIME_LIB})
  target_link_libraries(test_ave_infer PRIVATE ${ONNXRUNTIME_LIB})
  target_link_libraries(test_ave_sdk PRIVATE ${ONNXRUNTIME_LIB})
  target_link_libraries(test_ave_fl_abi PRIVATE ${ONNXRUNTIME_LIB})
  target_link_libraries(test_ave_pipeline PRIVATE ${ONNXRUNTIME_LIB})
  target_link_libraries(test_ave_e2e_full PRIVATE ${ONNXRUNTIME_LIB})
  target_link_libraries(test_ave_hotfix_smoke PRIVATE ${ONNXRUNTIME_LIB})

  add_executable(test_ave_static_onnx_integration tests/test_ave_static_onnx_integration.c
    src/ave/ave_engine.c
    src/ave/ave_onnx_infer.c
    src/ave/edr_onnx_behavior_fl_tensor_export.c
    src/ave/ave_static_features.c
    src/config/config.c
    third_party/tomlc99/toml.c
  )
  target_include_directories(test_ave_static_onnx_integration PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src/ave
    ${CMAKE_SOURCE_DIR}/third_party/tomlc99
  )
  target_compile_definitions(test_ave_static_onnx_integration PRIVATE EDR_HAVE_ONNXRUNTIME=1)
  target_compile_definitions(test_ave_static_onnx_integration PRIVATE
    "EDR_TEST_FIXTURE_ONNX=\"${CMAKE_SOURCE_DIR}/tests/fixtures/static_triple_minimal.onnx\""
  )
  target_include_directories(test_ave_static_onnx_integration PRIVATE ${ONNXRUNTIME_INCLUDE_DIR})
  target_link_libraries(test_ave_static_onnx_integration PRIVATE ${ONNXRUNTIME_LIB} Threads::Threads)
  if(UNIX AND NOT WIN32)
    target_link_libraries(test_ave_static_onnx_integration PRIVATE m)
  endif()
  if(WIN32)
    target_compile_definitions(test_ave_static_onnx_integration PRIVATE EDR_OS_WINDOWS=1)
  else()
    target_compile_definitions(test_ave_static_onnx_integration PRIVATE EDR_OS_POSIX=1)
  endif()

  if(APPLE)
    get_filename_component(_edr_ort_libdir_t "${ONNXRUNTIME_LIB}" DIRECTORY)
    set_target_properties(test_ave_fp test_ave_infer test_ave_sdk test_ave_fl_abi test_ave_pipeline
      test_ave_e2e_full test_ave_hotfix_smoke test_ave_static_onnx_integration PROPERTIES BUILD_RPATH "${_edr_ort_libdir_t}")
  endif()

  add_test(NAME ave_static_onnx_triple_integration COMMAND test_ave_static_onnx_integration
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

  add_executable(test_ave_behavior_onnx_integration tests/test_ave_behavior_onnx_integration.c
    src/ave/ave_onnx_infer.c
    src/ave/edr_onnx_behavior_fl_tensor_export.c
    src/ave/ave_static_features.c
    src/config/config.c
    third_party/tomlc99/toml.c
  )
  target_include_directories(test_ave_behavior_onnx_integration PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src/ave
    ${CMAKE_SOURCE_DIR}/third_party/tomlc99
  )
  target_compile_definitions(test_ave_behavior_onnx_integration PRIVATE EDR_HAVE_ONNXRUNTIME=1)
  target_compile_definitions(test_ave_behavior_onnx_integration PRIVATE
    "EDR_TEST_BEHAVIOR_FIXTURE=\"${CMAKE_SOURCE_DIR}/tests/fixtures/behavior_dual_minimal.onnx\""
    "EDR_TEST_BEHAVIOR_SEQ128_FIXTURE=\"${CMAKE_SOURCE_DIR}/tests/fixtures/behavior_seq128_dual_minimal.onnx\""
  )
  target_include_directories(test_ave_behavior_onnx_integration PRIVATE ${ONNXRUNTIME_INCLUDE_DIR})
  target_link_libraries(test_ave_behavior_onnx_integration PRIVATE ${ONNXRUNTIME_LIB} Threads::Threads)
  if(UNIX AND NOT WIN32)
    target_link_libraries(test_ave_behavior_onnx_integration PRIVATE m)
  endif()
  if(WIN32)
    target_compile_definitions(test_ave_behavior_onnx_integration PRIVATE EDR_OS_WINDOWS=1)
  else()
    target_compile_definitions(test_ave_behavior_onnx_integration PRIVATE EDR_OS_POSIX=1)
  endif()

  if(APPLE)
    get_filename_component(_edr_ort_libdir_beh "${ONNXRUNTIME_LIB}" DIRECTORY)
    set_target_properties(test_ave_behavior_onnx_integration PROPERTIES BUILD_RPATH "${_edr_ort_libdir_beh}")
  endif()

  add_test(NAME ave_behavior_onnx_dual_integration COMMAND test_ave_behavior_onnx_integration
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

  # P1：小 fixture 拷成 model_dir 命名（static.onnx + behavior.onnx），与 Agent 真链一致
  set(EDR_E2E_MODEL_FIXTURE_DIR "${CMAKE_BINARY_DIR}/test_models_e2e")
  file(MAKE_DIRECTORY "${EDR_E2E_MODEL_FIXTURE_DIR}")
  configure_file(
    "${CMAKE_SOURCE_DIR}/tests/fixtures/static_triple_minimal.onnx"
    "${EDR_E2E_MODEL_FIXTURE_DIR}/static.onnx"
    COPYONLY)
  configure_file(
    "${CMAKE_SOURCE_DIR}/tests/fixtures/behavior_seq128_dual_minimal.onnx"
    "${EDR_E2E_MODEL_FIXTURE_DIR}/behavior.onnx"
    COPYONLY)
  add_test(NAME ave_e2e_full_smoke COMMAND test_ave_e2e_full WORKING_DIRECTORY "${CMAKE_BINARY_DIR}")
  set_tests_properties(ave_e2e_full_smoke PROPERTIES
    ENVIRONMENT "EDR_AVE_TEST_MODEL_DIR=${EDR_E2E_MODEL_FIXTURE_DIR}")

  set(EDR_E2E_HOTFIX_FIXTURE_DIR "${CMAKE_BINARY_DIR}/test_models_e2e_hotfix")
  file(MAKE_DIRECTORY "${EDR_E2E_HOTFIX_FIXTURE_DIR}")
  configure_file(
    "${CMAKE_SOURCE_DIR}/tests/fixtures/static_triple_minimal.onnx"
    "${EDR_E2E_HOTFIX_FIXTURE_DIR}/static.onnx"
    COPYONLY)
  configure_file(
    "${CMAKE_SOURCE_DIR}/tests/fixtures/behavior_seq128_dual_minimal.onnx"
    "${EDR_E2E_HOTFIX_FIXTURE_DIR}/behavior.onnx"
    COPYONLY)
  add_test(NAME ave_hotfix_smoke COMMAND test_ave_hotfix_smoke WORKING_DIRECTORY "${CMAKE_BINARY_DIR}")
  set_property(TEST ave_hotfix_smoke PROPERTY ENVIRONMENT
    "EDR_AVE_TEST_MODEL_DIR=${EDR_E2E_MODEL_FIXTURE_DIR}"
    "EDR_AVE_HOTFIX_DIR=${EDR_E2E_HOTFIX_FIXTURE_DIR}")
  if(UNIX AND NOT WIN32)
    add_test(NAME ave_hotfix_empty_dir_fail COMMAND test_ave_hotfix_smoke WORKING_DIRECTORY "${CMAKE_BINARY_DIR}")
    set_property(TEST ave_hotfix_empty_dir_fail PROPERTY ENVIRONMENT
      "EDR_AVE_TEST_MODEL_DIR=${EDR_E2E_MODEL_FIXTURE_DIR}"
      "EDR_AVE_HOTFIX_DIR=${EDR_E2E_HOTFIX_FIXTURE_DIR}"
      "EDR_AVE_TEST_HOTFIX_EMPTY=1")
  endif()
endif()

if(WIN32)
  target_link_libraries(test_ave_sdk PRIVATE advapi32 ws2_32 crypt32 wintrust)
  target_link_libraries(test_ave_fl_abi PRIVATE advapi32 ws2_32 crypt32 wintrust)
  target_link_libraries(test_ave_pipeline PRIVATE advapi32 ws2_32 crypt32 wintrust)
  target_link_libraries(test_ave_e2e_full PRIVATE advapi32 ws2_32 crypt32 wintrust)
  target_link_libraries(test_ave_hotfix_smoke PRIVATE advapi32 ws2_32 crypt32 wintrust)
endif()
if(UNIX AND NOT WIN32)
  target_link_libraries(test_ave_sdk PRIVATE m)
  target_link_libraries(test_ave_fl_abi PRIVATE m)
  target_link_libraries(test_ave_pipeline PRIVATE m)
  target_link_libraries(test_ave_e2e_full PRIVATE m)
  target_link_libraries(test_ave_hotfix_smoke PRIVATE m)
endif()

if(MSVC)
  target_compile_options(test_ave_fp PRIVATE /W4 /WX-)
  target_compile_options(test_ave_infer PRIVATE /W4 /WX-)
  target_compile_options(test_ave_sdk PRIVATE /W4 /WX-)
  target_compile_options(test_ave_fl_abi PRIVATE /W4 /WX-)
  target_compile_options(test_ave_suppression PRIVATE /W4 /WX-)
  target_compile_options(test_ave_pipeline PRIVATE /W4 /WX-)
  target_compile_options(test_ave_e2e_full PRIVATE /W4 /WX-)
  target_compile_options(test_ave_hotfix_smoke PRIVATE /W4 /WX-)
  target_compile_options(test_config_fp PRIVATE /W4 /WX-)
  if(EDR_ONNXRUNTIME_AVAILABLE)
    target_compile_options(test_ave_static_onnx_integration PRIVATE /W4 /WX-)
    target_compile_options(test_ave_behavior_onnx_integration PRIVATE /W4 /WX-)
  endif()
else()
  target_compile_options(test_ave_fp PRIVATE -Wall -Wextra -Wno-unused-parameter)
  target_compile_options(test_ave_infer PRIVATE -Wall -Wextra -Wno-unused-parameter)
  target_compile_options(test_ave_sdk PRIVATE -Wall -Wextra -Wno-unused-parameter)
  target_compile_options(test_ave_fl_abi PRIVATE -Wall -Wextra -Wno-unused-parameter)
  target_compile_options(test_ave_suppression PRIVATE -Wall -Wextra -Wno-unused-parameter)
  target_compile_options(test_ave_pipeline PRIVATE -Wall -Wextra -Wno-unused-parameter)
  target_compile_options(test_ave_e2e_full PRIVATE -Wall -Wextra -Wno-unused-parameter)
  target_compile_options(test_ave_hotfix_smoke PRIVATE -Wall -Wextra -Wno-unused-parameter)
  target_compile_options(test_config_fp PRIVATE -Wall -Wextra -Wno-unused-parameter)
  if(EDR_ONNXRUNTIME_AVAILABLE)
    target_compile_options(test_ave_static_onnx_integration PRIVATE -Wall -Wextra -Wno-unused-parameter)
    target_compile_options(test_ave_behavior_onnx_integration PRIVATE -Wall -Wextra -Wno-unused-parameter)
  endif()
endif()

add_test(NAME ave_file_fingerprint COMMAND test_ave_fp WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
add_test(NAME ave_infer_dry_run COMMAND test_ave_infer WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
add_test(NAME ave_phase1_contract COMMAND test_ave_phase1 WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
add_executable(test_ave_static_features tests/test_ave_static_features.c src/ave/ave_static_features.c)
target_include_directories(test_ave_static_features PRIVATE ${CMAKE_SOURCE_DIR}/src/ave)
add_test(NAME ave_static_features_lite512 COMMAND test_ave_static_features WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
add_test(NAME ave_sdk_smoke COMMAND test_ave_sdk WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
add_test(NAME ave_fl_abi_c0 COMMAND test_ave_fl_abi WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
if(SQLite3_FOUND)
  add_test(NAME fl_ave_samples_bridge COMMAND test_fl_ave_samples_bridge WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
endif()
add_test(NAME ave_suppression_sqlite COMMAND test_ave_suppression WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
add_test(NAME ave_scan_pipeline COMMAND test_ave_pipeline WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
add_test(NAME config_fingerprint COMMAND test_config_fp WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
if(EDR_WITH_FL_TRAINER)
  add_test(NAME fl_trainer_c1 COMMAND test_fl_trainer_smoke WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
endif()
add_executable(test_shellcode tests/test_shellcode.c ${EDR_SHELLCODE_SRCS})
target_include_directories(test_shellcode PRIVATE
  ${CMAKE_SOURCE_DIR}/include
  ${CMAKE_SOURCE_DIR}/third_party/windivert
)
if(EDR_YARA_AVAILABLE)
  target_compile_definitions(test_shellcode PRIVATE EDR_HAVE_YARA=1)
  target_include_directories(test_shellcode PRIVATE ${YARA_INCLUDE_DIR})
  target_link_libraries(test_shellcode PRIVATE ${YARA_LIB})
endif()
if(WIN32)
  target_link_libraries(test_shellcode PRIVATE advapi32 ws2_32)
endif()
if(UNIX AND NOT WIN32)
  target_link_libraries(test_shellcode PRIVATE m)
endif()
if(MSVC)
  target_compile_options(test_shellcode PRIVATE /W4 /WX-)
else()
  target_compile_options(test_shellcode PRIVATE -Wall -Wextra -Wno-unused-parameter)
endif()
add_test(NAME shellcode_modules COMMAND test_shellcode WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
add_test(NAME edr_agent_smoke COMMAND bash ${CMAKE_SOURCE_DIR}/scripts/agent_smoke.sh $<TARGET_FILE:edr_agent>)
set_tests_properties(edr_agent_smoke PROPERTIES TIMEOUT 30)

endif() # EDR_BUILD_TESTS
