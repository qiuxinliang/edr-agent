add_test(NAME edr_agent_help COMMAND edr_agent --help)

function(edr_absolutize_sources output_var)
  set(_edr_abs_sources)
  foreach(_edr_source ${ARGN})
    if(IS_ABSOLUTE "${_edr_source}")
      list(APPEND _edr_abs_sources "${_edr_source}")
    else()
      list(APPEND _edr_abs_sources "${CMAKE_SOURCE_DIR}/${_edr_source}")
    endif()
  endforeach()
  set(${output_var} "${_edr_abs_sources}" PARENT_SCOPE)
endfunction()

add_executable(test_ave_fp ${CMAKE_CURRENT_SOURCE_DIR}/test_ave_fp.c ${CMAKE_SOURCE_DIR}/src/ave/ave_engine.c ${CMAKE_SOURCE_DIR}/src/ave/ave_onnx_infer.c
  ${CMAKE_SOURCE_DIR}/src/ave/ave_static_features.c
  ${CMAKE_SOURCE_DIR}/src/core/edr_log.c ${CMAKE_SOURCE_DIR}/src/command/sha256.c)
target_include_directories(test_ave_fp PRIVATE ${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/src/ave)
add_executable(test_ave_infer ${CMAKE_CURRENT_SOURCE_DIR}/test_ave_infer.c ${CMAKE_SOURCE_DIR}/src/ave/ave_engine.c ${CMAKE_SOURCE_DIR}/src/ave/ave_onnx_infer.c
  ${CMAKE_SOURCE_DIR}/src/ave/ave_static_features.c
  ${CMAKE_SOURCE_DIR}/src/core/edr_log.c ${CMAKE_SOURCE_DIR}/src/command/sha256.c)
target_include_directories(test_ave_infer PRIVATE ${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/src/ave)
add_executable(test_ave_phase1 ${CMAKE_CURRENT_SOURCE_DIR}/test_ave_phase1_contract.c ${CMAKE_SOURCE_DIR}/src/ave/ave_engine.c ${CMAKE_SOURCE_DIR}/src/ave/ave_onnx_infer.c
  ${CMAKE_SOURCE_DIR}/src/ave/ave_static_features.c
  ${CMAKE_SOURCE_DIR}/src/core/edr_log.c ${CMAKE_SOURCE_DIR}/src/command/sha256.c)
target_include_directories(test_ave_phase1 PRIVATE ${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/src/ave)
set(_edr_test_ave_sdk_sources
  ${CMAKE_SOURCE_DIR}/src/ave/ave_sdk.c
  ${CMAKE_SOURCE_DIR}/src/ave/ave_suppression.c
  ${CMAKE_SOURCE_DIR}/src/ave/ave_rules_meta.c
  ${CMAKE_SOURCE_DIR}/src/ave/ave_behavior_pipeline.c
  ${CMAKE_SOURCE_DIR}/src/ave/ave_behavior_features.c
  ${CMAKE_SOURCE_DIR}/src/ave/ave_cross_engine_parse.c
  ${CMAKE_SOURCE_DIR}/src/ave/ave_cross_engine_feed.c
  ${CMAKE_SOURCE_DIR}/src/ave/ave_lf_mpmc.c
  ${CMAKE_SOURCE_DIR}/src/ave/ave_hotfix.c
  ${CMAKE_SOURCE_DIR}/src/ave/ave_db_update.c
  ${CMAKE_SOURCE_DIR}/src/ave/ave_static_features.c
  ${CMAKE_SOURCE_DIR}/src/ave/ave_engine.c
  ${CMAKE_SOURCE_DIR}/src/ave/ave_onnx_infer.c
  ${CMAKE_SOURCE_DIR}/src/core/edr_log.c
  ${CMAKE_SOURCE_DIR}/src/config/config.c
  ${CMAKE_SOURCE_DIR}/src/command/sha256.c
  ${CMAKE_SOURCE_DIR}/third_party/tomlc99/toml.c
)
# 与 `edr_agent` 一致：`ave_behavior_pipeline` → `edr_behavior_alert_emit_to_batch` 的依赖链
set(_edr_test_behavior_emit_sources
  ${CMAKE_SOURCE_DIR}/src/serialize/behavior_alert_emit.c
  ${CMAKE_SOURCE_DIR}/src/serialize/behavior_proto.c
  ${CMAKE_SOURCE_DIR}/src/proto/edr/v1/event.pb.c
  ${CMAKE_SOURCE_DIR}/third_party/nanopb/pb_common.c
  ${CMAKE_SOURCE_DIR}/third_party/nanopb/pb_encode.c
  ${CMAKE_SOURCE_DIR}/third_party/nanopb/pb_decode.c
  ${CMAKE_SOURCE_DIR}/src/transport/event_batch.c
  ${CMAKE_SOURCE_DIR}/src/transport/ingest_http.c
  ${CMAKE_SOURCE_DIR}/src/transport/transport_v2.c
  ${CMAKE_SOURCE_DIR}/src/transport/transport_stub.c
  ${CMAKE_SOURCE_DIR}/src/transport/grpc_client_stub.c
  ${CMAKE_SOURCE_DIR}/src/core/time_util.c
  ${CMAKE_SOURCE_DIR}/src/storage/queue_sqlite.c
  ${CMAKE_CURRENT_SOURCE_DIR}/stub_agent_runtime_hooks.c
  ${CMAKE_CURRENT_SOURCE_DIR}/stub_preprocess_agent_ids.c
)
add_library(edr_ave_test_common INTERFACE)
target_include_directories(edr_ave_test_common INTERFACE
  ${CMAKE_SOURCE_DIR}/include
  ${CMAKE_SOURCE_DIR}/src/ave
  ${CMAKE_SOURCE_DIR}/third_party/tomlc99
  ${CMAKE_SOURCE_DIR}/third_party/nanopb
  ${CMAKE_SOURCE_DIR}/src/proto
)
target_compile_definitions(edr_ave_test_common INTERFACE EDR_HAVE_NANOPB=1)
if(SQLite3_FOUND)
  if(TARGET SQLite3::SQLite3)
    target_link_libraries(edr_ave_test_common INTERFACE SQLite3::SQLite3)
  else()
    target_link_libraries(edr_ave_test_common INTERFACE SQLite::SQLite3)
  endif()
  target_compile_definitions(edr_ave_test_common INTERFACE EDR_HAVE_SQLITE=1)
endif()
if(WIN32)
  target_compile_definitions(edr_ave_test_common INTERFACE EDR_OS_WINDOWS=1)
  target_link_libraries(edr_ave_test_common INTERFACE advapi32 ws2_32 crypt32 wintrust)
else()
  target_compile_definitions(edr_ave_test_common INTERFACE EDR_OS_POSIX=1)
  if(UNIX)
    target_link_libraries(edr_ave_test_common INTERFACE m)
  endif()
endif()

add_executable(test_ave_sdk ${CMAKE_CURRENT_SOURCE_DIR}/test_ave_sdk.c ${_edr_test_ave_sdk_sources} ${_edr_test_behavior_emit_sources})
target_link_libraries(test_ave_sdk PRIVATE edr_ave_test_common)
add_executable(test_ave_fl_abi ${CMAKE_CURRENT_SOURCE_DIR}/test_ave_fl_abi.c ${_edr_test_ave_sdk_sources} ${_edr_test_behavior_emit_sources})
target_link_libraries(test_ave_fl_abi PRIVATE edr_ave_test_common)
set(_edr_test_behavior_seq128_fixture "${CMAKE_SOURCE_DIR}/tests/fixtures/behavior_seq128_dual_minimal.onnx")
if(EDR_WITH_AVE_BEHAVIOR_ONNX AND EXISTS "${_edr_test_behavior_seq128_fixture}")
  target_compile_definitions(test_ave_fl_abi PRIVATE
    "EDR_TEST_BEH_ONNX=\"${_edr_test_behavior_seq128_fixture}\""
  )
endif()
if(WIN32)
  target_sources(test_ave_sdk PRIVATE ${CMAKE_SOURCE_DIR}/src/attack_surface/listen_table_win.c)
  target_sources(test_ave_sdk PRIVATE ${CMAKE_SOURCE_DIR}/src/ave/ave_sign_whitelist_win.c)
  target_sources(test_ave_fl_abi PRIVATE ${CMAKE_SOURCE_DIR}/src/attack_surface/listen_table_win.c)
  target_sources(test_ave_fl_abi PRIVATE ${CMAKE_SOURCE_DIR}/src/ave/ave_sign_whitelist_win.c)
else()
  target_sources(test_ave_sdk PRIVATE ${CMAKE_SOURCE_DIR}/src/ave/ave_sign_whitelist_stub.c)
  target_sources(test_ave_fl_abi PRIVATE ${CMAKE_SOURCE_DIR}/src/ave/ave_sign_whitelist_stub.c)
endif()
if(FALSE AND SQLite3_FOUND)
  add_executable(test_fl_ave_samples_bridge ${CMAKE_CURRENT_SOURCE_DIR}/test_fl_ave_samples_bridge.c
    ${CMAKE_SOURCE_DIR}/src/fl_trainer/fl_samples_db.c
    ${_edr_test_ave_sdk_sources} ${_edr_test_behavior_emit_sources})
  target_link_libraries(test_fl_ave_samples_bridge PRIVATE edr_ave_test_common)
  target_include_directories(test_fl_ave_samples_bridge PRIVATE ${CMAKE_SOURCE_DIR}/src/fl_trainer)
  if(WIN32)
    target_sources(test_fl_ave_samples_bridge PRIVATE ${CMAKE_SOURCE_DIR}/src/attack_surface/listen_table_win.c)
    target_sources(test_fl_ave_samples_bridge PRIVATE ${CMAKE_SOURCE_DIR}/src/ave/ave_sign_whitelist_win.c)
  else()
    target_sources(test_fl_ave_samples_bridge PRIVATE ${CMAKE_SOURCE_DIR}/src/ave/ave_sign_whitelist_stub.c)
  endif()
  edr_apply_common_warnings(test_fl_ave_samples_bridge)
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
add_executable(test_ave_e2e_full ${CMAKE_CURRENT_SOURCE_DIR}/test_ave_e2e_full.c ${_edr_test_ave_sdk_sources} ${_edr_test_behavior_emit_sources})
target_link_libraries(test_ave_e2e_full PRIVATE edr_ave_test_common)
if(WIN32)
  target_sources(test_ave_e2e_full PRIVATE ${CMAKE_SOURCE_DIR}/src/attack_surface/listen_table_win.c)
  target_sources(test_ave_e2e_full PRIVATE ${CMAKE_SOURCE_DIR}/src/ave/ave_sign_whitelist_win.c)
else()
  target_sources(test_ave_e2e_full PRIVATE ${CMAKE_SOURCE_DIR}/src/ave/ave_sign_whitelist_stub.c)
endif()

# P4：AVE_ApplyHotfix + AVE_GetStatus（须 ORT + 双目录 fixture）
add_executable(test_ave_hotfix_smoke ${CMAKE_CURRENT_SOURCE_DIR}/test_ave_hotfix_smoke.c ${_edr_test_ave_sdk_sources} ${_edr_test_behavior_emit_sources})
target_link_libraries(test_ave_hotfix_smoke PRIVATE edr_ave_test_common)
if(WIN32)
  target_sources(test_ave_hotfix_smoke PRIVATE ${CMAKE_SOURCE_DIR}/src/attack_surface/listen_table_win.c)
  target_sources(test_ave_hotfix_smoke PRIVATE ${CMAKE_SOURCE_DIR}/src/ave/ave_sign_whitelist_win.c)
else()
  target_sources(test_ave_hotfix_smoke PRIVATE ${CMAKE_SOURCE_DIR}/src/ave/ave_sign_whitelist_stub.c)
endif()

add_executable(test_ave_suppression ${CMAKE_CURRENT_SOURCE_DIR}/test_ave_suppression.c
  ${CMAKE_SOURCE_DIR}/src/ave/ave_suppression.c
  ${CMAKE_SOURCE_DIR}/src/ave/ave_rules_meta.c
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

add_executable(test_detection_decision ${CMAKE_CURRENT_SOURCE_DIR}/test_detection_decision.c
  ${CMAKE_SOURCE_DIR}/src/preprocess/detection_decision.c
  ${CMAKE_SOURCE_DIR}/src/preprocess/detection_profile.c)
target_include_directories(test_detection_decision PRIVATE ${CMAKE_SOURCE_DIR}/include)
edr_apply_common_warnings(test_detection_decision)
add_test(NAME detection_decision_combo COMMAND test_detection_decision WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

add_executable(test_detection_regression ${CMAKE_CURRENT_SOURCE_DIR}/test_detection_regression.c
  ${CMAKE_SOURCE_DIR}/src/preprocess/detection_decision.c
  ${CMAKE_SOURCE_DIR}/src/preprocess/detection_profile.c)
target_include_directories(test_detection_regression PRIVATE ${CMAKE_SOURCE_DIR}/include)
edr_apply_common_warnings(test_detection_regression)
add_test(NAME detection_regression_scenarios COMMAND test_detection_regression WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

add_executable(test_webshell_semantic ${CMAKE_CURRENT_SOURCE_DIR}/test_webshell_semantic.c ${CMAKE_SOURCE_DIR}/src/webshell_detector/webshell_semantic.c)
target_include_directories(test_webshell_semantic PRIVATE ${CMAKE_SOURCE_DIR}/include)
edr_apply_common_warnings(test_webshell_semantic)
add_test(NAME webshell_semantic_rules COMMAND test_webshell_semantic WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

add_executable(test_detection_sensor_bridge ${CMAKE_CURRENT_SOURCE_DIR}/test_detection_sensor_bridge.c
  ${CMAKE_SOURCE_DIR}/src/preprocess/behavior_record.c
  ${CMAKE_SOURCE_DIR}/src/preprocess/behavior_from_slot.c
  ${CMAKE_SOURCE_DIR}/src/preprocess/detection_decision.c
  ${CMAKE_SOURCE_DIR}/src/preprocess/detection_profile.c)
target_include_directories(test_detection_sensor_bridge PRIVATE ${CMAKE_SOURCE_DIR}/include)
edr_apply_common_warnings(test_detection_sensor_bridge)
if(NOT MSVC)
  target_link_libraries(test_detection_sensor_bridge PRIVATE m)
endif()
add_test(NAME detection_sensor_bridge COMMAND test_detection_sensor_bridge WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

if(EDR_PCRE2_AVAILABLE)
  add_executable(test_p0_rule_ir_record_golden
    ${CMAKE_SOURCE_DIR}/src/preprocess/p0_rule_ir_record_golden_test.c
    ${CMAKE_SOURCE_DIR}/src/preprocess/p0_rule_ir.c
    ${CMAKE_SOURCE_DIR}/src/preprocess/behavior_record.c
    ${CMAKE_SOURCE_DIR}/src/preprocess/encrypt_p0_rules.c
    ${CMAKE_SOURCE_DIR}/src/preprocess/preprocess_env.c
    ${CMAKE_SOURCE_DIR}/src/command/sha256.c
    ${CMAKE_SOURCE_DIR}/third_party/cjson/cJSON.c)
  target_include_directories(test_p0_rule_ir_record_golden PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/third_party/cjson)
  if(EDR_PCRE2_TARGET)
    target_link_libraries(test_p0_rule_ir_record_golden PRIVATE ${EDR_PCRE2_TARGET})
  else()
    target_include_directories(test_p0_rule_ir_record_golden PRIVATE ${EDR_PCRE2_INCLUDE_DIR})
    target_link_libraries(test_p0_rule_ir_record_golden PRIVATE ${EDR_PCRE2_LIBRARY})
  endif()
  edr_apply_common_warnings(test_p0_rule_ir_record_golden)
  add_test(NAME p0_rule_ir_record_golden COMMAND test_p0_rule_ir_record_golden WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
  set_tests_properties(p0_rule_ir_record_golden PROPERTIES
    ENVIRONMENT "EDR_P0_IR_PATH=${CMAKE_SOURCE_DIR}/config/p0_rule_bundle_ir_v1.json")
endif()

add_executable(test_windows_event_policy ${CMAKE_CURRENT_SOURCE_DIR}/test_windows_event_policy.c
  ${CMAKE_SOURCE_DIR}/src/preprocess/behavior_record.c
  ${CMAKE_SOURCE_DIR}/src/preprocess/windows_event_policy.c)
target_include_directories(test_windows_event_policy PRIVATE ${CMAKE_SOURCE_DIR}/include)
edr_apply_common_warnings(test_windows_event_policy)
add_test(NAME windows_event_policy COMMAND test_windows_event_policy WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

add_executable(test_collection_admission ${CMAKE_CURRENT_SOURCE_DIR}/test_collection_admission.c
  ${CMAKE_SOURCE_DIR}/src/preprocess/adaptive_collection.c
  ${CMAKE_SOURCE_DIR}/src/preprocess/sensor_interest.c
  ${CMAKE_SOURCE_DIR}/third_party/cjson/cJSON.c)
target_include_directories(test_collection_admission PRIVATE
  ${CMAKE_SOURCE_DIR}/include
  ${CMAKE_SOURCE_DIR}/third_party/cjson)
edr_apply_common_warnings(test_collection_admission)
add_test(NAME collection_admission COMMAND test_collection_admission WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

add_executable(test_preprocess_dedup ${CMAKE_CURRENT_SOURCE_DIR}/test_preprocess_dedup.c
  ${CMAKE_SOURCE_DIR}/src/preprocess/dedup.c
  ${CMAKE_SOURCE_DIR}/src/preprocess/behavior_record.c
  ${CMAKE_SOURCE_DIR}/src/preprocess/windows_event_policy.c)
target_include_directories(test_preprocess_dedup PRIVATE ${CMAKE_SOURCE_DIR}/include)
edr_apply_common_warnings(test_preprocess_dedup)
add_test(NAME preprocess_dedup COMMAND test_preprocess_dedup WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

add_executable(test_ave_pipeline ${CMAKE_CURRENT_SOURCE_DIR}/test_ave_pipeline.c
  ${CMAKE_SOURCE_DIR}/src/ave/ave_sdk.c
  ${CMAKE_SOURCE_DIR}/src/ave/ave_suppression.c
  ${CMAKE_SOURCE_DIR}/src/ave/ave_rules_meta.c
  ${CMAKE_SOURCE_DIR}/src/ave/ave_behavior_pipeline.c
  ${CMAKE_SOURCE_DIR}/src/ave/ave_behavior_features.c
  ${CMAKE_SOURCE_DIR}/src/ave/ave_cross_engine_parse.c
  ${CMAKE_SOURCE_DIR}/src/ave/ave_cross_engine_feed.c
  ${CMAKE_SOURCE_DIR}/src/ave/ave_lf_mpmc.c
  ${CMAKE_SOURCE_DIR}/src/ave/ave_hotfix.c
  ${CMAKE_SOURCE_DIR}/src/ave/ave_db_update.c
  ${CMAKE_SOURCE_DIR}/src/ave/ave_static_features.c
  ${CMAKE_SOURCE_DIR}/src/ave/ave_engine.c
  ${CMAKE_SOURCE_DIR}/src/ave/ave_onnx_infer.c
  ${CMAKE_SOURCE_DIR}/src/core/edr_log.c
  ${CMAKE_SOURCE_DIR}/src/config/config.c
  ${CMAKE_SOURCE_DIR}/src/command/sha256.c
  ${CMAKE_SOURCE_DIR}/third_party/tomlc99/toml.c
  ${_edr_test_behavior_emit_sources}
)
target_link_libraries(test_ave_pipeline PRIVATE edr_ave_test_common)
if(WIN32)
  target_sources(test_ave_pipeline PRIVATE ${CMAKE_SOURCE_DIR}/src/attack_surface/listen_table_win.c)
  target_sources(test_ave_pipeline PRIVATE ${CMAKE_SOURCE_DIR}/src/ave/ave_sign_whitelist_win.c)
else()
  target_sources(test_ave_pipeline PRIVATE ${CMAKE_SOURCE_DIR}/src/ave/ave_sign_whitelist_stub.c)
endif()

add_executable(test_ave_behavior_features_m3a ${CMAKE_CURRENT_SOURCE_DIR}/test_ave_behavior_features_m3a.c ${CMAKE_SOURCE_DIR}/src/ave/ave_behavior_features.c)
target_include_directories(test_ave_behavior_features_m3a PRIVATE ${CMAKE_SOURCE_DIR}/include)
add_executable(test_ave_cross_engine_parse ${CMAKE_CURRENT_SOURCE_DIR}/test_ave_cross_engine_parse.c ${CMAKE_SOURCE_DIR}/src/ave/ave_cross_engine_parse.c)
target_include_directories(test_ave_cross_engine_parse PRIVATE ${CMAKE_SOURCE_DIR}/include)
add_executable(test_ave_cross_engine_feed_quality
  ${CMAKE_CURRENT_SOURCE_DIR}/test_ave_cross_engine_feed_quality.c
  ${CMAKE_SOURCE_DIR}/src/preprocess/behavior_record.c
  ${CMAKE_SOURCE_DIR}/src/ave/ave_cross_engine_feed.c
  ${CMAKE_SOURCE_DIR}/src/ave/ave_cross_engine_parse.c)
target_include_directories(test_ave_cross_engine_feed_quality PRIVATE ${CMAKE_SOURCE_DIR}/include)
if(NOT WIN32)
  target_link_libraries(test_ave_cross_engine_parse PRIVATE m)
  target_link_libraries(test_ave_cross_engine_feed_quality PRIVATE m)
endif()
if(NOT WIN32)
  target_link_libraries(test_ave_behavior_features_m3a PRIVATE m)
endif()
add_test(NAME ave_behavior_features_m3a COMMAND test_ave_behavior_features_m3a WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
add_test(NAME ave_cross_engine_parse COMMAND test_ave_cross_engine_parse WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
add_test(NAME ave_cross_engine_feed_quality COMMAND test_ave_cross_engine_feed_quality WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

add_executable(test_ave_behavior_features_m3b ${CMAKE_CURRENT_SOURCE_DIR}/test_ave_behavior_features_m3b.c ${CMAKE_SOURCE_DIR}/src/ave/ave_behavior_features.c)
target_include_directories(test_ave_behavior_features_m3b PRIVATE ${CMAKE_SOURCE_DIR}/include)
if(NOT WIN32)
  target_link_libraries(test_ave_behavior_features_m3b PRIVATE m)
endif()
add_test(NAME ave_behavior_features_m3b COMMAND test_ave_behavior_features_m3b WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

add_executable(test_ave_behavior_gates ${CMAKE_CURRENT_SOURCE_DIR}/test_ave_behavior_gates.c)
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

add_executable(test_config_fp ${CMAKE_CURRENT_SOURCE_DIR}/test_config_fp.c ${CMAKE_SOURCE_DIR}/src/config/config.c ${CMAKE_SOURCE_DIR}/third_party/tomlc99/toml.c)
target_include_directories(test_config_fp PRIVATE ${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/third_party/tomlc99)

add_executable(test_pmfe_detail ${CMAKE_CURRENT_SOURCE_DIR}/test_pmfe_detail.c)
add_test(NAME pmfe_scan_detail_format COMMAND test_pmfe_detail WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  add_executable(test_pmfe_linux_maps ${CMAKE_CURRENT_SOURCE_DIR}/test_pmfe_linux_maps.c ${CMAKE_SOURCE_DIR}/src/pmfe/pmfe_linux_scan_util.c)
  target_include_directories(test_pmfe_linux_maps PRIVATE ${CMAKE_SOURCE_DIR}/src/pmfe)
  add_test(NAME pmfe_linux_maps_parse COMMAND test_pmfe_linux_maps WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
endif()

if(EDR_WITH_FL_TRAINER)
  edr_absolutize_sources(_edr_fl_trainer_sources_abs ${EDR_FL_TRAINER_SOURCES})
  add_executable(test_fl_trainer_smoke ${CMAKE_CURRENT_SOURCE_DIR}/test_fl_trainer_smoke.c ${CMAKE_SOURCE_DIR}/src/ave/fl_feature_provider.c
                  ${_edr_fl_trainer_sources_abs})
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
  edr_apply_common_warnings(test_fl_trainer_smoke)
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
      set_property(SOURCE ${CMAKE_SOURCE_DIR}/src/fl_trainer/local_train_torch.cpp APPEND PROPERTY COMPILE_OPTIONS
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
    target_include_directories(test_fl_trainer_smoke PRIVATE "${EDR_GRPC_GEN_DIR}")
  endif()
  if(OpenSSL_FOUND)
    add_executable(test_fl_crypto_fl3 ${CMAKE_CURRENT_SOURCE_DIR}/test_fl_crypto_fl3.c ${CMAKE_SOURCE_DIR}/src/fl_trainer/fl_crypto.c)
    target_include_directories(test_fl_crypto_fl3 PRIVATE ${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/src/fl_trainer)
    target_compile_definitions(test_fl_crypto_fl3 PRIVATE EDR_HAVE_OPENSSL_FL=1)
    target_link_libraries(test_fl_crypto_fl3 PRIVATE OpenSSL::Crypto)
    add_test(NAME fl_crypto_fl3 COMMAND test_fl_crypto_fl3 WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
  endif()
  add_executable(test_fl_pb_gradient_chunk ${CMAKE_CURRENT_SOURCE_DIR}/test_fl_pb_gradient_chunk.c ${CMAKE_SOURCE_DIR}/src/fl_trainer/fl_pb_wire.c)
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

  add_executable(test_ave_static_onnx_integration ${CMAKE_CURRENT_SOURCE_DIR}/test_ave_static_onnx_integration.c
    ${CMAKE_SOURCE_DIR}/src/ave/ave_engine.c
    ${CMAKE_SOURCE_DIR}/src/ave/ave_onnx_infer.c
    ${CMAKE_SOURCE_DIR}/src/ave/ave_static_features.c
    ${CMAKE_SOURCE_DIR}/src/config/config.c
    ${CMAKE_SOURCE_DIR}/third_party/tomlc99/toml.c
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

  if(EDR_WITH_AVE_BEHAVIOR_ONNX)
    add_executable(test_ave_behavior_onnx_integration ${CMAKE_CURRENT_SOURCE_DIR}/test_ave_behavior_onnx_integration.c
      ${CMAKE_SOURCE_DIR}/src/ave/ave_onnx_infer.c
      ${CMAKE_SOURCE_DIR}/src/ave/edr_onnx_behavior_fl_tensor_export.c
      ${CMAKE_SOURCE_DIR}/src/ave/ave_static_features.c
      ${CMAKE_SOURCE_DIR}/src/config/config.c
      ${CMAKE_SOURCE_DIR}/third_party/tomlc99/toml.c
    )
    target_include_directories(test_ave_behavior_onnx_integration PRIVATE
      ${CMAKE_SOURCE_DIR}/include
      ${CMAKE_SOURCE_DIR}/src/ave
      ${CMAKE_SOURCE_DIR}/third_party/tomlc99
    )
    target_compile_definitions(test_ave_behavior_onnx_integration PRIVATE EDR_HAVE_ONNXRUNTIME=1 EDR_WITH_AVE_BEHAVIOR_ONNX=1)
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
  endif()

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

foreach(_edr_warning_target IN ITEMS
    test_ave_fp
    test_ave_infer
    test_ave_phase1
    test_ave_sdk
    test_ave_fl_abi
    test_ave_suppression
    test_ave_pipeline
    test_ave_e2e_full
    test_ave_hotfix_smoke
    test_config_fp)
  edr_apply_common_warnings(${_edr_warning_target})
endforeach()
if(EDR_ONNXRUNTIME_AVAILABLE)
  edr_apply_common_warnings(test_ave_static_onnx_integration)
  if(EDR_WITH_AVE_BEHAVIOR_ONNX)
    edr_apply_common_warnings(test_ave_behavior_onnx_integration)
  endif()
endif()

add_test(NAME ave_file_fingerprint COMMAND test_ave_fp WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
add_test(NAME ave_infer_dry_run COMMAND test_ave_infer WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
add_test(NAME ave_phase1_contract COMMAND test_ave_phase1 WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
add_executable(test_ave_static_features ${CMAKE_CURRENT_SOURCE_DIR}/test_ave_static_features.c ${CMAKE_SOURCE_DIR}/src/ave/ave_static_features.c)
target_include_directories(test_ave_static_features PRIVATE ${CMAKE_SOURCE_DIR}/src/ave)
add_test(NAME ave_static_features_lite512 COMMAND test_ave_static_features WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
add_test(NAME ave_sdk_smoke COMMAND test_ave_sdk WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
add_test(NAME ave_fl_abi_c0 COMMAND test_ave_fl_abi WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
if(FALSE AND SQLite3_FOUND)
  add_test(NAME fl_ave_samples_bridge COMMAND test_fl_ave_samples_bridge WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
endif()
add_test(NAME ave_suppression_sqlite COMMAND test_ave_suppression WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
add_test(NAME ave_scan_pipeline COMMAND test_ave_pipeline WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
add_test(NAME config_fingerprint COMMAND test_config_fp WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
if(EDR_WITH_FL_TRAINER)
  add_test(NAME fl_trainer_c1 COMMAND test_fl_trainer_smoke WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
endif()
edr_absolutize_sources(_edr_shellcode_sources_abs ${EDR_SHELLCODE_SRCS})
add_executable(test_shellcode ${CMAKE_CURRENT_SOURCE_DIR}/test_shellcode.c ${_edr_shellcode_sources_abs})
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
  target_link_libraries(test_shellcode PRIVATE advapi32 ws2_32 iphlpapi)
endif()
if(UNIX AND NOT WIN32)
  target_link_libraries(test_shellcode PRIVATE m)
endif()
edr_apply_common_warnings(test_shellcode)
add_test(NAME shellcode_modules COMMAND test_shellcode WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
add_test(NAME edr_agent_smoke COMMAND bash ${CMAKE_SOURCE_DIR}/scripts/agent_smoke.sh $<TARGET_FILE:edr_agent>)
set_tests_properties(edr_agent_smoke PROPERTIES TIMEOUT 30)
