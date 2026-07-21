add_test(NAME edr_agent_help COMMAND edr_agent --help)

add_executable(test_shell_policy ${CMAKE_CURRENT_SOURCE_DIR}/test_shell_policy.c
  ${CMAKE_SOURCE_DIR}/src/command/shell_exec.c
  ${CMAKE_SOURCE_DIR}/third_party/cjson/cJSON.c)
target_include_directories(test_shell_policy PRIVATE
  ${CMAKE_SOURCE_DIR}/include
  ${CMAKE_SOURCE_DIR}/third_party/cjson)
edr_apply_common_warnings(test_shell_policy)
add_test(NAME shell_policy_and_json_parser COMMAND test_shell_policy WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

add_executable(test_command_inbox ${CMAKE_CURRENT_SOURCE_DIR}/test_command_inbox.c
  ${CMAKE_SOURCE_DIR}/src/command/command_state.c
  ${CMAKE_SOURCE_DIR}/third_party/cjson/cJSON.c)
target_include_directories(test_command_inbox PRIVATE
  ${CMAKE_SOURCE_DIR}/include
  ${CMAKE_SOURCE_DIR}/third_party/cjson)
edr_apply_common_warnings(test_command_inbox)
add_test(NAME command_inbox_persistence COMMAND test_command_inbox WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
if(WIN32)
  target_link_libraries(test_command_inbox PRIVATE advapi32)
endif()

if(NOT WIN32)
  add_executable(test_shell_session_stream
    ${CMAKE_CURRENT_SOURCE_DIR}/test_shell_session_stream.c
    ${CMAKE_SOURCE_DIR}/src/shell/shell_session.c)
  target_include_directories(test_shell_session_stream PRIVATE ${CMAKE_SOURCE_DIR}/include)
  edr_apply_common_warnings(test_shell_session_stream)
  add_test(NAME shell_session_stream_completeness COMMAND test_shell_session_stream
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
endif()

add_executable(test_command_contract ${CMAKE_CURRENT_SOURCE_DIR}/test_command_contract.c
  ${CMAKE_SOURCE_DIR}/src/command/command_contract.c
  ${CMAKE_SOURCE_DIR}/src/command/command_registry.c
  ${CMAKE_SOURCE_DIR}/third_party/cjson/cJSON.c)
target_include_directories(test_command_contract PRIVATE
  ${CMAKE_SOURCE_DIR}/include
  ${CMAKE_SOURCE_DIR}/third_party/cjson)
edr_apply_common_warnings(test_command_contract)
add_test(NAME command_registry_and_payload_contract COMMAND test_command_contract
  WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

add_executable(test_command_executor ${CMAKE_CURRENT_SOURCE_DIR}/test_command_executor.c
  ${CMAKE_SOURCE_DIR}/src/command/command_executor.c
  ${CMAKE_SOURCE_DIR}/src/command/command_cancel.c)
target_include_directories(test_command_executor PRIVATE ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(test_command_executor PRIVATE Threads::Threads)
edr_apply_common_warnings(test_command_executor)
add_test(NAME command_executor_thread_isolation COMMAND test_command_executor
  WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

add_executable(test_command_active_type_tls
  ${CMAKE_CURRENT_SOURCE_DIR}/test_command_active_type_tls.c
  ${CMAKE_SOURCE_DIR}/src/command/command_util.c)
target_include_directories(test_command_active_type_tls PRIVATE ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(test_command_active_type_tls PRIVATE Threads::Threads)
edr_apply_common_warnings(test_command_active_type_tls)
add_test(NAME command_active_type_thread_isolation COMMAND test_command_active_type_tls
  WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

add_executable(test_command_cancel ${CMAKE_CURRENT_SOURCE_DIR}/test_command_cancel.c
  ${CMAKE_SOURCE_DIR}/src/command/command_cancel.c)
target_include_directories(test_command_cancel PRIVATE ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(test_command_cancel PRIVATE Threads::Threads)
edr_apply_common_warnings(test_command_cancel)
add_test(NAME command_cancellation_registry COMMAND test_command_cancel
  WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

add_executable(test_request_signing ${CMAKE_CURRENT_SOURCE_DIR}/test_request_signing.c
  ${CMAKE_SOURCE_DIR}/src/transport/request_signing.c
  ${CMAKE_SOURCE_DIR}/src/command/sha256.c)
target_include_directories(test_request_signing PRIVATE ${CMAKE_SOURCE_DIR}/include)
edr_apply_common_warnings(test_request_signing)
add_test(NAME request_signing COMMAND test_request_signing WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

add_executable(test_command_result_json ${CMAKE_CURRENT_SOURCE_DIR}/test_command_result_json.c
  ${CMAKE_SOURCE_DIR}/src/transport/command_result_json.c
  ${CMAKE_SOURCE_DIR}/third_party/cjson/cJSON.c)
target_include_directories(test_command_result_json PRIVATE
  ${CMAKE_SOURCE_DIR}/include
  ${CMAKE_SOURCE_DIR}/third_party/cjson)
edr_apply_common_warnings(test_command_result_json)
add_test(NAME command_result_json_contract COMMAND test_command_result_json
  WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

add_executable(test_attack_surface_contract ${CMAKE_CURRENT_SOURCE_DIR}/test_attack_surface_contract.c)
edr_apply_common_warnings(test_attack_surface_contract)
add_test(NAME attack_surface_command_ingest_contract COMMAND test_attack_surface_contract WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
set_tests_properties(attack_surface_command_ingest_contract PROPERTIES
  ENVIRONMENT "EDR_SOURCE_DIR=${CMAKE_SOURCE_DIR}")

add_executable(test_process_identity_contract
  ${CMAKE_CURRENT_SOURCE_DIR}/test_process_identity_contract.c)
edr_apply_common_warnings(test_process_identity_contract)
add_test(NAME process_identity_lifecycle_contract COMMAND test_process_identity_contract
  WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
set_tests_properties(process_identity_lifecycle_contract PROPERTIES
  ENVIRONMENT "EDR_SOURCE_DIR=${CMAKE_SOURCE_DIR}")

add_executable(test_attack_surface_inventory_policy
  ${CMAKE_CURRENT_SOURCE_DIR}/test_attack_surface_inventory_policy.c
  ${CMAKE_SOURCE_DIR}/src/attack_surface/attack_surface_inventory.c
  ${CMAKE_SOURCE_DIR}/third_party/cjson/cJSON.c)
target_include_directories(test_attack_surface_inventory_policy PRIVATE
  ${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/third_party/cjson)
if(WIN32)
  target_link_libraries(test_attack_surface_inventory_policy PRIVATE netapi32 advapi32)
endif()
edr_apply_common_warnings(test_attack_surface_inventory_policy)
add_test(NAME attack_surface_inventory_policy COMMAND test_attack_surface_inventory_policy)

add_executable(test_control_stream_lease_contract ${CMAKE_CURRENT_SOURCE_DIR}/test_control_stream_lease_contract.c)
edr_apply_common_warnings(test_control_stream_lease_contract)
add_test(NAME control_stream_lease_contract COMMAND test_control_stream_lease_contract
  WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
set_tests_properties(control_stream_lease_contract PROPERTIES
  ENVIRONMENT "EDR_SOURCE_DIR=${CMAKE_SOURCE_DIR}")

add_executable(test_mtls_upload_contract ${CMAKE_CURRENT_SOURCE_DIR}/test_mtls_upload_contract.c)
edr_apply_common_warnings(test_mtls_upload_contract)
add_test(NAME mtls_upload_transport_contract COMMAND test_mtls_upload_contract
  WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
set_tests_properties(mtls_upload_transport_contract PROPERTIES
  ENVIRONMENT "EDR_SOURCE_DIR=${CMAKE_SOURCE_DIR}")

add_executable(test_yara_delivery_contract ${CMAKE_CURRENT_SOURCE_DIR}/test_yara_delivery_contract.c)
edr_apply_common_warnings(test_yara_delivery_contract)
add_test(NAME yara_delivery_contract COMMAND test_yara_delivery_contract
  WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
set_tests_properties(yara_delivery_contract PROPERTIES
  ENVIRONMENT "EDR_SOURCE_DIR=${CMAKE_SOURCE_DIR}")

add_executable(test_windows_headless_runtime_contract
  ${CMAKE_CURRENT_SOURCE_DIR}/test_windows_headless_runtime_contract.c)
edr_apply_common_warnings(test_windows_headless_runtime_contract)
add_test(NAME windows_headless_runtime_contract COMMAND test_windows_headless_runtime_contract
  WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
set_tests_properties(windows_headless_runtime_contract PROPERTIES
  ENVIRONMENT "EDR_SOURCE_DIR=${CMAKE_SOURCE_DIR}")

add_executable(test_remote_config_status_contract
  ${CMAKE_CURRENT_SOURCE_DIR}/test_remote_config_status_contract.c)
edr_apply_common_warnings(test_remote_config_status_contract)
add_test(NAME remote_config_status_contract COMMAND test_remote_config_status_contract
  WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
set_tests_properties(remote_config_status_contract PROPERTIES
  ENVIRONMENT "EDR_SOURCE_DIR=${CMAKE_SOURCE_DIR}")

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
  ${CMAKE_SOURCE_DIR}/src/serialize/alert_governor.c
  ${CMAKE_SOURCE_DIR}/src/serialize/behavior_alert_emit.c
  ${CMAKE_SOURCE_DIR}/src/forensic/process_tree_cache.c
  ${CMAKE_SOURCE_DIR}/src/detection/policy_v2.c
  ${CMAKE_SOURCE_DIR}/src/serialize/behavior_proto.c
  ${CMAKE_SOURCE_DIR}/src/proto/edr/v1/event.pb.c
  ${CMAKE_SOURCE_DIR}/third_party/nanopb/pb_common.c
  ${CMAKE_SOURCE_DIR}/third_party/nanopb/pb_encode.c
  ${CMAKE_SOURCE_DIR}/third_party/nanopb/pb_decode.c
  ${CMAKE_SOURCE_DIR}/third_party/cjson/cJSON.c
  ${CMAKE_SOURCE_DIR}/src/transport/event_batch.c
  ${CMAKE_SOURCE_DIR}/src/transport/ingest_http.c
  ${CMAKE_SOURCE_DIR}/src/transport/command_result_json.c
  ${CMAKE_SOURCE_DIR}/src/transport/request_signing.c
  ${CMAKE_SOURCE_DIR}/src/transport/transport_v2.c
  ${CMAKE_SOURCE_DIR}/src/transport/transport_stub.c
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
  ${CMAKE_SOURCE_DIR}/third_party/cjson
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

target_link_libraries(test_ave_fp PRIVATE edr_ave_test_common)
target_link_libraries(test_ave_infer PRIVATE edr_ave_test_common)
target_link_libraries(test_ave_phase1 PRIVATE edr_ave_test_common)

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
target_link_libraries(test_ave_suppression PRIVATE edr_ave_test_common)

add_executable(test_detection_decision ${CMAKE_CURRENT_SOURCE_DIR}/test_detection_decision.c
  ${CMAKE_SOURCE_DIR}/src/preprocess/detection_decision.c
  ${CMAKE_SOURCE_DIR}/src/preprocess/detection_profile.c
  ${CMAKE_SOURCE_DIR}/src/detection/policy_v2.c)
target_include_directories(test_detection_decision PRIVATE ${CMAKE_SOURCE_DIR}/include)
edr_apply_common_warnings(test_detection_decision)
add_test(NAME detection_decision_combo COMMAND test_detection_decision WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

add_executable(test_detection_regression ${CMAKE_CURRENT_SOURCE_DIR}/test_detection_regression.c
  ${CMAKE_SOURCE_DIR}/src/preprocess/detection_decision.c
  ${CMAKE_SOURCE_DIR}/src/preprocess/detection_profile.c
  ${CMAKE_SOURCE_DIR}/src/detection/policy_v2.c)
target_include_directories(test_detection_regression PRIVATE ${CMAKE_SOURCE_DIR}/include)
edr_apply_common_warnings(test_detection_regression)
add_test(NAME detection_regression_scenarios COMMAND test_detection_regression WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

add_executable(test_detection_profile_trigger
  ${CMAKE_CURRENT_SOURCE_DIR}/test_detection_profile_trigger.c
  ${CMAKE_SOURCE_DIR}/src/detection/detection_profile.c
  ${CMAKE_SOURCE_DIR}/src/detection/detection_trigger.c)
target_include_directories(test_detection_profile_trigger PRIVATE ${CMAKE_SOURCE_DIR}/include)
edr_apply_common_warnings(test_detection_profile_trigger)
add_test(NAME detection_profile_and_trigger_modes COMMAND test_detection_profile_trigger
  WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

add_executable(test_webshell_semantic ${CMAKE_CURRENT_SOURCE_DIR}/test_webshell_semantic.c ${CMAKE_SOURCE_DIR}/src/webshell_detector/webshell_semantic.c)
target_include_directories(test_webshell_semantic PRIVATE ${CMAKE_SOURCE_DIR}/include)
edr_apply_common_warnings(test_webshell_semantic)
add_test(NAME webshell_semantic_rules COMMAND test_webshell_semantic WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

add_executable(test_detection_sensor_bridge ${CMAKE_CURRENT_SOURCE_DIR}/test_detection_sensor_bridge.c
  ${CMAKE_SOURCE_DIR}/src/preprocess/behavior_record.c
  ${CMAKE_SOURCE_DIR}/src/preprocess/behavior_from_slot.c
  ${CMAKE_SOURCE_DIR}/src/preprocess/detection_decision.c
  ${CMAKE_SOURCE_DIR}/src/preprocess/detection_profile.c
  ${CMAKE_SOURCE_DIR}/src/detection/policy_v2.c
  ${CMAKE_SOURCE_DIR}/src/preprocess/windows_event_policy.c)
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

add_executable(test_p0_direct_emit_suppression ${CMAKE_CURRENT_SOURCE_DIR}/test_p0_direct_emit_suppression.c
  ${CMAKE_SOURCE_DIR}/src/preprocess/p0_rule_direct_emit.c
  ${CMAKE_SOURCE_DIR}/src/preprocess/p0_rule_match.c
  ${CMAKE_SOURCE_DIR}/src/preprocess/behavior_record.c
  ${CMAKE_SOURCE_DIR}/src/detection/policy_enforcement.c
  ${CMAKE_SOURCE_DIR}/src/detection/policy_v2.c)
target_include_directories(test_p0_direct_emit_suppression PRIVATE ${CMAKE_SOURCE_DIR}/include)
target_compile_definitions(test_p0_direct_emit_suppression PRIVATE EDR_P0_DIRECT_EMIT_TESTING=1)
edr_apply_common_warnings(test_p0_direct_emit_suppression)
add_test(NAME p0_direct_emit_suppression COMMAND test_p0_direct_emit_suppression WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

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

add_executable(test_process_tree_cache ${CMAKE_CURRENT_SOURCE_DIR}/test_process_tree_cache.c
  ${CMAKE_SOURCE_DIR}/src/forensic/process_tree_cache.c)
target_include_directories(test_process_tree_cache PRIVATE ${CMAKE_SOURCE_DIR}/include)
if(UNIX)
  target_link_libraries(test_process_tree_cache PRIVATE Threads::Threads)
endif()
edr_apply_common_warnings(test_process_tree_cache)
add_test(NAME process_tree_cache COMMAND test_process_tree_cache WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

add_executable(test_local_evidence_cache_candidate ${CMAKE_CURRENT_SOURCE_DIR}/test_local_evidence_cache_candidate.c
  ${CMAKE_SOURCE_DIR}/src/storage/local_evidence_cache.c
  ${CMAKE_SOURCE_DIR}/src/preprocess/behavior_record.c
  ${CMAKE_SOURCE_DIR}/src/preprocess/windows_event_policy.c
  ${CMAKE_SOURCE_DIR}/src/preprocess/p0_rule_ir_stub.c)
target_include_directories(test_local_evidence_cache_candidate PRIVATE ${CMAKE_SOURCE_DIR}/include)
if(SQLite3_FOUND)
  if(TARGET SQLite3::SQLite3)
    target_link_libraries(test_local_evidence_cache_candidate PRIVATE SQLite3::SQLite3)
  else()
    target_link_libraries(test_local_evidence_cache_candidate PRIVATE SQLite::SQLite3)
  endif()
  target_compile_definitions(test_local_evidence_cache_candidate PRIVATE EDR_HAVE_SQLITE=1)
endif()
edr_apply_common_warnings(test_local_evidence_cache_candidate)
add_test(NAME local_evidence_cache_candidate COMMAND test_local_evidence_cache_candidate WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

add_executable(test_deep_collector_manifest ${CMAKE_CURRENT_SOURCE_DIR}/test_deep_collector_manifest.c
  ${CMAKE_SOURCE_DIR}/src/command/sha256.c)
target_include_directories(test_deep_collector_manifest PRIVATE ${CMAKE_SOURCE_DIR}/include)
edr_apply_common_warnings(test_deep_collector_manifest)
add_test(NAME deep_collector_manifest COMMAND test_deep_collector_manifest WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

set(_edr_test_ave_pipeline_sources ${_edr_test_ave_sdk_sources})
list(REMOVE_ITEM _edr_test_ave_pipeline_sources ${CMAKE_SOURCE_DIR}/src/ave/fl_feature_provider.c)
add_executable(test_ave_pipeline ${CMAKE_CURRENT_SOURCE_DIR}/test_ave_pipeline.c
  ${_edr_test_ave_pipeline_sources} ${_edr_test_behavior_emit_sources})
target_link_libraries(test_ave_pipeline PRIVATE edr_ave_test_common)
if(WIN32)
  target_sources(test_ave_pipeline PRIVATE ${CMAKE_SOURCE_DIR}/src/attack_surface/listen_table_win.c)
  target_sources(test_ave_pipeline PRIVATE ${CMAKE_SOURCE_DIR}/src/ave/ave_sign_whitelist_win.c)
else()
  target_sources(test_ave_pipeline PRIVATE ${CMAKE_SOURCE_DIR}/src/ave/ave_sign_whitelist_stub.c)
endif()

if(WIN32)
  foreach(_edr_ave_windows_test
      test_ave_sdk test_ave_fl_abi test_ave_e2e_full test_ave_hotfix_smoke test_ave_pipeline)
    target_sources(${_edr_ave_windows_test} PRIVATE
      ${CMAKE_SOURCE_DIR}/src/attack_surface/attack_surface_win_util.c)
    target_link_libraries(${_edr_ave_windows_test} PRIVATE iphlpapi ws2_32)
  endforeach()
endif()

add_executable(test_ave_behavior_features_m3a ${CMAKE_CURRENT_SOURCE_DIR}/test_ave_behavior_features_m3a.c ${CMAKE_SOURCE_DIR}/src/ave/ave_behavior_features.c)
target_include_directories(test_ave_behavior_features_m3a PRIVATE ${CMAKE_SOURCE_DIR}/include)
add_executable(test_ave_cross_engine_parse ${CMAKE_CURRENT_SOURCE_DIR}/test_ave_cross_engine_parse.c ${CMAKE_SOURCE_DIR}/src/ave/ave_cross_engine_parse.c)
target_include_directories(test_ave_cross_engine_parse PRIVATE ${CMAKE_SOURCE_DIR}/include)
add_executable(test_ave_cross_engine_feed_quality
  ${CMAKE_CURRENT_SOURCE_DIR}/test_ave_cross_engine_feed_quality.c
  ${CMAKE_SOURCE_DIR}/src/preprocess/behavior_record.c
  ${CMAKE_SOURCE_DIR}/src/ave/ave_cross_engine_feed.c
  ${CMAKE_SOURCE_DIR}/src/ave/ave_cross_engine_parse.c
  ${CMAKE_SOURCE_DIR}/src/detection/policy_v2.c)
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

if(EDR_ONNXRUNTIME_AVAILABLE)
  add_library(edr_ave_onnx_test_common INTERFACE)
  target_compile_definitions(edr_ave_onnx_test_common INTERFACE EDR_HAVE_ONNXRUNTIME=1)
  target_include_directories(edr_ave_onnx_test_common INTERFACE ${ONNXRUNTIME_INCLUDE_DIR})
  target_link_libraries(edr_ave_onnx_test_common INTERFACE ${ONNXRUNTIME_LIB})

  foreach(_edr_onnx_test_target IN ITEMS
      test_ave_fp
      test_ave_infer
      test_ave_sdk
      test_ave_fl_abi
      test_ave_pipeline
      test_ave_e2e_full
      test_ave_hotfix_smoke)
    target_link_libraries(${_edr_onnx_test_target} PRIVATE edr_ave_onnx_test_common)
  endforeach()

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
  target_compile_definitions(test_ave_static_onnx_integration PRIVATE
    "EDR_TEST_FIXTURE_ONNX=\"${CMAKE_SOURCE_DIR}/tests/fixtures/static_triple_minimal.onnx\""
  )
  target_link_libraries(test_ave_static_onnx_integration PRIVATE edr_ave_onnx_test_common Threads::Threads)
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
    target_compile_definitions(test_ave_behavior_onnx_integration PRIVATE EDR_WITH_AVE_BEHAVIOR_ONNX=1)
    target_compile_definitions(test_ave_behavior_onnx_integration PRIVATE
      "EDR_TEST_BEHAVIOR_FIXTURE=\"${CMAKE_SOURCE_DIR}/tests/fixtures/behavior_dual_minimal.onnx\""
      "EDR_TEST_BEHAVIOR_SEQ128_FIXTURE=\"${CMAKE_SOURCE_DIR}/tests/fixtures/behavior_seq128_dual_minimal.onnx\""
    )
    target_link_libraries(test_ave_behavior_onnx_integration PRIVATE edr_ave_onnx_test_common Threads::Threads)
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
if(WIN32)
  target_sources(test_shellcode PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/stub_shellcode_runtime_hooks.c)
endif()
if(EDR_YARA_AVAILABLE)
  target_compile_definitions(test_shellcode PRIVATE EDR_HAVE_YARA=1)
  if(EDR_YARA_TARGET)
    target_link_libraries(test_shellcode PRIVATE ${EDR_YARA_TARGET})
  else()
    target_include_directories(test_shellcode PRIVATE ${YARA_INCLUDE_DIR})
    target_link_libraries(test_shellcode PRIVATE ${YARA_LIB})
  endif()
endif()
if(WIN32)
  target_link_libraries(test_shellcode PRIVATE advapi32 ws2_32 iphlpapi)
endif()
if(UNIX AND NOT WIN32)
  target_link_libraries(test_shellcode PRIVATE m)
endif()
edr_apply_common_warnings(test_shellcode)
add_test(NAME shellcode_modules COMMAND test_shellcode WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
set_tests_properties(shellcode_modules PROPERTIES LABELS "shellcode")

# §A bundled shellcode YARA 规则可加载 + 已知漏洞命中（无 YARA 时回退内置匹配器）
add_executable(test_shellcode_yara_rules ${CMAKE_CURRENT_SOURCE_DIR}/test_shellcode_yara_rules.c ${_edr_shellcode_sources_abs})
target_include_directories(test_shellcode_yara_rules PRIVATE
  ${CMAKE_SOURCE_DIR}/include
  ${CMAKE_SOURCE_DIR}/third_party/windivert
)
if(WIN32)
  target_sources(test_shellcode_yara_rules PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/stub_shellcode_runtime_hooks.c)
endif()
target_compile_definitions(test_shellcode_yara_rules PRIVATE
  EDR_SHELLCODE_RULES_DIR="${CMAKE_SOURCE_DIR}/src/shellcode_detector/rules")
if(EDR_YARA_AVAILABLE)
  target_compile_definitions(test_shellcode_yara_rules PRIVATE EDR_HAVE_YARA=1)
  if(EDR_YARA_TARGET)
    target_link_libraries(test_shellcode_yara_rules PRIVATE ${EDR_YARA_TARGET})
  else()
    target_include_directories(test_shellcode_yara_rules PRIVATE ${YARA_INCLUDE_DIR})
    target_link_libraries(test_shellcode_yara_rules PRIVATE ${YARA_LIB})
  endif()
endif()
if(WIN32)
  target_link_libraries(test_shellcode_yara_rules PRIVATE advapi32 ws2_32 iphlpapi)
endif()
if(UNIX AND NOT WIN32)
  target_link_libraries(test_shellcode_yara_rules PRIVATE m)
endif()
edr_apply_common_warnings(test_shellcode_yara_rules)
add_test(NAME shellcode_yara_rules COMMAND test_shellcode_yara_rules WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
set_tests_properties(shellcode_yara_rules PROPERTIES LABELS "shellcode")

add_executable(test_yara_rule_catalog_compile ${CMAKE_CURRENT_SOURCE_DIR}/test_yara_rule_catalog_compile.c)
target_include_directories(test_yara_rule_catalog_compile PRIVATE ${CMAKE_SOURCE_DIR}/include)
target_compile_definitions(test_yara_rule_catalog_compile PRIVATE
  EDR_FORENSIC_RULES_DIR="${CMAKE_SOURCE_DIR}/rules/forensic"
  EDR_SHELLCODE_RULES_DIR="${CMAKE_SOURCE_DIR}/src/shellcode_detector/rules"
  EDR_WEBSHELL_RULES_DIR="${CMAKE_SOURCE_DIR}/src/webshell_detector/rules")
if(EDR_YARA_AVAILABLE)
  target_compile_definitions(test_yara_rule_catalog_compile PRIVATE EDR_HAVE_YARA=1)
  if(EDR_YARA_TARGET)
    target_link_libraries(test_yara_rule_catalog_compile PRIVATE ${EDR_YARA_TARGET})
  else()
    target_include_directories(test_yara_rule_catalog_compile PRIVATE ${YARA_INCLUDE_DIR})
    target_link_libraries(test_yara_rule_catalog_compile PRIVATE ${YARA_LIB})
  endif()
endif()
edr_apply_common_warnings(test_yara_rule_catalog_compile)
add_test(NAME yara_rule_catalog_compile COMMAND test_yara_rule_catalog_compile WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

# P0 #2/#3 流级去重 + TLS 记录短路（纯逻辑，跨平台）
add_executable(test_shellcode_flow_dedup
  ${CMAKE_CURRENT_SOURCE_DIR}/test_shellcode_flow_dedup.c
  ${CMAKE_SOURCE_DIR}/src/shellcode_detector/flow_dedup.c
  ${CMAKE_SOURCE_DIR}/src/shellcode_detector/proto_parse.c)
target_include_directories(test_shellcode_flow_dedup PRIVATE ${CMAKE_SOURCE_DIR}/include)
edr_apply_common_warnings(test_shellcode_flow_dedup)
add_test(NAME shellcode_flow_dedup COMMAND test_shellcode_flow_dedup WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
set_tests_properties(shellcode_flow_dedup PROPERTIES LABELS "shellcode")

add_executable(test_shellcode_tcp_reassembly
  ${CMAKE_CURRENT_SOURCE_DIR}/test_shellcode_tcp_reassembly.c
  ${CMAKE_SOURCE_DIR}/src/shellcode_detector/tcp_reassembly.c)
target_include_directories(test_shellcode_tcp_reassembly PRIVATE ${CMAKE_SOURCE_DIR}/include)
edr_apply_common_warnings(test_shellcode_tcp_reassembly)
add_test(NAME shellcode_tcp_reassembly COMMAND test_shellcode_tcp_reassembly
  WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
set_tests_properties(shellcode_tcp_reassembly PROPERTIES LABELS "shellcode")

add_executable(test_shellcode_server_benchmark
  ${CMAKE_CURRENT_SOURCE_DIR}/test_shellcode_server_benchmark.c
  ${CMAKE_SOURCE_DIR}/src/shellcode_detector/tcp_reassembly.c
  ${CMAKE_SOURCE_DIR}/src/shellcode_detector/proto_parse.c
  ${CMAKE_SOURCE_DIR}/src/shellcode_detector/shellcode_entropy.c
  ${CMAKE_SOURCE_DIR}/src/shellcode_detector/shellcode_heuristic.c)
target_include_directories(test_shellcode_server_benchmark PRIVATE ${CMAKE_SOURCE_DIR}/include)
edr_apply_common_warnings(test_shellcode_server_benchmark)
if(UNIX AND NOT WIN32)
  target_link_libraries(test_shellcode_server_benchmark PRIVATE m)
endif()
add_test(NAME shellcode_server_benchmark COMMAND test_shellcode_server_benchmark
  WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
set_tests_properties(shellcode_server_benchmark PROPERTIES
  LABELS "shellcode;performance;release-gate"
  TIMEOUT 30)

add_executable(test_shellcode_runtime_contract
  ${CMAKE_CURRENT_SOURCE_DIR}/test_shellcode_runtime_contract.c)
edr_apply_common_warnings(test_shellcode_runtime_contract)
add_test(NAME shellcode_runtime_truth_contract COMMAND test_shellcode_runtime_contract
  WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
set_tests_properties(shellcode_runtime_truth_contract PROPERTIES
  ENVIRONMENT "EDR_SOURCE_DIR=${CMAKE_SOURCE_DIR}"
  LABELS "shellcode")

# 端侧网络扇出/扫描检测器核心逻辑
add_executable(test_net_fanout
  ${CMAKE_CURRENT_SOURCE_DIR}/test_net_fanout.c
  ${CMAKE_SOURCE_DIR}/src/detection/net_fanout_core.c)
target_include_directories(test_net_fanout PRIVATE ${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/src/detection)
edr_apply_common_warnings(test_net_fanout)
add_test(NAME net_fanout COMMAND test_net_fanout WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

# §B1 子系统心跳逻辑
add_executable(test_self_protect_heartbeat
  ${CMAKE_CURRENT_SOURCE_DIR}/test_self_protect_heartbeat.c
  ${CMAKE_SOURCE_DIR}/src/self_protect/heartbeat.c
  ${CMAKE_SOURCE_DIR}/src/core/time_util.c)
target_include_directories(test_self_protect_heartbeat PRIVATE ${CMAKE_SOURCE_DIR}/include)
edr_apply_common_warnings(test_self_protect_heartbeat)
add_test(NAME self_protect_heartbeat COMMAND test_self_protect_heartbeat WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

# Release blocker: ordinary behavior-alert output must stay within the endpoint/rule SLO.
add_executable(test_alert_governor_cardinality
  ${CMAKE_CURRENT_SOURCE_DIR}/test_alert_governor_cardinality.c
  ${CMAKE_SOURCE_DIR}/src/serialize/alert_governor.c
  ${CMAKE_SOURCE_DIR}/src/serialize/behavior_alert_emit.c
  ${CMAKE_SOURCE_DIR}/src/forensic/process_tree_cache.c
  ${CMAKE_SOURCE_DIR}/src/detection/policy_v2.c)
target_include_directories(test_alert_governor_cardinality PRIVATE ${CMAKE_SOURCE_DIR}/include)
target_compile_definitions(test_alert_governor_cardinality PRIVATE EDR_HAVE_NANOPB=1)
if(UNIX AND NOT WIN32)
  target_link_libraries(test_alert_governor_cardinality PRIVATE Threads::Threads)
endif()
edr_apply_common_warnings(test_alert_governor_cardinality)
add_test(NAME alert_cardinality_release_gate COMMAND test_alert_governor_cardinality WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
set_tests_properties(alert_cardinality_release_gate PROPERTIES LABELS "release-gate")

add_executable(test_policy_v2
  ${CMAKE_CURRENT_SOURCE_DIR}/test_policy_v2.c
  ${CMAKE_SOURCE_DIR}/src/detection/policy_v2.c)
target_include_directories(test_policy_v2 PRIVATE ${CMAKE_SOURCE_DIR}/include)
edr_apply_common_warnings(test_policy_v2)
add_test(NAME endpoint_policy_v2_modes COMMAND test_policy_v2 WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

add_executable(test_forensic_result_contract
  ${CMAKE_CURRENT_SOURCE_DIR}/test_forensic_result_contract.c
  ${CMAKE_SOURCE_DIR}/src/command/forensic_result_contract.c)
target_include_directories(test_forensic_result_contract PRIVATE ${CMAKE_SOURCE_DIR}/include)
edr_apply_common_warnings(test_forensic_result_contract)
add_test(NAME forensic_result_contract COMMAND test_forensic_result_contract WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

add_executable(test_event_batch_max_age
  ${CMAKE_CURRENT_SOURCE_DIR}/test_event_batch_max_age.c
  ${CMAKE_SOURCE_DIR}/src/transport/event_batch.c)
target_include_directories(test_event_batch_max_age PRIVATE ${CMAKE_SOURCE_DIR}/include)
edr_apply_common_warnings(test_event_batch_max_age)
add_test(NAME event_batch_max_age COMMAND test_event_batch_max_age WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

add_test(NAME edr_agent_smoke COMMAND bash ${CMAKE_SOURCE_DIR}/scripts/agent_smoke.sh $<TARGET_FILE:edr_agent>)
set_tests_properties(edr_agent_smoke PROPERTIES TIMEOUT 30)
