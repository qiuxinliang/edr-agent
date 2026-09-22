add_test(NAME edr_agent_help COMMAND edr_agent --help)

find_package(Python3 REQUIRED COMPONENTS Interpreter)
add_custom_target(test_python_installer_config_contract DEPENDS edr_agent)
add_test(NAME python_installer_config_contract
  COMMAND ${Python3_EXECUTABLE} -B ${CMAKE_CURRENT_SOURCE_DIR}/test_python_installer_config_contract.py
    --agent $<TARGET_FILE:edr_agent>)
set_tests_properties(python_installer_config_contract PROPERTIES TIMEOUT 120)

if(OpenSSL_FOUND)
  add_executable(test_command_signature_cross_language
    ${CMAKE_CURRENT_SOURCE_DIR}/test_command_signature_cross_language.c
    ${CMAKE_SOURCE_DIR}/src/command/command_signature.c
    ${CMAKE_SOURCE_DIR}/src/command/command_signature_helpers.c
    ${CMAKE_SOURCE_DIR}/src/command/sha256.c
    ${CMAKE_SOURCE_DIR}/third_party/cjson/cJSON.c)
  configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/testdata/command_sigv2_fixture.json
    ${CMAKE_CURRENT_BINARY_DIR}/command_sigv2_fixture.json
    COPYONLY)
  target_include_directories(test_command_signature_cross_language PRIVATE
    ${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/third_party/cjson)
  edr_apply_test_warnings(test_command_signature_cross_language)
  target_compile_definitions(test_command_signature_cross_language PRIVATE EDR_HAVE_OPENSSL_HTTP=1)
  target_link_libraries(test_command_signature_cross_language PRIVATE OpenSSL::SSL OpenSSL::Crypto)
  add_test(NAME command_signature_cross_language COMMAND test_command_signature_cross_language
    ${CMAKE_CURRENT_BINARY_DIR}/command_sigv2_fixture.json
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
else()
  message(STATUS "Command signature cross-language test unavailable: OpenSSL was not found")
endif()

add_executable(test_response_capability_manifest
  ${CMAKE_CURRENT_SOURCE_DIR}/test_response_capability_manifest.c
  ${CMAKE_SOURCE_DIR}/src/core/response_capability_manifest.c
  ${CMAKE_SOURCE_DIR}/third_party/cjson/cJSON.c)
target_include_directories(test_response_capability_manifest PRIVATE
  ${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/third_party/cjson)
edr_apply_test_warnings(test_response_capability_manifest)
add_test(NAME response_capability_manifest_contract COMMAND test_response_capability_manifest
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})

add_executable(test_shell_policy ${CMAKE_CURRENT_SOURCE_DIR}/test_shell_policy.c
  ${CMAKE_SOURCE_DIR}/src/command/shell_exec.c
  ${CMAKE_SOURCE_DIR}/third_party/cjson/cJSON.c)
target_include_directories(test_shell_policy PRIVATE
  ${CMAKE_SOURCE_DIR}/include
  ${CMAKE_SOURCE_DIR}/third_party/cjson)
if(WIN32)
  target_sources(test_shell_policy PRIVATE
    ${CMAKE_SOURCE_DIR}/src/platform/windows_spawn_lock.c)
endif()
edr_apply_test_warnings(test_shell_policy)
add_test(NAME shell_policy_and_json_parser COMMAND test_shell_policy WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

add_executable(test_command_inbox ${CMAKE_CURRENT_SOURCE_DIR}/test_command_inbox.c
  ${CMAKE_SOURCE_DIR}/src/command/command_state.c
  ${CMAKE_SOURCE_DIR}/third_party/cjson/cJSON.c)
target_include_directories(test_command_inbox PRIVATE
  ${CMAKE_SOURCE_DIR}/include
  ${CMAKE_SOURCE_DIR}/third_party/cjson)
target_link_libraries(test_command_inbox PRIVATE Threads::Threads)
edr_apply_test_warnings(test_command_inbox)
add_test(NAME command_inbox_persistence COMMAND test_command_inbox WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
if(WIN32)
  target_link_libraries(test_command_inbox PRIVATE advapi32)
endif()

add_executable(test_response_forensic_paths
  ${CMAKE_CURRENT_SOURCE_DIR}/test_response_forensic_paths.c
  ${CMAKE_SOURCE_DIR}/src/response/response_utils.c
  ${CMAKE_SOURCE_DIR}/third_party/cjson/cJSON.c)
target_include_directories(test_response_forensic_paths PRIVATE ${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/third_party/cjson)
edr_apply_test_warnings(test_response_forensic_paths)
add_test(NAME response_forensic_path_contract COMMAND test_response_forensic_paths
  WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

# The test embeds the implementation for Win32 error/readback injection.
add_executable(test_response_file_security
  ${CMAKE_CURRENT_SOURCE_DIR}/test_response_file_security.c)
target_include_directories(test_response_file_security PRIVATE ${CMAKE_SOURCE_DIR}/include)
edr_apply_test_warnings(test_response_file_security)
if(WIN32)
  target_link_libraries(test_response_file_security PRIVATE advapi32)
  add_test(NAME windows_isolation_mock_behavior
    COMMAND powershell.exe -NoProfile -ExecutionPolicy Bypass -File ${CMAKE_SOURCE_DIR}/scripts/test_windows_isolation_behavior.ps1)
endif()
add_test(NAME response_file_security_behavior COMMAND test_response_file_security)

if(NOT WIN32)
  add_executable(test_shell_session_stream
    ${CMAKE_CURRENT_SOURCE_DIR}/test_shell_session_stream.c
    ${CMAKE_SOURCE_DIR}/src/shell/shell_session.c)
  target_include_directories(test_shell_session_stream PRIVATE ${CMAKE_SOURCE_DIR}/include)
  edr_apply_test_warnings(test_shell_session_stream)
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
edr_apply_test_warnings(test_command_contract)
add_test(NAME command_registry_and_payload_contract COMMAND test_command_contract
  WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

add_executable(test_command_process ${CMAKE_CURRENT_SOURCE_DIR}/test_command_process.c
  ${CMAKE_SOURCE_DIR}/src/command/command_process.c
  ${CMAKE_SOURCE_DIR}/src/command/command_util.c
  ${CMAKE_SOURCE_DIR}/src/command/command_state.c
  ${CMAKE_SOURCE_DIR}/third_party/cjson/cJSON.c)
target_include_directories(test_command_process PRIVATE ${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/third_party/cjson)
target_link_libraries(test_command_process PRIVATE Threads::Threads)
if(WIN32)
  target_link_libraries(test_command_process PRIVATE advapi32)
endif()
edr_apply_test_warnings(test_command_process)
add_test(NAME command_process_identity_and_receipts COMMAND test_command_process)

add_executable(test_agent_update_contract
  ${CMAKE_CURRENT_SOURCE_DIR}/test_agent_update_contract.c
  ${CMAKE_SOURCE_DIR}/src/command/agent_update_command.c
  ${CMAKE_SOURCE_DIR}/src/command/agent_update_event.c
  ${CMAKE_SOURCE_DIR}/src/command/full_installer_readiness.c
  ${CMAKE_SOURCE_DIR}/src/command/full_installer_windows_identity.c
  ${CMAKE_SOURCE_DIR}/src/command/sha256.c
  ${CMAKE_SOURCE_DIR}/src/command/command_contract.c
  ${CMAKE_SOURCE_DIR}/src/command/command_registry.c
  ${CMAKE_SOURCE_DIR}/third_party/cjson/cJSON.c)
target_include_directories(test_agent_update_contract PRIVATE
  ${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/third_party/cjson)
if(NOT WIN32)
  target_compile_definitions(test_agent_update_contract PRIVATE EDR_OS_POSIX=1)
else()
  target_link_libraries(test_agent_update_contract PRIVATE
    advapi32 shell32 ole32 oleaut32 uuid taskschd)
endif()
edr_apply_test_warnings(test_agent_update_contract)
add_test(NAME agent_update_command_contract COMMAND test_agent_update_contract)

if(NOT WIN32)
  add_executable(test_agent_update_event
    ${CMAKE_CURRENT_SOURCE_DIR}/test_agent_update_event.c
    ${CMAKE_SOURCE_DIR}/src/command/agent_update_event.c
    ${CMAKE_SOURCE_DIR}/third_party/cjson/cJSON.c)
  target_include_directories(test_agent_update_event PRIVATE
    ${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/third_party/cjson)
  edr_apply_test_warnings(test_agent_update_event)
  add_test(NAME agent_update_event_outbox COMMAND test_agent_update_event)
endif()

add_executable(test_agent_update_assets ${CMAKE_CURRENT_SOURCE_DIR}/test_agent_update_assets.c)
edr_apply_test_warnings(test_agent_update_assets)
add_test(NAME agent_update_packaging_contract COMMAND test_agent_update_assets)
set_tests_properties(agent_update_packaging_contract PROPERTIES
  ENVIRONMENT "EDR_SOURCE_DIR=${CMAKE_SOURCE_DIR}")

if(WIN32)
  add_executable(test_agent_update_embedded_resource
    ${CMAKE_CURRENT_SOURCE_DIR}/test_agent_update_embedded_resource.c
    ${CMAKE_SOURCE_DIR}/resources/FDSensor.rc)
  target_include_directories(test_agent_update_embedded_resource PRIVATE ${CMAKE_SOURCE_DIR}/include)
  edr_apply_test_warnings(test_agent_update_embedded_resource)
  add_test(NAME agent_update_embedded_resource COMMAND test_agent_update_embedded_resource)
  set_tests_properties(agent_update_embedded_resource PROPERTIES
    ENVIRONMENT "EDR_SOURCE_DIR=${CMAKE_SOURCE_DIR}")
  # CTest inherits PSModulePath from CI's pwsh host. Windows PowerShell must
  # rebuild its own module path before startup (not import PowerShell 7 modules).
  add_test(NAME windows_release_collector_pe_closure
    COMMAND "${CMAKE_COMMAND}" -E env --unset=PSModulePath powershell.exe -NoProfile -Command
      "& ([scriptblock]::Create((Get-Content -LiteralPath '${CMAKE_CURRENT_SOURCE_DIR}/test_windows_release_collector_pe_closure.ps1' -Raw -Encoding UTF8))) -RepoRoot '${CMAKE_SOURCE_DIR}'")
  add_test(NAME windows_inplace_collector_transaction
    COMMAND "${CMAKE_COMMAND}" -E env --unset=PSModulePath powershell.exe -NoProfile -Command
      "& ([scriptblock]::Create((Get-Content -LiteralPath '${CMAKE_CURRENT_SOURCE_DIR}/test_windows_inplace_collector_transaction.ps1' -Raw -Encoding UTF8))) -RepoRoot '${CMAKE_SOURCE_DIR}'")
  set_tests_properties(
    windows_release_collector_pe_closure
    windows_inplace_collector_transaction
    PROPERTIES TIMEOUT 60)
  add_test(NAME windows_installer_acl_behavior
    COMMAND "${CMAKE_COMMAND}" -E env --unset=PSModulePath powershell.exe -NoProfile -Command
      "& ([scriptblock]::Create((Get-Content -LiteralPath '${CMAKE_CURRENT_SOURCE_DIR}/test_windows_installer_acl.ps1' -Raw -Encoding UTF8))) -InstallerWorker '$<TARGET_FILE:fd_installer_worker>'")
  set_tests_properties(windows_installer_acl_behavior PROPERTIES TIMEOUT 120)
endif()

add_executable(test_command_executor ${CMAKE_CURRENT_SOURCE_DIR}/test_command_executor.c
  ${CMAKE_SOURCE_DIR}/src/command/command_executor.c
  ${CMAKE_SOURCE_DIR}/src/command/command_cancel.c)
target_include_directories(test_command_executor PRIVATE ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(test_command_executor PRIVATE Threads::Threads)
edr_apply_test_warnings(test_command_executor)
add_test(NAME command_executor_thread_isolation COMMAND test_command_executor
  WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

add_executable(test_command_active_type_tls
  ${CMAKE_CURRENT_SOURCE_DIR}/test_command_active_type_tls.c
  ${CMAKE_SOURCE_DIR}/src/command/command_util.c)
target_include_directories(test_command_active_type_tls PRIVATE ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(test_command_active_type_tls PRIVATE Threads::Threads)
edr_apply_test_warnings(test_command_active_type_tls)
add_test(NAME command_active_type_thread_isolation COMMAND test_command_active_type_tls
  WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

add_executable(test_command_cancel ${CMAKE_CURRENT_SOURCE_DIR}/test_command_cancel.c
  ${CMAKE_SOURCE_DIR}/src/command/command_cancel.c)
target_include_directories(test_command_cancel PRIVATE ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(test_command_cancel PRIVATE Threads::Threads)
edr_apply_test_warnings(test_command_cancel)
add_test(NAME command_cancellation_registry COMMAND test_command_cancel
  WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

add_executable(test_request_signing ${CMAKE_CURRENT_SOURCE_DIR}/test_request_signing.c
  ${CMAKE_SOURCE_DIR}/src/transport/request_signing.c
  ${CMAKE_SOURCE_DIR}/src/command/sha256.c)
target_include_directories(test_request_signing PRIVATE ${CMAKE_SOURCE_DIR}/include)
if(WIN32)
  target_link_libraries(test_request_signing PRIVATE advapi32)
endif()
edr_apply_test_warnings(test_request_signing)
add_test(NAME request_signing COMMAND test_request_signing WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

add_executable(test_http_retry
  ${CMAKE_CURRENT_SOURCE_DIR}/test_http_retry.c
  ${CMAKE_SOURCE_DIR}/src/transport/http_retry.c
  ${CMAKE_SOURCE_DIR}/src/transport/request_signing.c
  ${CMAKE_SOURCE_DIR}/src/command/sha256.c)
target_include_directories(test_http_retry PRIVATE ${CMAKE_SOURCE_DIR}/include)
if(WIN32)
  target_link_libraries(test_http_retry PRIVATE advapi32)
endif()
edr_apply_test_warnings(test_http_retry)
add_test(NAME http_retry_contract COMMAND test_http_retry)

add_executable(test_transport_v2_status
  ${CMAKE_CURRENT_SOURCE_DIR}/test_transport_v2_status.c
  ${CMAKE_SOURCE_DIR}/src/transport/transport_v2.c)
target_include_directories(test_transport_v2_status PRIVATE ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(test_transport_v2_status PRIVATE Threads::Threads)
edr_apply_test_warnings(test_transport_v2_status)
add_test(NAME transport_v2_status_capacity COMMAND test_transport_v2_status)

add_executable(test_transport_durable_owner
  ${CMAKE_CURRENT_SOURCE_DIR}/test_transport_durable_owner.c
  ${CMAKE_SOURCE_DIR}/src/transport/transport_stub.c
  ${CMAKE_SOURCE_DIR}/src/core/time_util.c)
target_include_directories(test_transport_durable_owner PRIVATE ${CMAKE_SOURCE_DIR}/include)
target_compile_definitions(test_transport_durable_owner PRIVATE EDR_TRANSPORT_STOP_TIMEOUT_MS=25)
target_link_libraries(test_transport_durable_owner PRIVATE Threads::Threads)
edr_apply_test_warnings(test_transport_durable_owner)
add_test(NAME transport_durable_owner COMMAND test_transport_durable_owner)

add_executable(test_process_evidence_pending
  ${CMAKE_CURRENT_SOURCE_DIR}/test_process_evidence_pending.c
  ${CMAKE_SOURCE_DIR}/src/preprocess/process_evidence_pending.c)
target_include_directories(test_process_evidence_pending PRIVATE ${CMAKE_SOURCE_DIR}/include)
edr_apply_test_warnings(test_process_evidence_pending)
add_test(NAME process_evidence_pending COMMAND test_process_evidence_pending)

add_executable(test_telemetry_admission
  ${CMAKE_CURRENT_SOURCE_DIR}/test_telemetry_admission.c
  ${CMAKE_SOURCE_DIR}/src/preprocess/telemetry_admission.c)
target_include_directories(test_telemetry_admission PRIVATE ${CMAKE_SOURCE_DIR}/include)
edr_apply_test_warnings(test_telemetry_admission)
add_test(NAME telemetry_admission COMMAND test_telemetry_admission)

add_executable(test_pid_history_pmfe
  ${CMAKE_CURRENT_SOURCE_DIR}/test_pid_history_pmfe.c
  ${CMAKE_SOURCE_DIR}/src/pmfe/pid_history_pmfe.c)
target_include_directories(test_pid_history_pmfe PRIVATE ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(test_pid_history_pmfe PRIVATE Threads::Threads)
edr_apply_test_warnings(test_pid_history_pmfe)
add_test(NAME pid_history_pmfe_generation COMMAND test_pid_history_pmfe)

add_executable(test_command_result_json ${CMAKE_CURRENT_SOURCE_DIR}/test_command_result_json.c
  ${CMAKE_SOURCE_DIR}/src/transport/command_result_json.c
  ${CMAKE_SOURCE_DIR}/third_party/cjson/cJSON.c)
target_include_directories(test_command_result_json PRIVATE
  ${CMAKE_SOURCE_DIR}/include
  ${CMAKE_SOURCE_DIR}/third_party/cjson)
edr_apply_test_warnings(test_command_result_json)
add_test(NAME command_result_json_contract COMMAND test_command_result_json
  WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

add_executable(test_attack_surface_contract ${CMAKE_CURRENT_SOURCE_DIR}/test_attack_surface_contract.c)
edr_apply_test_warnings(test_attack_surface_contract)
add_test(NAME attack_surface_command_ingest_contract COMMAND test_attack_surface_contract WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
set_tests_properties(attack_surface_command_ingest_contract PROPERTIES
  ENVIRONMENT "EDR_SOURCE_DIR=${CMAKE_SOURCE_DIR}")

add_executable(test_process_identity_contract
  ${CMAKE_CURRENT_SOURCE_DIR}/test_process_identity_contract.c
  ${CMAKE_SOURCE_DIR}/third_party/cjson/cJSON.c)
target_include_directories(test_process_identity_contract PRIVATE
  ${CMAKE_SOURCE_DIR}/third_party/cjson)
edr_apply_test_warnings(test_process_identity_contract)
add_test(NAME process_identity_lifecycle_contract COMMAND test_process_identity_contract
  WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
set_tests_properties(process_identity_lifecycle_contract PROPERTIES
  ENVIRONMENT "EDR_SOURCE_DIR=${CMAKE_SOURCE_DIR}")

add_executable(test_windows_file_identity_contract
  ${CMAKE_CURRENT_SOURCE_DIR}/test_windows_file_identity_contract.c
  ${CMAKE_SOURCE_DIR}/src/preprocess/windows_file_identity.c)
target_include_directories(test_windows_file_identity_contract PRIVATE ${CMAKE_SOURCE_DIR}/include)
edr_apply_test_warnings(test_windows_file_identity_contract)
add_test(NAME windows_file_identity_contract COMMAND test_windows_file_identity_contract)

add_executable(test_windows_unicode_path_contract
  ${CMAKE_CURRENT_SOURCE_DIR}/test_windows_unicode_path_contract.c)
edr_apply_test_warnings(test_windows_unicode_path_contract)
add_test(NAME windows_unicode_path_source_contract COMMAND test_windows_unicode_path_contract
  WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
set_tests_properties(windows_unicode_path_source_contract PROPERTIES
  ENVIRONMENT "EDR_SOURCE_DIR=${CMAKE_SOURCE_DIR}")

if(WIN32)
  add_executable(test_rtq_long_command_windows
    ${CMAKE_CURRENT_SOURCE_DIR}/test_rtq_long_command_windows.c
    ${CMAKE_SOURCE_DIR}/src/preprocess/process_generation.c)
  target_include_directories(test_rtq_long_command_windows PRIVATE
    ${CMAKE_SOURCE_DIR}/include)
  target_link_libraries(test_rtq_long_command_windows PRIVATE advapi32)
  edr_apply_test_warnings(test_rtq_long_command_windows)
  add_test(NAME rtq_long_command_windows
    COMMAND test_rtq_long_command_windows)
endif()

if(WIN32)
  add_executable(test_windows_unicode_path_native
    ${CMAKE_CURRENT_SOURCE_DIR}/test_windows_unicode_path_native.c
    ${CMAKE_SOURCE_DIR}/src/preprocess/windows_file_identity.c)
  target_include_directories(test_windows_unicode_path_native PRIVATE
    ${CMAKE_SOURCE_DIR}/include)
  edr_apply_test_warnings(test_windows_unicode_path_native)
  add_test(NAME windows_unicode_path_native_contract
    COMMAND test_windows_unicode_path_native)

  add_executable(test_process_evidence_worker_windows
    ${CMAKE_CURRENT_SOURCE_DIR}/test_process_evidence_worker_windows.c
    ${CMAKE_SOURCE_DIR}/src/preprocess/process_evidence_worker.c
    ${CMAKE_SOURCE_DIR}/src/preprocess/windows_file_identity.c
    ${CMAKE_SOURCE_DIR}/src/command/sha256.c
    ${CMAKE_SOURCE_DIR}/src/core/time_util.c)
  target_include_directories(test_process_evidence_worker_windows PRIVATE
    ${CMAKE_SOURCE_DIR}/include)
  target_compile_definitions(test_process_evidence_worker_windows PRIVATE
    EDR_PROCESS_EVIDENCE_TESTING=1
    EDR_WINDOWS_FILE_IDENTITY_TESTING=1)
  target_link_libraries(test_process_evidence_worker_windows PRIVATE wintrust crypt32)
  edr_apply_test_warnings(test_process_evidence_worker_windows)
  add_test(NAME process_evidence_worker_windows_toctou
    COMMAND test_process_evidence_worker_windows)

  add_executable(test_process_generation_windows
    ${CMAKE_CURRENT_SOURCE_DIR}/test_process_generation_windows.c
    ${CMAKE_SOURCE_DIR}/src/preprocess/process_generation.c)
  target_include_directories(test_process_generation_windows PRIVATE
    ${CMAKE_SOURCE_DIR}/include)
  target_link_libraries(test_process_generation_windows PRIVATE advapi32)
  edr_apply_test_warnings(test_process_generation_windows)
  add_test(NAME process_generation_same_handle_command_line
    COMMAND test_process_generation_windows)

  add_executable(test_kernel_file_io_windows
    ${CMAKE_CURRENT_SOURCE_DIR}/test_kernel_file_io_windows.c
    ${CMAKE_CURRENT_SOURCE_DIR}/test_file_object_binding.c
    ${CMAKE_SOURCE_DIR}/src/collector/etw_tdh_win.c
    ${CMAKE_SOURCE_DIR}/src/preprocess/process_generation.c)
  target_include_directories(test_kernel_file_io_windows PRIVATE ${CMAKE_SOURCE_DIR}/include)
  target_link_libraries(test_kernel_file_io_windows PRIVATE tdh)
  target_compile_definitions(test_kernel_file_io_windows PRIVATE EDR_FILE_OBJECT_BINDING_NO_MAIN=1)
  edr_apply_test_warnings(test_kernel_file_io_windows)
  add_test(NAME kernel_file_io_identity COMMAND test_kernel_file_io_windows)

  # Keep the real collector decoder and discard unrelated service entry points.
  # MSVC needs packaged functions and non-incremental REF even in Debug builds.
  add_executable(test_collector_file_read_windows
    ${CMAKE_CURRENT_SOURCE_DIR}/test_collector_file_read_windows.c
    ${CMAKE_CURRENT_SOURCE_DIR}/collector_file_read_stubs.c
    ${CMAKE_SOURCE_DIR}/src/collector/collector_win.c
    ${CMAKE_SOURCE_DIR}/src/collector/etw_tdh_win.c
    ${CMAKE_SOURCE_DIR}/src/preprocess/behavior_record.c
    ${CMAKE_SOURCE_DIR}/src/preprocess/behavior_from_slot.c
    ${CMAKE_SOURCE_DIR}/src/preprocess/process_generation.c
    ${CMAKE_SOURCE_DIR}/src/preprocess/windows_event_policy.c
    ${CMAKE_SOURCE_DIR}/src/core/time_util.c
    ${CMAKE_SOURCE_DIR}/src/command/sha256.c)
  target_include_directories(test_collector_file_read_windows PRIVATE
    ${CMAKE_SOURCE_DIR}/include ${CMAKE_CURRENT_SOURCE_DIR})
  target_compile_definitions(test_collector_file_read_windows PRIVATE
    EDR_COLLECTOR_FILE_IO_TESTING=1)
  if(MSVC)
    target_compile_options(test_collector_file_read_windows PRIVATE /Gy /Gw)
    target_link_options(test_collector_file_read_windows PRIVATE /OPT:REF /INCREMENTAL:NO)
  else()
    target_compile_options(test_collector_file_read_windows PRIVATE -ffunction-sections -fdata-sections)
    target_link_options(test_collector_file_read_windows PRIVATE -Wl,--gc-sections)
  endif()
  target_link_libraries(test_collector_file_read_windows PRIVATE tdh advapi32 wevtapi)
  edr_apply_test_warnings(test_collector_file_read_windows)
  add_test(NAME collector_file_read_windows COMMAND test_collector_file_read_windows)

  add_executable(test_etw_network_decode_windows
    ${CMAKE_CURRENT_SOURCE_DIR}/test_etw_network_decode_windows.c
    ${CMAKE_SOURCE_DIR}/src/collector/etw_tdh_win.c)
  target_include_directories(test_etw_network_decode_windows PRIVATE
    ${CMAKE_SOURCE_DIR}/include)
  target_compile_definitions(test_etw_network_decode_windows PRIVATE
    EDR_TDH_TESTING=1)
  edr_apply_test_warnings(test_etw_network_decode_windows)
  add_test(NAME etw_network_decode_native COMMAND test_etw_network_decode_windows)

  add_executable(test_security_event_time_windows test_security_event_time_windows.c)
  target_link_libraries(test_security_event_time_windows PRIVATE wevtapi)
  edr_apply_test_warnings(test_security_event_time_windows)
  add_test(NAME security_event_time_native COMMAND test_security_event_time_windows)
  add_executable(test_security_event_time_failures_windows test_security_event_time_failures_windows.c)
  edr_apply_test_warnings(test_security_event_time_failures_windows)
  add_test(NAME security_event_time_failures COMMAND test_security_event_time_failures_windows)
endif()

add_executable(test_process_create_coalescer
  ${CMAKE_CURRENT_SOURCE_DIR}/test_process_create_coalescer.c
  ${CMAKE_SOURCE_DIR}/src/preprocess/process_create_coalescer.c)
target_include_directories(test_process_create_coalescer PRIVATE ${CMAKE_SOURCE_DIR}/include)
edr_apply_test_warnings(test_process_create_coalescer)
if(NOT WIN32)
  target_link_libraries(test_process_create_coalescer PRIVATE Threads::Threads)
endif()
add_test(NAME process_create_coalescer_state_machine COMMAND test_process_create_coalescer)

add_executable(test_security_event_xml
  ${CMAKE_CURRENT_SOURCE_DIR}/test_security_event_xml.c)
edr_apply_test_warnings(test_security_event_xml)
add_test(NAME security_event_xml_bounded_command_line COMMAND test_security_event_xml)

add_executable(test_cmd_actor_artifact
  ${CMAKE_CURRENT_SOURCE_DIR}/test_cmd_actor_artifact.c
  ${CMAKE_SOURCE_DIR}/src/preprocess/behavior_record.c
  ${CMAKE_SOURCE_DIR}/src/preprocess/behavior_from_slot.c
  ${CMAKE_SOURCE_DIR}/src/detection/policy_v2.c)
target_include_directories(test_cmd_actor_artifact PRIVATE ${CMAKE_SOURCE_DIR}/include)
edr_apply_test_warnings(test_cmd_actor_artifact)
if(NOT MSVC)
  target_link_libraries(test_cmd_actor_artifact PRIVATE m)
endif()
add_test(NAME cmd_actor_and_script_artifact COMMAND test_cmd_actor_artifact)

add_executable(test_file_key_lifetime ${CMAKE_CURRENT_SOURCE_DIR}/test_file_key_lifetime.c)
target_include_directories(test_file_key_lifetime PRIVATE ${CMAKE_SOURCE_DIR}/include)
edr_apply_test_warnings(test_file_key_lifetime)
add_test(NAME file_key_lifetime COMMAND test_file_key_lifetime)

add_executable(test_file_object_binding ${CMAKE_CURRENT_SOURCE_DIR}/test_file_object_binding.c)
target_include_directories(test_file_object_binding PRIVATE ${CMAKE_SOURCE_DIR}/include)
edr_apply_test_warnings(test_file_object_binding)
add_test(NAME file_object_binding COMMAND test_file_object_binding)

add_executable(test_kernel_file_semantics
  ${CMAKE_CURRENT_SOURCE_DIR}/test_kernel_file_semantics.c)
target_include_directories(test_kernel_file_semantics PRIVATE ${CMAKE_SOURCE_DIR}/include)
edr_apply_test_warnings(test_kernel_file_semantics)
add_test(NAME kernel_file_semantics COMMAND test_kernel_file_semantics)

add_executable(test_windows_a44_collector_contract
  ${CMAKE_CURRENT_SOURCE_DIR}/test_windows_a44_collector_contract.c)
edr_apply_test_warnings(test_windows_a44_collector_contract)
add_test(NAME windows_a44_collector_contract COMMAND test_windows_a44_collector_contract
  WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
set_tests_properties(windows_a44_collector_contract PROPERTIES
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
edr_apply_test_warnings(test_attack_surface_inventory_policy)
add_test(NAME attack_surface_inventory_policy COMMAND test_attack_surface_inventory_policy)

add_executable(test_control_stream_lease_contract ${CMAKE_CURRENT_SOURCE_DIR}/test_control_stream_lease_contract.c)
edr_apply_test_warnings(test_control_stream_lease_contract)
add_test(NAME control_stream_lease_contract COMMAND test_control_stream_lease_contract
  WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
set_tests_properties(control_stream_lease_contract PROPERTIES
  ENVIRONMENT "EDR_SOURCE_DIR=${CMAKE_SOURCE_DIR}")

add_executable(test_mtls_upload_contract ${CMAKE_CURRENT_SOURCE_DIR}/test_mtls_upload_contract.c)
edr_apply_test_warnings(test_mtls_upload_contract)
add_test(NAME mtls_upload_transport_contract COMMAND test_mtls_upload_contract
  WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
set_tests_properties(mtls_upload_transport_contract PROPERTIES
  ENVIRONMENT "EDR_SOURCE_DIR=${CMAKE_SOURCE_DIR}")

add_executable(test_http_budget ${CMAKE_CURRENT_SOURCE_DIR}/test_http_budget.c)
target_include_directories(test_http_budget PRIVATE ${CMAKE_SOURCE_DIR}/src/transport)
edr_apply_test_warnings(test_http_budget)
add_test(NAME http_telemetry_budget COMMAND test_http_budget)

add_executable(test_yara_delivery_contract ${CMAKE_CURRENT_SOURCE_DIR}/test_yara_delivery_contract.c)
edr_apply_test_warnings(test_yara_delivery_contract)
add_test(NAME yara_delivery_contract COMMAND test_yara_delivery_contract
  WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
set_tests_properties(yara_delivery_contract PROPERTIES
  ENVIRONMENT "EDR_SOURCE_DIR=${CMAKE_SOURCE_DIR}")

add_executable(test_windows_headless_runtime_contract
  ${CMAKE_CURRENT_SOURCE_DIR}/test_windows_headless_runtime_contract.c)
edr_apply_test_warnings(test_windows_headless_runtime_contract)
add_test(NAME windows_headless_runtime_contract COMMAND test_windows_headless_runtime_contract
  WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
set_tests_properties(windows_headless_runtime_contract PROPERTIES
  ENVIRONMENT "EDR_SOURCE_DIR=${CMAKE_SOURCE_DIR}")

if(WIN32)
  add_test(NAME windows_install_compatibility_behavior
    COMMAND powershell.exe -NoProfile -ExecutionPolicy Bypass -File
      ${CMAKE_SOURCE_DIR}/tests/test_windows_install_compatibility.ps1
      -RepositoryRoot ${CMAKE_SOURCE_DIR}
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
  # Four bounded TLS clients/servers plus real RSA CSR/certreq and rollback.
  set_tests_properties(windows_install_compatibility_behavior PROPERTIES TIMEOUT 600 RUN_SERIAL TRUE)
endif()

if(WIN32)
  add_executable(test_windows_native_manifest
    ${CMAKE_CURRENT_SOURCE_DIR}/test_windows_native_manifest.c
    ${CMAKE_SOURCE_DIR}/src/platform/windows_native_manifest.c
    ${CMAKE_SOURCE_DIR}/src/command/sha256.c
    ${CMAKE_SOURCE_DIR}/third_party/cjson/cJSON.c)
  target_include_directories(test_windows_native_manifest PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/third_party/cjson)
  target_link_libraries(test_windows_native_manifest PRIVATE advapi32)
  edr_apply_test_warnings(test_windows_native_manifest)
  add_test(NAME windows_native_manifest_behavior COMMAND test_windows_native_manifest
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
  set_tests_properties(windows_native_manifest_behavior PROPERTIES TIMEOUT 60)

  # The production uninstall.exe has no test-only command-line modes. This
  # executable includes the same native implementation and owns the Windows
  # handoff, inheritance, safe-delete, and self-unlink behavior checks.
  add_executable(test_windows_native_uninstall
    ${CMAKE_CURRENT_SOURCE_DIR}/test_windows_native_uninstall.c
    ${CMAKE_CURRENT_SOURCE_DIR}/test_native_service_remove.c
    ${CMAKE_SOURCE_DIR}/src/platform/windows_spawn_lock.c
    ${CMAKE_SOURCE_DIR}/src/platform/windows_handoff.c
    ${CMAKE_SOURCE_DIR}/src/platform/windows_spawn.c
    ${CMAKE_SOURCE_DIR}/src/platform/windows_native_manifest.c
    ${CMAKE_SOURCE_DIR}/src/command/sha256.c
    ${CMAKE_SOURCE_DIR}/third_party/cjson/cJSON.c)
  target_compile_definitions(test_windows_native_uninstall PRIVATE UNICODE _UNICODE _CRT_SECURE_NO_WARNINGS)
  target_include_directories(test_windows_native_uninstall PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/third_party/cjson)
  target_link_libraries(test_windows_native_uninstall PRIVATE
    shell32 user32 advapi32 rpcrt4 crypt32 ncrypt winhttp ole32 oleaut32 taskschd onecore)
  edr_apply_test_warnings(test_windows_native_uninstall)
  add_test(NAME windows_native_uninstall_behavior COMMAND test_windows_native_uninstall
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
  set_tests_properties(windows_native_uninstall_behavior PROPERTIES TIMEOUT 120)
endif()

add_executable(test_remote_config_status_contract
  ${CMAKE_CURRENT_SOURCE_DIR}/test_remote_config_status_contract.c)
edr_apply_test_warnings(test_remote_config_status_contract)
add_test(NAME remote_config_status_contract COMMAND test_remote_config_status_contract
  WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
set_tests_properties(remote_config_status_contract PROPERTIES
  ENVIRONMENT "EDR_SOURCE_DIR=${CMAKE_SOURCE_DIR}")

add_executable(test_event_bus_mpmc_stress
  ${CMAKE_CURRENT_SOURCE_DIR}/test_event_bus_mpmc_stress.c
  ${CMAKE_SOURCE_DIR}/src/core/event_bus.c)
target_include_directories(test_event_bus_mpmc_stress PRIVATE ${CMAKE_SOURCE_DIR}/include)
if(UNIX AND NOT WIN32)
  target_link_libraries(test_event_bus_mpmc_stress PRIVATE Threads::Threads)
endif()
edr_apply_test_warnings(test_event_bus_mpmc_stress)
add_test(NAME event_bus_wait_and_mpmc COMMAND test_event_bus_mpmc_stress 100 4 128
  WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
set_tests_properties(event_bus_wait_and_mpmc PROPERTIES TIMEOUT 90)

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

add_executable(test_ave_fp ${CMAKE_CURRENT_SOURCE_DIR}/test_ave_fp.c
  ${CMAKE_SOURCE_DIR}/src/ave/ave_engine.c
  ${CMAKE_SOURCE_DIR}/src/command/sha256.c)
target_include_directories(test_ave_fp PRIVATE ${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/src/ave)
set(_edr_test_ave_sdk_sources
  ${CMAKE_SOURCE_DIR}/src/ave/ave_sdk.c
  ${CMAKE_SOURCE_DIR}/src/ave/ave_suppression.c
  ${CMAKE_SOURCE_DIR}/src/ave/ave_rules_meta.c
  ${CMAKE_SOURCE_DIR}/src/ave/ave_behavior_pipeline.c
  ${CMAKE_SOURCE_DIR}/src/ave/ave_behavior_features.c
  ${CMAKE_SOURCE_DIR}/src/ave/ave_cross_engine_parse.c
  ${CMAKE_SOURCE_DIR}/src/ave/ave_cross_engine_feed.c
  ${CMAKE_SOURCE_DIR}/src/ave/ave_lf_mpmc.c
  ${CMAKE_SOURCE_DIR}/src/ave/ave_db_update.c
  ${CMAKE_SOURCE_DIR}/src/ave/ave_engine.c
  ${CMAKE_SOURCE_DIR}/src/core/edr_log.c
  ${CMAKE_SOURCE_DIR}/src/config/config.c
  ${CMAKE_SOURCE_DIR}/src/command/sha256.c
  ${CMAKE_SOURCE_DIR}/third_party/tomlc99/toml.c
)

add_executable(test_full_installer_readiness
  ${CMAKE_CURRENT_SOURCE_DIR}/test_full_installer_readiness.c
  ${CMAKE_SOURCE_DIR}/src/command/full_installer_readiness.c
  ${CMAKE_SOURCE_DIR}/src/command/agent_update_manifest.c
)
target_include_directories(test_full_installer_readiness PRIVATE ${CMAKE_SOURCE_DIR}/include)
add_test(NAME full_installer_readiness_core COMMAND test_full_installer_readiness)

add_executable(generate_agent_update_manifest
  ${CMAKE_CURRENT_SOURCE_DIR}/generate_agent_update_manifest.c
  ${CMAKE_SOURCE_DIR}/src/command/agent_update_command.c
  ${CMAKE_SOURCE_DIR}/src/command/agent_update_event.c
  ${CMAKE_SOURCE_DIR}/src/command/sha256.c
  ${CMAKE_SOURCE_DIR}/src/command/command_contract.c
  ${CMAKE_SOURCE_DIR}/src/command/command_registry.c
  ${CMAKE_SOURCE_DIR}/src/command/agent_update_manifest.c
  ${CMAKE_SOURCE_DIR}/third_party/cjson/cJSON.c)
target_include_directories(generate_agent_update_manifest PRIVATE
  ${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/third_party/cjson)
if(NOT WIN32)
  target_compile_definitions(generate_agent_update_manifest PRIVATE EDR_OS_POSIX=1)
endif()
edr_apply_test_warnings(generate_agent_update_manifest)
add_test(NAME agent_update_manifest_fixture_check COMMAND generate_agent_update_manifest
  --check ${CMAKE_SOURCE_DIR}/tests/testdata/agent_update_v1_manifest_fixture.json)

add_executable(test_full_installer_windows_identity
  ${CMAKE_CURRENT_SOURCE_DIR}/test_full_installer_windows_identity.c
  ${CMAKE_SOURCE_DIR}/src/command/full_installer_windows_identity.c
)
target_include_directories(test_full_installer_windows_identity PRIVATE ${CMAKE_SOURCE_DIR}/include)
add_test(NAME full_installer_windows_identity_contract COMMAND test_full_installer_windows_identity)

add_executable(test_full_installer_windows_adapter
  ${CMAKE_CURRENT_SOURCE_DIR}/test_full_installer_windows_adapter.c
  ${CMAKE_SOURCE_DIR}/src/command/full_installer_readiness.c
  ${CMAKE_SOURCE_DIR}/src/command/full_installer_windows_identity.c)
target_include_directories(test_full_installer_windows_adapter PRIVATE ${CMAKE_SOURCE_DIR}/include)
edr_apply_test_warnings(test_full_installer_windows_adapter)
if(WIN32)
  add_test(NAME full_installer_windows_adapter_snapshot COMMAND test_full_installer_windows_adapter)
else()
  set_target_properties(test_full_installer_windows_adapter PROPERTIES EXCLUDE_FROM_ALL TRUE)
endif()
# 与 `edr_agent` 一致：`ave_behavior_pipeline` → `edr_behavior_alert_emit_to_batch` 的依赖链
set(_edr_test_behavior_emit_sources
  ${CMAKE_SOURCE_DIR}/src/preprocess/p0_source_only_contract.c
  ${CMAKE_SOURCE_DIR}/src/serialize/alert_governor.c
  ${CMAKE_SOURCE_DIR}/src/serialize/behavior_alert_emit.c
  ${CMAKE_SOURCE_DIR}/src/forensic/process_tree_cache.c
  ${CMAKE_SOURCE_DIR}/src/detection/policy_v2.c
  ${CMAKE_SOURCE_DIR}/src/serialize/behavior_proto.c
  ${CMAKE_SOURCE_DIR}/src/command/sha256.c
  ${CMAKE_SOURCE_DIR}/src/proto/edr/v1/event.pb.c
  ${CMAKE_SOURCE_DIR}/third_party/nanopb/pb_common.c
  ${CMAKE_SOURCE_DIR}/third_party/nanopb/pb_encode.c
  ${CMAKE_SOURCE_DIR}/third_party/nanopb/pb_decode.c
  ${CMAKE_SOURCE_DIR}/third_party/cjson/cJSON.c
  ${CMAKE_SOURCE_DIR}/src/transport/event_batch.c
  ${CMAKE_SOURCE_DIR}/src/transport/ingest_http.c
  ${CMAKE_SOURCE_DIR}/src/transport/command_result_json.c
  ${CMAKE_SOURCE_DIR}/src/transport/request_signing.c
  ${CMAKE_SOURCE_DIR}/src/transport/http_retry.c
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
target_link_libraries(edr_ave_test_common INTERFACE Threads::Threads)
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

add_executable(test_behavior_record_alert_proto
  ${CMAKE_CURRENT_SOURCE_DIR}/test_behavior_record_alert_proto.c
  ${CMAKE_SOURCE_DIR}/src/serialize/behavior_proto.c
  ${CMAKE_SOURCE_DIR}/src/serialize/behavior_proto_c.c
  ${CMAKE_SOURCE_DIR}/src/proto/edr/v1/event.pb.c
  ${CMAKE_SOURCE_DIR}/third_party/nanopb/pb_common.c
  ${CMAKE_SOURCE_DIR}/third_party/nanopb/pb_encode.c
  ${CMAKE_SOURCE_DIR}/third_party/nanopb/pb_decode.c)
target_link_libraries(test_behavior_record_alert_proto PRIVATE edr_ave_test_common)
edr_apply_test_warnings(test_behavior_record_alert_proto)
add_test(NAME behavior_record_alert_proto_contract COMMAND test_behavior_record_alert_proto)

add_executable(test_behavior_record_alert_emit
  ${CMAKE_CURRENT_SOURCE_DIR}/test_behavior_record_alert_emit.c
  ${CMAKE_SOURCE_DIR}/src/preprocess/p0_source_only_contract.c
  ${CMAKE_SOURCE_DIR}/src/serialize/alert_governor.c
  ${CMAKE_SOURCE_DIR}/src/serialize/behavior_alert_emit.c
  ${CMAKE_SOURCE_DIR}/src/serialize/behavior_proto.c
  ${CMAKE_SOURCE_DIR}/src/command/sha256.c
  ${CMAKE_SOURCE_DIR}/src/proto/edr/v1/event.pb.c
  ${CMAKE_SOURCE_DIR}/third_party/nanopb/pb_common.c
  ${CMAKE_SOURCE_DIR}/third_party/nanopb/pb_encode.c
  ${CMAKE_SOURCE_DIR}/third_party/nanopb/pb_decode.c
  ${CMAKE_SOURCE_DIR}/third_party/cjson/cJSON.c)
target_include_directories(test_behavior_record_alert_emit PRIVATE
  ${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/third_party/cjson)
target_link_libraries(test_behavior_record_alert_emit PRIVATE edr_ave_test_common)
edr_apply_test_warnings(test_behavior_record_alert_emit)
add_test(NAME behavior_record_alert_emit_contract COMMAND test_behavior_record_alert_emit)

if(EDR_PCRE2_AVAILABLE)
  # This test emits durable wire bytes carrying the authenticated published IR
  # binding.  The explicit Debug stub has no matcher and cannot prove that
  # authority; registering a guaranteed-red test would falsely imply that the
  # stub can exercise a production P0 contract.
  add_executable(test_p0_source_only_durable_contract
    ${CMAKE_CURRENT_SOURCE_DIR}/test_p0_source_only_durable_contract.c
    ${CMAKE_SOURCE_DIR}/src/preprocess/p0_source_only_contract.c
    ${CMAKE_SOURCE_DIR}/src/preprocess/p0_rule_direct_emit.c
    ${CMAKE_SOURCE_DIR}/src/preprocess/p0_deferred_snapshot.c
    ${CMAKE_SOURCE_DIR}/src/preprocess/windows_file_identity.c
    ${EDR_P0_RULE_IR_IMPLEMENTATION_SOURCE}
    ${CMAKE_SOURCE_DIR}/src/preprocess/p0_rule_match.c
    ${CMAKE_SOURCE_DIR}/src/preprocess/behavior_record.c
    ${CMAKE_SOURCE_DIR}/src/preprocess/encrypt_p0_rules.c
    ${CMAKE_SOURCE_DIR}/src/preprocess/preprocess_env.c
    ${CMAKE_SOURCE_DIR}/src/detection/policy_enforcement.c
    ${CMAKE_SOURCE_DIR}/src/detection/policy_v2.c
    ${CMAKE_SOURCE_DIR}/src/serialize/alert_governor.c
    ${CMAKE_SOURCE_DIR}/src/serialize/behavior_alert_emit.c
    ${CMAKE_SOURCE_DIR}/src/serialize/behavior_proto.c
    ${CMAKE_SOURCE_DIR}/src/command/sha256.c
    ${CMAKE_SOURCE_DIR}/src/proto/edr/v1/event.pb.c
    ${CMAKE_SOURCE_DIR}/third_party/cjson/cJSON.c
    ${CMAKE_SOURCE_DIR}/third_party/nanopb/pb_common.c
    ${CMAKE_SOURCE_DIR}/third_party/nanopb/pb_encode.c
    ${CMAKE_SOURCE_DIR}/third_party/nanopb/pb_decode.c)
  target_include_directories(test_p0_source_only_durable_contract PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/third_party/cjson)
  target_compile_definitions(test_p0_source_only_durable_contract PRIVATE EDR_P0_DIRECT_EMIT_TESTING=1)
  # Select the verified static header before SQLite's shared vcpkg include
  # directory. vcpkg's dynamic pcre2.h hardcodes the static check to 0, so
  # PCRE2_STATIC alone cannot prevent dllimport declarations from that header.
  target_link_libraries(test_p0_source_only_durable_contract PRIVATE
    ${EDR_PCRE2_TARGET} edr_ave_test_common Threads::Threads)
  edr_apply_test_warnings(test_p0_source_only_durable_contract)
  add_test(NAME p0_source_only_durable_contract COMMAND test_p0_source_only_durable_contract)
  set_tests_properties(p0_source_only_durable_contract PROPERTIES
    ENVIRONMENT "EDR_P0_IR_PATH=${CMAKE_SOURCE_DIR}/config/p0_rule_bundle_ir_v1.json")
else()
  message(STATUS
    "P0 source-only durable fixture: not registered because the non-production "
    "PCRE2 stub cannot verify published IR authority")
endif()

if(SQLite3_FOUND)
  add_executable(test_storage_queue_sqlite
    ${CMAKE_CURRENT_SOURCE_DIR}/test_storage_queue_sqlite.c
    ${CMAKE_SOURCE_DIR}/src/storage/queue_sqlite.c
    ${CMAKE_SOURCE_DIR}/src/command/sha256.c
    ${CMAKE_SOURCE_DIR}/src/core/time_util.c)
  target_include_directories(test_storage_queue_sqlite PRIVATE ${CMAKE_SOURCE_DIR}/include)
  target_compile_definitions(test_storage_queue_sqlite PRIVATE EDR_HAVE_SQLITE=1 EDR_STORAGE_QUEUE_TESTING=1)
  if(TARGET SQLite3::SQLite3)
    target_link_libraries(test_storage_queue_sqlite PRIVATE SQLite3::SQLite3 Threads::Threads)
  else()
    target_link_libraries(test_storage_queue_sqlite PRIVATE SQLite::SQLite3 Threads::Threads)
  endif()
  edr_apply_test_warnings(test_storage_queue_sqlite)
  add_test(NAME storage_queue_sqlite_contract COMMAND test_storage_queue_sqlite)
  # Relative per-process database files work on Windows too; /tmp is POSIX-only.
  set_tests_properties(storage_queue_sqlite_contract PROPERTIES
    WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}")
endif()

add_executable(test_ave_sdk ${CMAKE_CURRENT_SOURCE_DIR}/test_ave_sdk.c ${_edr_test_ave_sdk_sources} ${_edr_test_behavior_emit_sources})
target_link_libraries(test_ave_sdk PRIVATE edr_ave_test_common)
edr_apply_test_warnings(test_ave_sdk)
if(WIN32)
  target_sources(test_ave_sdk PRIVATE ${CMAKE_SOURCE_DIR}/src/attack_surface/listen_table_win.c)
  target_sources(test_ave_sdk PRIVATE ${CMAKE_SOURCE_DIR}/src/ave/ave_sign_whitelist_win.c)
else()
  target_sources(test_ave_sdk PRIVATE ${CMAKE_SOURCE_DIR}/src/ave/ave_sign_whitelist_stub.c)
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
edr_apply_test_warnings(test_detection_decision)
add_test(NAME detection_decision_combo COMMAND test_detection_decision WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

add_executable(test_detection_regression ${CMAKE_CURRENT_SOURCE_DIR}/test_detection_regression.c
  ${CMAKE_SOURCE_DIR}/src/preprocess/detection_decision.c
  ${CMAKE_SOURCE_DIR}/src/preprocess/detection_profile.c
  ${CMAKE_SOURCE_DIR}/src/detection/policy_v2.c)
target_include_directories(test_detection_regression PRIVATE ${CMAKE_SOURCE_DIR}/include)
edr_apply_test_warnings(test_detection_regression)
add_test(NAME detection_regression_scenarios COMMAND test_detection_regression WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

add_executable(test_detection_profile_trigger
  ${CMAKE_CURRENT_SOURCE_DIR}/test_detection_profile_trigger.c
  ${CMAKE_SOURCE_DIR}/src/detection/detection_profile.c
  ${CMAKE_SOURCE_DIR}/src/detection/detection_trigger.c)
target_include_directories(test_detection_profile_trigger PRIVATE ${CMAKE_SOURCE_DIR}/include)
edr_apply_test_warnings(test_detection_profile_trigger)
add_test(NAME detection_profile_and_trigger_modes COMMAND test_detection_profile_trigger
  WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

add_executable(test_webshell_semantic ${CMAKE_CURRENT_SOURCE_DIR}/test_webshell_semantic.c ${CMAKE_SOURCE_DIR}/src/webshell_detector/webshell_semantic.c)
target_include_directories(test_webshell_semantic PRIVATE ${CMAKE_SOURCE_DIR}/include)
edr_apply_test_warnings(test_webshell_semantic)
add_test(NAME webshell_semantic_rules COMMAND test_webshell_semantic WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

add_executable(test_detection_sensor_bridge ${CMAKE_CURRENT_SOURCE_DIR}/test_detection_sensor_bridge.c
  ${CMAKE_SOURCE_DIR}/src/preprocess/behavior_record.c
  ${CMAKE_SOURCE_DIR}/src/preprocess/behavior_from_slot.c
  ${CMAKE_SOURCE_DIR}/src/preprocess/detection_decision.c
  ${CMAKE_SOURCE_DIR}/src/preprocess/detection_profile.c
  ${CMAKE_SOURCE_DIR}/src/detection/policy_v2.c
  ${CMAKE_SOURCE_DIR}/src/preprocess/windows_event_policy.c)
target_include_directories(test_detection_sensor_bridge PRIVATE ${CMAKE_SOURCE_DIR}/include)
edr_apply_test_warnings(test_detection_sensor_bridge)
if(NOT MSVC)
  target_link_libraries(test_detection_sensor_bridge PRIVATE m)
endif()
add_test(NAME detection_sensor_bridge COMMAND test_detection_sensor_bridge WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

foreach(target test_detection_decision test_detection_regression test_detection_sensor_bridge)
  target_sources(${target} PRIVATE ${CMAKE_SOURCE_DIR}/third_party/cjson/cJSON.c)
  target_include_directories(${target} PRIVATE ${CMAKE_SOURCE_DIR}/third_party/cjson)
endforeach()

if(EDR_PCRE2_AVAILABLE)
  add_executable(test_p0_candidate_replay
    ${CMAKE_CURRENT_SOURCE_DIR}/test_p0_candidate_replay.c
    ${EDR_P0_RULE_IR_IMPLEMENTATION_SOURCE}
    ${CMAKE_SOURCE_DIR}/src/preprocess/behavior_record.c
    ${CMAKE_SOURCE_DIR}/src/preprocess/encrypt_p0_rules.c
    ${CMAKE_SOURCE_DIR}/src/preprocess/preprocess_env.c
    ${CMAKE_SOURCE_DIR}/src/command/sha256.c
    ${CMAKE_SOURCE_DIR}/third_party/cjson/cJSON.c)
  target_include_directories(test_p0_candidate_replay PRIVATE
    ${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/third_party/cjson)
  if(EDR_PCRE2_TARGET)
    target_link_libraries(test_p0_candidate_replay PRIVATE ${EDR_PCRE2_TARGET})
  else()
    target_include_directories(test_p0_candidate_replay PRIVATE ${EDR_PCRE2_INCLUDE_DIR})
    target_link_libraries(test_p0_candidate_replay PRIVATE ${EDR_PCRE2_LIBRARY})
  endif()
  edr_apply_test_warnings(test_p0_candidate_replay)

  add_executable(test_p0_rule_ir_record_golden
    ${CMAKE_SOURCE_DIR}/src/preprocess/p0_rule_ir_record_golden_test.c
    ${EDR_P0_RULE_IR_IMPLEMENTATION_SOURCE}
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
  edr_apply_test_warnings(test_p0_rule_ir_record_golden)
  add_test(NAME p0_rule_ir_record_golden COMMAND test_p0_rule_ir_record_golden WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
  set_tests_properties(p0_rule_ir_record_golden PROPERTIES
    ENVIRONMENT "EDR_P0_IR_PATH=${CMAKE_SOURCE_DIR}/config/p0_rule_bundle_ir_v1.json")

  if(NOT WIN32)
    add_executable(test_p0_rule_ir_snapshot
      ${CMAKE_CURRENT_SOURCE_DIR}/test_p0_rule_ir_snapshot.c
      ${EDR_P0_RULE_IR_IMPLEMENTATION_SOURCE}
      ${CMAKE_SOURCE_DIR}/src/preprocess/encrypt_p0_rules.c
      ${CMAKE_SOURCE_DIR}/src/preprocess/preprocess_env.c
      ${CMAKE_SOURCE_DIR}/src/command/sha256.c
      ${CMAKE_SOURCE_DIR}/third_party/cjson/cJSON.c)
    target_include_directories(test_p0_rule_ir_snapshot PRIVATE ${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/third_party/cjson)
    target_compile_definitions(test_p0_rule_ir_snapshot PRIVATE EDR_P0_RULE_IR_TESTING=1)
    if(EDR_PCRE2_TARGET)
      target_link_libraries(test_p0_rule_ir_snapshot PRIVATE ${EDR_PCRE2_TARGET} Threads::Threads)
    else()
      target_include_directories(test_p0_rule_ir_snapshot PRIVATE ${EDR_PCRE2_INCLUDE_DIR})
      target_link_libraries(test_p0_rule_ir_snapshot PRIVATE ${EDR_PCRE2_LIBRARY} Threads::Threads)
    endif()
    edr_apply_test_warnings(test_p0_rule_ir_snapshot)
    add_test(NAME p0_rule_ir_snapshot COMMAND test_p0_rule_ir_snapshot WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
    set_tests_properties(p0_rule_ir_snapshot PROPERTIES
      ENVIRONMENT "EDR_P0_IR_PATH=${CMAKE_SOURCE_DIR}/config/p0_rule_bundle_ir_v1.json")

    if(EDR_WITH_P0_RULES_OPENSSL AND OpenSSL_FOUND)
      add_executable(test_p0_rule_ir_envelope_boundary
        ${CMAKE_CURRENT_SOURCE_DIR}/test_p0_rule_ir_envelope_boundary.c
        ${EDR_P0_RULE_IR_IMPLEMENTATION_SOURCE}
        ${CMAKE_SOURCE_DIR}/src/preprocess/encrypt_p0_rules.c
        ${CMAKE_SOURCE_DIR}/src/preprocess/preprocess_env.c
        ${CMAKE_SOURCE_DIR}/src/command/sha256.c
        ${CMAKE_SOURCE_DIR}/third_party/cjson/cJSON.c)
      target_include_directories(test_p0_rule_ir_envelope_boundary PRIVATE
        ${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/third_party/cjson)
      target_compile_definitions(test_p0_rule_ir_envelope_boundary PRIVATE
        EDR_P0_ENCRYPT_TESTING=1 EDR_HAVE_OPENSSL_FL=1)
      if(EDR_PCRE2_TARGET)
        target_link_libraries(test_p0_rule_ir_envelope_boundary PRIVATE
          ${EDR_PCRE2_TARGET} OpenSSL::Crypto)
      else()
        target_include_directories(test_p0_rule_ir_envelope_boundary PRIVATE ${EDR_PCRE2_INCLUDE_DIR})
        target_link_libraries(test_p0_rule_ir_envelope_boundary PRIVATE
          ${EDR_PCRE2_LIBRARY} OpenSSL::Crypto)
      endif()
      edr_apply_test_warnings(test_p0_rule_ir_envelope_boundary)
      add_test(NAME p0_rule_ir_envelope_boundary COMMAND test_p0_rule_ir_envelope_boundary
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
    endif()
  endif()

  add_executable(test_p0_validation_matrix
    ${CMAKE_SOURCE_DIR}/src/preprocess/p0_validation_matrix_test.c
    ${EDR_P0_RULE_IR_IMPLEMENTATION_SOURCE}
    ${CMAKE_SOURCE_DIR}/src/preprocess/behavior_record.c
    ${CMAKE_SOURCE_DIR}/src/preprocess/adaptive_collection.c
    ${CMAKE_SOURCE_DIR}/src/preprocess/sensor_interest.c
    ${CMAKE_SOURCE_DIR}/src/preprocess/encrypt_p0_rules.c
    ${CMAKE_SOURCE_DIR}/src/preprocess/preprocess_env.c
    ${CMAKE_SOURCE_DIR}/src/command/sha256.c
    ${CMAKE_SOURCE_DIR}/third_party/cjson/cJSON.c)
  target_include_directories(test_p0_validation_matrix PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/third_party/cjson)
  target_compile_definitions(test_p0_validation_matrix PRIVATE EDR_SENSOR_INTEREST_TESTING=1)
  if(EDR_PCRE2_TARGET)
    target_link_libraries(test_p0_validation_matrix PRIVATE ${EDR_PCRE2_TARGET})
  else()
    target_include_directories(test_p0_validation_matrix PRIVATE ${EDR_PCRE2_INCLUDE_DIR})
    target_link_libraries(test_p0_validation_matrix PRIVATE ${EDR_PCRE2_LIBRARY})
  endif()
  edr_apply_test_warnings(test_p0_validation_matrix)
  add_test(NAME p0_validation_matrix COMMAND test_p0_validation_matrix WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
  set_tests_properties(p0_validation_matrix PROPERTIES
    ENVIRONMENT "EDR_P0_IR_PATH=${CMAKE_SOURCE_DIR}/config/p0_rule_bundle_ir_v1.json;EDR_SENSOR_INTEREST_PATH=${CMAKE_SOURCE_DIR}/config/sensor_interest_manifest.json")
endif()

add_executable(test_windows_event_policy ${CMAKE_CURRENT_SOURCE_DIR}/test_windows_event_policy.c
  ${CMAKE_SOURCE_DIR}/src/preprocess/behavior_record.c
  ${CMAKE_SOURCE_DIR}/src/preprocess/windows_event_policy.c)
target_include_directories(test_windows_event_policy PRIVATE ${CMAKE_SOURCE_DIR}/include)
edr_apply_test_warnings(test_windows_event_policy)
add_test(NAME windows_event_policy COMMAND test_windows_event_policy WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

add_executable(test_pe_verify ${CMAKE_CURRENT_SOURCE_DIR}/test_pe_verify.c
  ${CMAKE_SOURCE_DIR}/src/command/pe_verify.c)
target_include_directories(test_pe_verify PRIVATE ${CMAKE_SOURCE_DIR}/include)
edr_apply_test_warnings(test_pe_verify)
add_test(NAME pe_verify COMMAND test_pe_verify WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

add_executable(test_p0_direct_emit_suppression ${CMAKE_CURRENT_SOURCE_DIR}/test_p0_direct_emit_suppression.c
  ${CMAKE_SOURCE_DIR}/src/preprocess/p0_source_only_contract.c
  ${CMAKE_SOURCE_DIR}/src/preprocess/p0_rule_direct_emit.c
  ${CMAKE_SOURCE_DIR}/src/preprocess/p0_deferred_snapshot.c
  ${CMAKE_SOURCE_DIR}/src/preprocess/windows_file_identity.c
  ${CMAKE_SOURCE_DIR}/src/preprocess/p0_rule_match.c
  ${CMAKE_SOURCE_DIR}/src/preprocess/behavior_record.c
  ${CMAKE_SOURCE_DIR}/src/detection/policy_enforcement.c
  ${CMAKE_SOURCE_DIR}/src/detection/policy_v2.c
  ${CMAKE_SOURCE_DIR}/src/command/sha256.c
  ${CMAKE_SOURCE_DIR}/third_party/cjson/cJSON.c)
target_include_directories(test_p0_direct_emit_suppression PRIVATE
  ${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/third_party/cjson)
target_compile_definitions(test_p0_direct_emit_suppression PRIVATE EDR_P0_DIRECT_EMIT_TESTING=1)
target_link_libraries(test_p0_direct_emit_suppression PRIVATE Threads::Threads)
edr_apply_test_warnings(test_p0_direct_emit_suppression)
add_test(NAME p0_direct_emit_suppression COMMAND test_p0_direct_emit_suppression WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
set_tests_properties(p0_direct_emit_suppression PROPERTIES TIMEOUT 120)

add_executable(test_p0_deferred_snapshot test_p0_deferred_snapshot.c
  ${CMAKE_SOURCE_DIR}/src/preprocess/p0_deferred_snapshot.c
  ${CMAKE_SOURCE_DIR}/third_party/cjson/cJSON.c)
target_include_directories(test_p0_deferred_snapshot PRIVATE
  ${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/third_party/cjson)
edr_apply_test_warnings(test_p0_deferred_snapshot)
add_test(NAME p0_deferred_snapshot COMMAND test_p0_deferred_snapshot)

add_executable(test_preprocess_p0_dispatch_contract
  ${CMAKE_CURRENT_SOURCE_DIR}/test_preprocess_p0_dispatch_contract.c)
edr_apply_test_warnings(test_preprocess_p0_dispatch_contract)
add_test(NAME preprocess_p0_dispatch_contract COMMAND test_preprocess_p0_dispatch_contract
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})
set_tests_properties(preprocess_p0_dispatch_contract PROPERTIES
  ENVIRONMENT "EDR_SOURCE_DIR=${CMAKE_SOURCE_DIR}")

add_executable(test_collection_admission ${CMAKE_CURRENT_SOURCE_DIR}/test_collection_admission.c
  ${CMAKE_SOURCE_DIR}/src/preprocess/adaptive_collection.c
  ${CMAKE_SOURCE_DIR}/src/preprocess/sensor_interest.c
  ${CMAKE_SOURCE_DIR}/src/preprocess/p0_rule_ir_stub.c
  ${CMAKE_SOURCE_DIR}/src/command/sha256.c
  ${CMAKE_SOURCE_DIR}/third_party/cjson/cJSON.c)
target_include_directories(test_collection_admission PRIVATE
  ${CMAKE_SOURCE_DIR}/include
  ${CMAKE_SOURCE_DIR}/third_party/cjson)
edr_apply_test_warnings(test_collection_admission)
add_test(NAME collection_admission COMMAND test_collection_admission WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

add_executable(test_p0_rule_ir_stub_health
  ${CMAKE_CURRENT_SOURCE_DIR}/test_p0_rule_ir_stub_health.c
  ${CMAKE_SOURCE_DIR}/src/preprocess/p0_rule_ir_stub.c)
target_include_directories(test_p0_rule_ir_stub_health PRIVATE ${CMAKE_SOURCE_DIR}/include)
edr_apply_test_warnings(test_p0_rule_ir_stub_health)
add_test(NAME p0_rule_ir_nonproduction_stub_health COMMAND test_p0_rule_ir_stub_health)

add_executable(test_preprocess_dedup ${CMAKE_CURRENT_SOURCE_DIR}/test_preprocess_dedup.c
  ${CMAKE_SOURCE_DIR}/src/preprocess/dedup.c
  ${CMAKE_SOURCE_DIR}/src/preprocess/behavior_record.c
  ${CMAKE_SOURCE_DIR}/src/preprocess/windows_event_policy.c)
target_include_directories(test_preprocess_dedup PRIVATE ${CMAKE_SOURCE_DIR}/include)
edr_apply_test_warnings(test_preprocess_dedup)
add_test(NAME preprocess_dedup COMMAND test_preprocess_dedup WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

add_executable(test_process_tree_cache ${CMAKE_CURRENT_SOURCE_DIR}/test_process_tree_cache.c
  ${CMAKE_SOURCE_DIR}/src/forensic/process_tree_cache.c)
target_include_directories(test_process_tree_cache PRIVATE ${CMAKE_SOURCE_DIR}/include)
if(UNIX)
  target_link_libraries(test_process_tree_cache PRIVATE Threads::Threads)
endif()
edr_apply_test_warnings(test_process_tree_cache)
add_test(NAME process_tree_cache COMMAND test_process_tree_cache WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

add_executable(test_local_evidence_cache_candidate ${CMAKE_CURRENT_SOURCE_DIR}/test_local_evidence_cache_candidate.c
  ${CMAKE_SOURCE_DIR}/src/preprocess/behavior_from_slot.c
  ${CMAKE_SOURCE_DIR}/src/detection/policy_v2.c
  ${CMAKE_SOURCE_DIR}/src/storage/local_evidence_cache.c
  ${CMAKE_SOURCE_DIR}/src/forensic/process_tree_cache.c
  ${CMAKE_SOURCE_DIR}/src/preprocess/behavior_record.c
  ${CMAKE_SOURCE_DIR}/src/preprocess/p0_rule_match.c
  ${CMAKE_SOURCE_DIR}/src/preprocess/windows_event_policy.c
  ${CMAKE_SOURCE_DIR}/src/preprocess/p0_rule_ir_stub.c
  ${CMAKE_SOURCE_DIR}/src/command/sha256.c
  ${CMAKE_SOURCE_DIR}/third_party/cjson/cJSON.c)
target_include_directories(test_local_evidence_cache_candidate PRIVATE
  ${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/third_party/cjson)
if(SQLite3_FOUND)
  if(TARGET SQLite3::SQLite3)
    target_link_libraries(test_local_evidence_cache_candidate PRIVATE SQLite3::SQLite3)
  else()
    target_link_libraries(test_local_evidence_cache_candidate PRIVATE SQLite::SQLite3)
  endif()
  target_compile_definitions(test_local_evidence_cache_candidate PRIVATE
    EDR_HAVE_SQLITE=1 EDR_LOCAL_EVIDENCE_CACHE_TESTING=1)
endif()
if(UNIX)
  target_link_libraries(test_local_evidence_cache_candidate PRIVATE Threads::Threads)
endif()
if(NOT MSVC)
  target_link_libraries(test_local_evidence_cache_candidate PRIVATE m)
endif()
edr_apply_test_warnings(test_local_evidence_cache_candidate)
add_test(NAME local_evidence_cache_candidate COMMAND test_local_evidence_cache_candidate WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

add_executable(test_deep_collector_manifest ${CMAKE_CURRENT_SOURCE_DIR}/test_deep_collector_manifest.c
  ${CMAKE_SOURCE_DIR}/src/command/sha256.c)
target_include_directories(test_deep_collector_manifest PRIVATE ${CMAKE_SOURCE_DIR}/include)
if(WIN32)
  target_sources(test_deep_collector_manifest PRIVATE
    ${CMAKE_SOURCE_DIR}/src/platform/windows_spawn_lock.c)
endif()
edr_apply_test_warnings(test_deep_collector_manifest)
add_test(NAME deep_collector_manifest COMMAND test_deep_collector_manifest WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

add_executable(test_ave_pipeline ${CMAKE_CURRENT_SOURCE_DIR}/test_ave_pipeline.c
  ${_edr_test_ave_sdk_sources} ${_edr_test_behavior_emit_sources})
target_link_libraries(test_ave_pipeline PRIVATE edr_ave_test_common)
if(WIN32)
  target_sources(test_ave_pipeline PRIVATE ${CMAKE_SOURCE_DIR}/src/attack_surface/listen_table_win.c)
  target_sources(test_ave_pipeline PRIVATE ${CMAKE_SOURCE_DIR}/src/ave/ave_sign_whitelist_win.c)
else()
  target_sources(test_ave_pipeline PRIVATE ${CMAKE_SOURCE_DIR}/src/ave/ave_sign_whitelist_stub.c)
endif()

if(WIN32)
  foreach(_edr_ave_windows_test test_ave_sdk test_ave_pipeline)
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

find_program(EDR_PYTHON3 python3)
if(EDR_PYTHON3)
  add_test(
    NAME ave_behavior_m3b_python_parity
    COMMAND ${EDR_PYTHON3} "${CMAKE_SOURCE_DIR}/scripts/behavior_encode_m3b.py"
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}")
endif()

add_executable(test_config_fp ${CMAKE_CURRENT_SOURCE_DIR}/test_config_fp.c ${CMAKE_SOURCE_DIR}/src/config/config.c ${CMAKE_SOURCE_DIR}/third_party/tomlc99/toml.c)
target_include_directories(test_config_fp PRIVATE ${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/third_party/tomlc99)

add_executable(test_pmfe_detail ${CMAKE_CURRENT_SOURCE_DIR}/test_pmfe_detail.c)
edr_apply_test_warnings(test_pmfe_detail)
add_test(NAME pmfe_scan_detail_format COMMAND test_pmfe_detail WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

add_executable(test_pmfe_pe_arch
  ${CMAKE_CURRENT_SOURCE_DIR}/test_pmfe_pe_arch.c
  ${CMAKE_SOURCE_DIR}/src/pmfe/pmfe_pe_arch.c)
target_include_directories(test_pmfe_pe_arch PRIVATE ${CMAKE_SOURCE_DIR}/src/pmfe)
edr_apply_test_warnings(test_pmfe_pe_arch)
add_test(NAME pmfe_pe_architectures COMMAND test_pmfe_pe_arch WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  add_executable(test_pmfe_linux_maps ${CMAKE_CURRENT_SOURCE_DIR}/test_pmfe_linux_maps.c ${CMAKE_SOURCE_DIR}/src/pmfe/pmfe_linux_scan_util.c)
  target_include_directories(test_pmfe_linux_maps PRIVATE ${CMAKE_SOURCE_DIR}/src/pmfe)
  add_test(NAME pmfe_linux_maps_parse COMMAND test_pmfe_linux_maps WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
endif()

foreach(_edr_warning_target IN ITEMS
    test_ave_fp
    test_ave_sdk
    test_ave_suppression
    test_ave_pipeline
    test_config_fp)
  edr_apply_test_warnings(${_edr_warning_target})
endforeach()

add_test(NAME ave_file_fingerprint COMMAND test_ave_fp WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
add_test(NAME ave_sdk_smoke COMMAND test_ave_sdk WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
set_tests_properties(ave_sdk_smoke PROPERTIES TIMEOUT 30)
add_test(NAME ave_suppression_sqlite COMMAND test_ave_suppression WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
add_test(NAME ave_scan_pipeline COMMAND test_ave_pipeline WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
add_test(NAME config_fingerprint COMMAND test_config_fp WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

add_executable(test_resource_metrics
  ${CMAKE_CURRENT_SOURCE_DIR}/test_resource_metrics.c
  ${CMAKE_SOURCE_DIR}/src/resource/resource.c)
target_include_directories(test_resource_metrics PRIVATE ${CMAKE_SOURCE_DIR}/include)
if(WIN32)
  target_link_libraries(test_resource_metrics PRIVATE psapi)
endif()
add_test(NAME resource_metrics_hot_reconfigure COMMAND test_resource_metrics
  WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
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
edr_apply_test_warnings(test_shellcode)
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
edr_apply_test_warnings(test_shellcode_yara_rules)
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
edr_apply_test_warnings(test_yara_rule_catalog_compile)
add_test(NAME yara_rule_catalog_compile COMMAND test_yara_rule_catalog_compile WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

# P0 #2/#3 流级去重 + TLS 记录短路（纯逻辑，跨平台）
add_executable(test_shellcode_flow_dedup
  ${CMAKE_CURRENT_SOURCE_DIR}/test_shellcode_flow_dedup.c
  ${CMAKE_SOURCE_DIR}/src/shellcode_detector/flow_dedup.c
  ${CMAKE_SOURCE_DIR}/src/shellcode_detector/proto_parse.c)
target_include_directories(test_shellcode_flow_dedup PRIVATE ${CMAKE_SOURCE_DIR}/include)
edr_apply_test_warnings(test_shellcode_flow_dedup)
add_test(NAME shellcode_flow_dedup COMMAND test_shellcode_flow_dedup WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
set_tests_properties(shellcode_flow_dedup PROPERTIES LABELS "shellcode")

add_executable(test_shellcode_tcp_reassembly
  ${CMAKE_CURRENT_SOURCE_DIR}/test_shellcode_tcp_reassembly.c
  ${CMAKE_SOURCE_DIR}/src/shellcode_detector/tcp_reassembly.c)
target_include_directories(test_shellcode_tcp_reassembly PRIVATE ${CMAKE_SOURCE_DIR}/include)
edr_apply_test_warnings(test_shellcode_tcp_reassembly)
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
edr_apply_test_warnings(test_shellcode_server_benchmark)
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
edr_apply_test_warnings(test_shellcode_runtime_contract)
add_test(NAME shellcode_runtime_truth_contract COMMAND test_shellcode_runtime_contract
  WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
set_tests_properties(shellcode_runtime_truth_contract PROPERTIES
  ENVIRONMENT "EDR_SOURCE_DIR=${CMAKE_SOURCE_DIR}"
  LABELS "shellcode")

# 端侧网络扇出/扫描检测器核心逻辑
add_executable(test_net_fanout
  ${CMAKE_CURRENT_SOURCE_DIR}/test_net_fanout.c
  ${CMAKE_SOURCE_DIR}/src/detection/net_fanout_core.c
  ${CMAKE_SOURCE_DIR}/src/detection/net_fanout_detector.c)
target_include_directories(test_net_fanout PRIVATE ${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/src/detection)
edr_apply_test_warnings(test_net_fanout)
add_test(NAME net_fanout COMMAND test_net_fanout WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

# §B1 子系统心跳逻辑
add_executable(test_self_protect_heartbeat
  ${CMAKE_CURRENT_SOURCE_DIR}/test_self_protect_heartbeat.c
  ${CMAKE_SOURCE_DIR}/src/self_protect/heartbeat.c
  ${CMAKE_SOURCE_DIR}/src/core/time_util.c)
target_include_directories(test_self_protect_heartbeat PRIVATE ${CMAKE_SOURCE_DIR}/include)
edr_apply_test_warnings(test_self_protect_heartbeat)
add_test(NAME self_protect_heartbeat COMMAND test_self_protect_heartbeat WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

# Release blocker: ordinary behavior-alert output must stay within the endpoint/rule SLO.
add_executable(test_alert_governor_cardinality
  ${CMAKE_CURRENT_SOURCE_DIR}/test_alert_governor_cardinality.c
  ${CMAKE_SOURCE_DIR}/src/preprocess/p0_source_only_contract.c
  ${CMAKE_SOURCE_DIR}/src/serialize/alert_governor.c
  ${CMAKE_SOURCE_DIR}/src/serialize/behavior_alert_emit.c
  ${CMAKE_SOURCE_DIR}/src/serialize/behavior_proto.c
  ${CMAKE_SOURCE_DIR}/src/command/sha256.c
  ${CMAKE_SOURCE_DIR}/src/forensic/process_tree_cache.c
  ${CMAKE_SOURCE_DIR}/src/detection/policy_v2.c
  ${CMAKE_SOURCE_DIR}/src/proto/edr/v1/event.pb.c
  ${CMAKE_SOURCE_DIR}/third_party/nanopb/pb_common.c
  ${CMAKE_SOURCE_DIR}/third_party/nanopb/pb_encode.c
  ${CMAKE_SOURCE_DIR}/third_party/cjson/cJSON.c)
target_include_directories(test_alert_governor_cardinality PRIVATE
  ${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/third_party/cjson)
target_compile_definitions(test_alert_governor_cardinality PRIVATE EDR_HAVE_NANOPB=1)
target_link_libraries(test_alert_governor_cardinality PRIVATE edr_ave_test_common)
if(UNIX AND NOT WIN32)
  target_link_libraries(test_alert_governor_cardinality PRIVATE Threads::Threads)
endif()
edr_apply_test_warnings(test_alert_governor_cardinality)
add_test(NAME alert_cardinality_release_gate COMMAND test_alert_governor_cardinality WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
set_tests_properties(alert_cardinality_release_gate PROPERTIES LABELS "release-gate")

add_executable(test_policy_v2
  ${CMAKE_CURRENT_SOURCE_DIR}/test_policy_v2.c
  ${CMAKE_SOURCE_DIR}/src/detection/policy_v2.c)
target_include_directories(test_policy_v2 PRIVATE ${CMAKE_SOURCE_DIR}/include)
edr_apply_test_warnings(test_policy_v2)
add_test(NAME endpoint_policy_v2_modes COMMAND test_policy_v2 WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

add_executable(test_forensic_result_contract
  ${CMAKE_CURRENT_SOURCE_DIR}/test_forensic_result_contract.c
  ${CMAKE_SOURCE_DIR}/src/command/forensic_result_contract.c)
target_include_directories(test_forensic_result_contract PRIVATE ${CMAKE_SOURCE_DIR}/include)
edr_apply_test_warnings(test_forensic_result_contract)
add_test(NAME forensic_result_contract COMMAND test_forensic_result_contract WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

add_executable(test_event_batch_max_age
  ${CMAKE_CURRENT_SOURCE_DIR}/test_event_batch_max_age.c
  ${CMAKE_SOURCE_DIR}/src/transport/event_batch.c)
target_include_directories(test_event_batch_max_age PRIVATE ${CMAKE_SOURCE_DIR}/include)
if(NOT WIN32)
  target_link_libraries(test_event_batch_max_age PRIVATE Threads::Threads)
endif()
if(EXISTS "${CMAKE_SOURCE_DIR}/third_party/lz4/lz4.c")
  target_sources(test_event_batch_max_age PRIVATE ${CMAKE_SOURCE_DIR}/third_party/lz4/lz4.c)
  target_include_directories(test_event_batch_max_age PRIVATE ${CMAKE_SOURCE_DIR}/third_party/lz4)
  target_compile_definitions(test_event_batch_max_age PRIVATE EDR_HAVE_LZ4=1)
endif()
edr_apply_test_warnings(test_event_batch_max_age)
add_test(NAME event_batch_max_age COMMAND test_event_batch_max_age WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
set_tests_properties(event_batch_max_age PROPERTIES TIMEOUT 30)

add_test(NAME edr_agent_smoke COMMAND bash ${CMAKE_SOURCE_DIR}/scripts/agent_smoke.sh $<TARGET_FILE:edr_agent>)
set_tests_properties(edr_agent_smoke PROPERTIES TIMEOUT 30)

include(${CMAKE_SOURCE_DIR}/cmake/AgentRuntimeGate.cmake)
if(WIN32)
  include(${CMAKE_SOURCE_DIR}/cmake/WindowsReleaseGate.cmake)
endif()

add_executable(test_builtin_forensic_bundle ${CMAKE_CURRENT_SOURCE_DIR}/test_builtin_forensic_bundle.c)
edr_apply_test_warnings(test_builtin_forensic_bundle)
add_test(NAME builtin_forensic_bundle COMMAND test_builtin_forensic_bundle)
if(UNIX AND TARGET forensic_collector)
  add_test(NAME builtin_forensic_bundle_regressions
    COMMAND ${CMAKE_COMMAND} -E env "BIN=$<TARGET_FILE:forensic_collector>"
      ${Python3_EXECUTABLE} -B ${CMAKE_SOURCE_DIR}/tools/forensic_collector/test_bundle.py)
endif()
