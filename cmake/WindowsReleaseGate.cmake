# One declaration binds each required CTest to its build dependency. Both
# Windows workflows build this target and select this label; neither keeps a
# second executable/test allowlist that can drift when a gate is added.
add_custom_target(windows_release_gate_tests)

function(edr_windows_release_gate test_name executable_target)
  if(NOT TEST "${test_name}")
    message(FATAL_ERROR "Windows release gate test is not registered: ${test_name}")
  endif()
  if(NOT "${executable_target}" STREQUAL "")
    if(NOT TARGET "${executable_target}")
      message(FATAL_ERROR "Windows release gate executable target is missing: ${executable_target}")
    endif()
    add_dependencies(windows_release_gate_tests "${executable_target}")
  endif()
  set_property(TEST "${test_name}" APPEND PROPERTY LABELS windows-release-gate)
endfunction()

edr_windows_release_gate(agent_update_command_contract test_agent_update_contract)
edr_windows_release_gate(agent_update_packaging_contract test_agent_update_assets)
edr_windows_release_gate(windows_headless_runtime_contract test_windows_headless_runtime_contract)
edr_windows_release_gate(command_registry_and_payload_contract test_command_contract)
edr_windows_release_gate(command_process_identity_and_receipts test_command_process)
edr_windows_release_gate(pmfe_pe_architectures test_pmfe_pe_arch)
edr_windows_release_gate(windows_native_manifest_behavior test_windows_native_manifest)
edr_windows_release_gate(windows_native_uninstall_behavior test_windows_native_uninstall)
edr_windows_release_gate(process_generation_same_handle_command_line test_process_generation_windows)
edr_windows_release_gate(kernel_file_io_identity test_kernel_file_io_windows)
edr_windows_release_gate(http_telemetry_budget test_http_budget)
edr_windows_release_gate(response_file_security_behavior test_response_file_security)
edr_windows_release_gate(response_forensic_path_contract test_response_forensic_paths)
# This test invokes the checked-in PowerShell script, not a generated EXE.
edr_windows_release_gate(windows_isolation_mock_behavior "")
edr_windows_release_gate(windows_install_compatibility_behavior "")
