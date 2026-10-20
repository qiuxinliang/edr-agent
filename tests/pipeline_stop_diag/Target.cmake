# Include from tests/CMakeLists.txt after edr_runtime_test_common is defined.
# This target is opt-in: it is neither an ALL target nor a registered CTest.
if(WIN32 AND TARGET edr_runtime_test_common AND EDR_P0_TEST_CONFIG_DIR)
  get_target_property(_pd_agent_dir edr_agent SOURCE_DIR)
  get_target_property(_pd_agent_sources edr_agent SOURCES)
  get_target_property(_pd_common_sources edr_runtime_test_common SOURCES)
  set(_pd_expected)
  foreach(_pd_source IN LISTS _pd_agent_sources)
    if(_pd_source MATCHES "\\$<")
      message(FATAL_ERROR "Pipeline diagnostic source inventory cannot contain a generator expression")
    endif()
    if(NOT IS_ABSOLUTE "${_pd_source}")
      set(_pd_source "${_pd_agent_dir}/${_pd_source}")
    endif()
    get_filename_component(_pd_source "${_pd_source}" ABSOLUTE)
    if(NOT _pd_source STREQUAL "${_pd_agent_dir}/src/main.c" AND
       NOT _pd_source STREQUAL "${_pd_agent_dir}/src/core/agent.c" AND
       NOT _pd_source STREQUAL "${_pd_agent_dir}/src/pmfe/pmfe_engine.c" AND
       NOT _pd_source MATCHES "\\.rc$")
      list(APPEND _pd_expected "${_pd_source}")
    endif()
  endforeach()
  set(_pd_actual)
  set(_pd_pipeline_count 0)
  set(_pd_real_ir_count 0)
  set(_pd_p0_count 0)
  set(_pd_policy_count 0)
  set(_pd_replacement_basename_count 0)
  foreach(_pd_source IN LISTS _pd_common_sources)
    if(_pd_source MATCHES "\\$<" OR NOT IS_ABSOLUTE "${_pd_source}")
      message(FATAL_ERROR "Pipeline diagnostic requires the current absolute runtime source inventory")
    endif()
    get_filename_component(_pd_source "${_pd_source}" ABSOLUTE)
    list(APPEND _pd_actual "${_pd_source}")
    if(_pd_source MATCHES "/(preprocess_pipeline|p0_rule_direct_emit|policy_enforcement)\\.c$")
      math(EXPR _pd_replacement_basename_count "${_pd_replacement_basename_count}+1")
    endif()
    if(_pd_source STREQUAL "${_pd_agent_dir}/src/preprocess/preprocess_pipeline.c")
      math(EXPR _pd_pipeline_count "${_pd_pipeline_count}+1")
    endif()
    if(_pd_source STREQUAL "${_pd_agent_dir}/src/preprocess/p0_rule_direct_emit.c")
      math(EXPR _pd_p0_count "${_pd_p0_count}+1")
    endif()
    if(_pd_source STREQUAL "${_pd_agent_dir}/src/detection/policy_enforcement.c")
      math(EXPR _pd_policy_count "${_pd_policy_count}+1")
    endif()
    if(_pd_source STREQUAL "${_pd_agent_dir}/src/preprocess/p0_rule_ir.c")
      math(EXPR _pd_real_ir_count "${_pd_real_ir_count}+1")
    endif()
  endforeach()
  list(SORT _pd_expected)
  list(SORT _pd_actual)
  if(NOT "${_pd_expected}" STREQUAL "${_pd_actual}" OR
     NOT _pd_pipeline_count EQUAL 1 OR NOT _pd_real_ir_count EQUAL 1 OR
     NOT _pd_p0_count EQUAL 1 OR NOT _pd_policy_count EQUAL 1 OR
     NOT _pd_replacement_basename_count EQUAL 3)
    message(FATAL_ERROR "Pipeline diagnostic runtime/real-IR source closure differs from the current agent owner")
  endif()
  if(NOT SQLite3_FOUND OR NOT OpenSSL_FOUND)
    message(FATAL_ERROR "Pipeline diagnostic requires real SQLite and the existing OpenSSL/P0 closure")
  endif()

  if(NOT EDR_P0_TEST_CONFIG_DIR OR
     NOT EXISTS "${EDR_P0_TEST_CONFIG_DIR}/p0_rule_bundle_ir_v1.json.enc")
    message(FATAL_ERROR "Pipeline diagnostic requires the existing verified canonical P0 fixture envelope")
  endif()
  set(_pd_home "${CMAKE_CURRENT_SOURCE_DIR}/pipeline_stop_diag")
  set(_pd_generated "${CMAKE_CURRENT_BINARY_DIR}/pipeline-stop-generated")
  file(MAKE_DIRECTORY "${_pd_generated}")
  execute_process(COMMAND "${Python3_EXECUTABLE}" -B
    "${_pd_home}/generate_diagnostic_source.py" "${_pd_agent_dir}" "${_pd_generated}"
    RESULT_VARIABLE _pd_generate_rc OUTPUT_VARIABLE _pd_generate_out
    ERROR_VARIABLE _pd_generate_error)
  if(NOT _pd_generate_rc EQUAL 0)
    message(FATAL_ERROR "Pipeline diagnostic source transform failed: ${_pd_generate_error}")
  endif()
  configure_file("${_pd_home}/fixture-main.inc" "${_pd_generated}/fixture-main.inc" COPYONLY)
  configure_file("${_pd_home}/windows_parent.inc" "${_pd_generated}/windows_parent.inc" COPYONLY)
  set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
    "${_pd_agent_dir}/src/preprocess/preprocess_pipeline.c"
    "${_pd_agent_dir}/src/preprocess/p0_rule_direct_emit.c"
    "${_pd_home}/generate_diagnostic_source.py"
    "${_pd_home}/fixture-main.inc" "${_pd_home}/windows_parent.inc")
  # Exactly three current common objects are replaced: pipeline/P0 get numeric
  # probes; policy is the original source, rebuilt for its existing deny hook.
  # Do not link the OBJECT target itself, which would reinject those originals.
  add_executable(test_preprocess_stop_boundary EXCLUDE_FROM_ALL
    "$<FILTER:$<TARGET_OBJECTS:edr_runtime_test_common>,EXCLUDE,(preprocess_pipeline|p0_rule_direct_emit|policy_enforcement)\\.c\\.(obj|o)$>"
    "${_pd_agent_dir}/src/core/agent.c"
    "${_pd_agent_dir}/src/pmfe/pmfe_engine.c"
    "${_pd_generated}/pipeline.diag.c"
    "${_pd_generated}/p0.instrumented.c"
    "${_pd_agent_dir}/src/detection/policy_enforcement.c")
  target_include_directories(test_preprocess_stop_boundary PRIVATE
    $<TARGET_PROPERTY:edr_agent,INCLUDE_DIRECTORIES>
    "${_pd_agent_dir}/src/preprocess" "${CMAKE_CURRENT_SOURCE_DIR}"
    "${_pd_generated}")
  target_compile_definitions(test_preprocess_stop_boundary PRIVATE
    $<TARGET_PROPERTY:edr_agent,COMPILE_DEFINITIONS>
    EDR_P0_DIRECT_EMIT_TESTING=1
    "EDR_DIAG_RULE_ENVELOPE_PATH=\"${EDR_P0_TEST_CONFIG_DIR}/p0_rule_bundle_ir_v1.json.enc\"")
  target_link_libraries(test_preprocess_stop_boundary PRIVATE
    $<TARGET_PROPERTY:edr_agent,LINK_LIBRARIES>)
  edr_apply_test_warnings(test_preprocess_stop_boundary)
  set_target_properties(test_preprocess_stop_boundary PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}")
  file(GENERATE OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/pipeline-stop-source-closure-$<CONFIG>.txt"
    CONTENT "$<JOIN:${_pd_actual},\n>\nobjects-after-three-owner-filter:\n$<JOIN:$<FILTER:$<TARGET_OBJECTS:edr_runtime_test_common>,EXCLUDE,(preprocess_pipeline|p0_rule_direct_emit|policy_enforcement)\\.c\\.(obj|o)$>,\n>\n")
endif()
