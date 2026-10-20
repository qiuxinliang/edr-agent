# A real Agent entry point for one opt-in, disposable SCM diagnosis. It is not
# built by ALL, registered with CTest, packaged or installed. Production sources
# and build properties are reused; only pipeline/cache numeric frontiers differ.
if(WIN32 AND TARGET edr_agent AND Python3_EXECUTABLE)
  get_target_property(_sd_agent_dir edr_agent SOURCE_DIR)
  get_target_property(_sd_original edr_agent SOURCES)
  set(_sd_sources)
  set(_sd_pipeline_count 0)
  set(_sd_cache_count 0)
  set(_sd_home "${CMAKE_CURRENT_SOURCE_DIR}/pipeline_stop_diag")
  set(_sd_generated "${CMAKE_CURRENT_BINARY_DIR}/service-stop-generated")
  foreach(_sd_source IN LISTS _sd_original)
    if(_sd_source MATCHES "\\$<")
      message(FATAL_ERROR "Service diagnostic requires an explicit Agent source inventory")
    endif()
    if(NOT IS_ABSOLUTE "${_sd_source}")
      set(_sd_source "${_sd_agent_dir}/${_sd_source}")
    endif()
    get_filename_component(_sd_source "${_sd_source}" ABSOLUTE)
    if(_sd_source STREQUAL "${_sd_agent_dir}/src/preprocess/preprocess_pipeline.c")
      math(EXPR _sd_pipeline_count "${_sd_pipeline_count}+1")
      list(APPEND _sd_sources "${_sd_generated}/pipeline.service.instrumented.c")
    elseif(_sd_source STREQUAL "${_sd_agent_dir}/src/storage/local_evidence_cache.c")
      math(EXPR _sd_cache_count "${_sd_cache_count}+1")
      list(APPEND _sd_sources "${_sd_generated}/cache.service.instrumented.c")
    else()
      list(APPEND _sd_sources "${_sd_source}")
    endif()
  endforeach()
  if(NOT _sd_pipeline_count EQUAL 1)
    message(FATAL_ERROR "Service diagnostic must replace exactly one Agent pipeline owner")
  endif()
  if(NOT _sd_cache_count EQUAL 1)
    message(FATAL_ERROR "Service diagnostic must replace exactly one Agent cache owner")
  endif()
  add_custom_command(
    OUTPUT "${_sd_generated}/pipeline.service.instrumented.c"
      "${_sd_generated}/cache.service.instrumented.c"
    BYPRODUCTS "${_sd_generated}/SERVICE-SOURCE-TRANSFORM-v2.json"
      "${_sd_generated}/SERVICE-CACHE-SOURCE-TRANSFORM-v2.json"
    COMMAND "${CMAKE_COMMAND}" -E make_directory "${_sd_generated}"
    COMMAND "${Python3_EXECUTABLE}" -B "${_sd_home}/generate_service_source.py"
      "${_sd_agent_dir}" "${_sd_generated}"
    DEPENDS "${_sd_agent_dir}/src/preprocess/preprocess_pipeline.c"
      "${_sd_agent_dir}/src/storage/local_evidence_cache.c"
      "${_sd_home}/generate_service_source.py"
      "${_sd_home}/service_substage_frontier.inc"
    VERBATIM)
  add_executable(test_service_stop_agent EXCLUDE_FROM_ALL ${_sd_sources})
  # Copy the actual product properties rather than the assertion-enabled common
  # test objects. Directory/configuration flags still come from the same build.
  foreach(_sd_property IN ITEMS INCLUDE_DIRECTORIES COMPILE_DEFINITIONS
      COMPILE_OPTIONS LINK_LIBRARIES LINK_OPTIONS C_STANDARD C_STANDARD_REQUIRED
      C_EXTENSIONS CXX_STANDARD CXX_STANDARD_REQUIRED MSVC_RUNTIME_LIBRARY
      INTERPROCEDURAL_OPTIMIZATION)
    get_target_property(_sd_value edr_agent ${_sd_property})
    if(NOT _sd_value STREQUAL "_sd_value-NOTFOUND")
      set_property(TARGET test_service_stop_agent PROPERTY ${_sd_property} "${_sd_value}")
    endif()
  endforeach()
  target_include_directories(test_service_stop_agent PRIVATE
    "${_sd_agent_dir}/src/preprocess" "${_sd_agent_dir}/src/storage")
  # Source properties set in the parent directory are not inherited by a
  # target declared here. Apply the resource owner's definitions to RC only,
  # avoiding both a second manifest and changes to other tests' RC sources.
  get_source_file_property(_sd_resource_defs
    "${_sd_agent_dir}/resources/FDSensor.rc" TARGET_DIRECTORY edr_agent
    COMPILE_DEFINITIONS)
  if(NOT _sd_resource_defs STREQUAL "NOTFOUND")
    foreach(_sd_definition IN LISTS _sd_resource_defs)
      target_compile_definitions(test_service_stop_agent PRIVATE
        "$<$<COMPILE_LANGUAGE:RC>:${_sd_definition}>")
    endforeach()
  endif()
  set_target_properties(test_service_stop_agent PROPERTIES OUTPUT_NAME FDSensor
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/service-stop-agent")
  file(GENERATE
    OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/service-stop-source-closure-$<CONFIG>-$<COMPILE_LANGUAGE>.txt"
    CONTENT "original-agent-sources:\n$<JOIN:${_sd_original},\n>\ndiagnostic-sources-two-owner-replacements:\n$<JOIN:${_sd_sources},\n>\ncompile-definitions:\n$<JOIN:$<TARGET_PROPERTY:test_service_stop_agent,COMPILE_DEFINITIONS>,\n>\ncompile-options:\n$<JOIN:$<TARGET_PROPERTY:test_service_stop_agent,COMPILE_OPTIONS>,\n>\nlink-options:\n$<JOIN:$<TARGET_PROPERTY:test_service_stop_agent,LINK_OPTIONS>,\n>\n")
endif()
