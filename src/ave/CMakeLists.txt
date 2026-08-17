set(_edr_ave_shared_sources)
foreach(_edr_ave_source ${EDR_AVE_CORE_SOURCES})
  if(IS_ABSOLUTE "${_edr_ave_source}")
    list(APPEND _edr_ave_shared_sources "${_edr_ave_source}")
  else()
    list(APPEND _edr_ave_shared_sources "${CMAKE_SOURCE_DIR}/${_edr_ave_source}")
  endif()
endforeach()
list(APPEND _edr_ave_shared_sources
  ${CMAKE_SOURCE_DIR}/src/ave/ave_shared_runtime_stubs.c
  ${CMAKE_SOURCE_DIR}/src/config/config.c
  ${CMAKE_SOURCE_DIR}/src/core/edr_log.c
  ${CMAKE_SOURCE_DIR}/third_party/tomlc99/toml.c
)

add_library(edr_ave_shared SHARED ${_edr_ave_shared_sources})
target_include_directories(edr_ave_shared PRIVATE
  ${CMAKE_SOURCE_DIR}/include
  ${CMAKE_SOURCE_DIR}/src/ave
  ${CMAKE_SOURCE_DIR}/third_party/tomlc99
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

set_target_properties(edr_ave_shared PROPERTIES OUTPUT_NAME "edr_ave")
