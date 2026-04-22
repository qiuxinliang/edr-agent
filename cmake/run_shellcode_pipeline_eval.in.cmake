# T-SC-001: run eval_shellcode_corpus --mode pipeline --strict (CTest driver, cmake -P).
# @CMAKE_BINARY_DIR@ substituted at configure time.
set(_bindir "@CMAKE_BINARY_DIR@")
set(_candidates
    "${_bindir}/eval_shellcode_corpus"
    "${_bindir}/Release/eval_shellcode_corpus.exe"
    "${_bindir}/Debug/eval_shellcode_corpus.exe"
    "${_bindir}/RelWithDebInfo/eval_shellcode_corpus.exe"
    "${_bindir}/MinSizeRel/eval_shellcode_corpus.exe"
    "${_bindir}/eval_shellcode_corpus.exe")
set(_ran 0)
foreach(_p IN LISTS _candidates)
  if(EXISTS "${_p}")
    execute_process(COMMAND "${_p}" --mode pipeline --strict RESULT_VARIABLE _r OUTPUT_VARIABLE _out
                    ERROR_VARIABLE _err)
    if(NOT _r EQUAL 0)
      message(FATAL_ERROR "eval_shellcode_corpus pipeline --strict failed (exit ${_r}) path=${_p}\n${_err}")
    endif()
    set(_ran 1)
    break()
  endif()
endforeach()
if(_ran EQUAL 0)
  message(FATAL_ERROR "eval_shellcode_corpus not found under ${_bindir} (T-SC-001)")
endif()
