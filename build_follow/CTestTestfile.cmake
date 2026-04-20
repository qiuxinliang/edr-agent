# CMake generated Testfile for 
# Source directory: /Users/qiuxinliang/工程区/EDR DEV/AI Agent/edr-agent
# Build directory: /Users/qiuxinliang/工程区/EDR DEV/AI Agent/edr-agent/build_follow
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test(edr_agent_help "/Users/qiuxinliang/工程区/EDR DEV/AI Agent/edr-agent/build_follow/edr_agent" "--help")
set_tests_properties(edr_agent_help PROPERTIES  _BACKTRACE_TRIPLES "/Users/qiuxinliang/工程区/EDR DEV/AI Agent/edr-agent/CMakeLists.txt;385;add_test;/Users/qiuxinliang/工程区/EDR DEV/AI Agent/edr-agent/CMakeLists.txt;0;")
add_test(ave_file_fingerprint "/Users/qiuxinliang/工程区/EDR DEV/AI Agent/edr-agent/build_follow/test_ave_fp")
set_tests_properties(ave_file_fingerprint PROPERTIES  WORKING_DIRECTORY "/Users/qiuxinliang/工程区/EDR DEV/AI Agent/edr-agent/build_follow" _BACKTRACE_TRIPLES "/Users/qiuxinliang/工程区/EDR DEV/AI Agent/edr-agent/CMakeLists.txt;605;add_test;/Users/qiuxinliang/工程区/EDR DEV/AI Agent/edr-agent/CMakeLists.txt;0;")
add_test(ave_infer_dry_run "/Users/qiuxinliang/工程区/EDR DEV/AI Agent/edr-agent/build_follow/test_ave_infer")
set_tests_properties(ave_infer_dry_run PROPERTIES  WORKING_DIRECTORY "/Users/qiuxinliang/工程区/EDR DEV/AI Agent/edr-agent/build_follow" _BACKTRACE_TRIPLES "/Users/qiuxinliang/工程区/EDR DEV/AI Agent/edr-agent/CMakeLists.txt;606;add_test;/Users/qiuxinliang/工程区/EDR DEV/AI Agent/edr-agent/CMakeLists.txt;0;")
add_test(ave_sdk_smoke "/Users/qiuxinliang/工程区/EDR DEV/AI Agent/edr-agent/build_follow/test_ave_sdk")
set_tests_properties(ave_sdk_smoke PROPERTIES  WORKING_DIRECTORY "/Users/qiuxinliang/工程区/EDR DEV/AI Agent/edr-agent/build_follow" _BACKTRACE_TRIPLES "/Users/qiuxinliang/工程区/EDR DEV/AI Agent/edr-agent/CMakeLists.txt;607;add_test;/Users/qiuxinliang/工程区/EDR DEV/AI Agent/edr-agent/CMakeLists.txt;0;")
add_test(ave_fl_abi_c0 "/Users/qiuxinliang/工程区/EDR DEV/AI Agent/edr-agent/build_follow/test_ave_fl_abi")
set_tests_properties(ave_fl_abi_c0 PROPERTIES  WORKING_DIRECTORY "/Users/qiuxinliang/工程区/EDR DEV/AI Agent/edr-agent/build_follow" _BACKTRACE_TRIPLES "/Users/qiuxinliang/工程区/EDR DEV/AI Agent/edr-agent/CMakeLists.txt;608;add_test;/Users/qiuxinliang/工程区/EDR DEV/AI Agent/edr-agent/CMakeLists.txt;0;")
add_test(ave_suppression_sqlite "/Users/qiuxinliang/工程区/EDR DEV/AI Agent/edr-agent/build_follow/test_ave_suppression")
set_tests_properties(ave_suppression_sqlite PROPERTIES  WORKING_DIRECTORY "/Users/qiuxinliang/工程区/EDR DEV/AI Agent/edr-agent/build_follow" _BACKTRACE_TRIPLES "/Users/qiuxinliang/工程区/EDR DEV/AI Agent/edr-agent/CMakeLists.txt;609;add_test;/Users/qiuxinliang/工程区/EDR DEV/AI Agent/edr-agent/CMakeLists.txt;0;")
add_test(ave_scan_pipeline "/Users/qiuxinliang/工程区/EDR DEV/AI Agent/edr-agent/build_follow/test_ave_pipeline")
set_tests_properties(ave_scan_pipeline PROPERTIES  WORKING_DIRECTORY "/Users/qiuxinliang/工程区/EDR DEV/AI Agent/edr-agent/build_follow" _BACKTRACE_TRIPLES "/Users/qiuxinliang/工程区/EDR DEV/AI Agent/edr-agent/CMakeLists.txt;610;add_test;/Users/qiuxinliang/工程区/EDR DEV/AI Agent/edr-agent/CMakeLists.txt;0;")
add_test(config_fingerprint "/Users/qiuxinliang/工程区/EDR DEV/AI Agent/edr-agent/build_follow/test_config_fp")
set_tests_properties(config_fingerprint PROPERTIES  WORKING_DIRECTORY "/Users/qiuxinliang/工程区/EDR DEV/AI Agent/edr-agent/build_follow" _BACKTRACE_TRIPLES "/Users/qiuxinliang/工程区/EDR DEV/AI Agent/edr-agent/CMakeLists.txt;611;add_test;/Users/qiuxinliang/工程区/EDR DEV/AI Agent/edr-agent/CMakeLists.txt;0;")
add_test(fl_trainer_c1 "/Users/qiuxinliang/工程区/EDR DEV/AI Agent/edr-agent/build_follow/test_fl_trainer_smoke")
set_tests_properties(fl_trainer_c1 PROPERTIES  WORKING_DIRECTORY "/Users/qiuxinliang/工程区/EDR DEV/AI Agent/edr-agent/build_follow" _BACKTRACE_TRIPLES "/Users/qiuxinliang/工程区/EDR DEV/AI Agent/edr-agent/CMakeLists.txt;613;add_test;/Users/qiuxinliang/工程区/EDR DEV/AI Agent/edr-agent/CMakeLists.txt;0;")
add_test(shellcode_modules "/Users/qiuxinliang/工程区/EDR DEV/AI Agent/edr-agent/build_follow/test_shellcode")
set_tests_properties(shellcode_modules PROPERTIES  WORKING_DIRECTORY "/Users/qiuxinliang/工程区/EDR DEV/AI Agent/edr-agent/build_follow" _BACKTRACE_TRIPLES "/Users/qiuxinliang/工程区/EDR DEV/AI Agent/edr-agent/CMakeLists.txt;636;add_test;/Users/qiuxinliang/工程区/EDR DEV/AI Agent/edr-agent/CMakeLists.txt;0;")
add_test(edr_agent_smoke "bash" "/Users/qiuxinliang/工程区/EDR DEV/AI Agent/edr-agent/scripts/agent_smoke.sh" "/Users/qiuxinliang/工程区/EDR DEV/AI Agent/edr-agent/build_follow/edr_agent")
set_tests_properties(edr_agent_smoke PROPERTIES  TIMEOUT "30" _BACKTRACE_TRIPLES "/Users/qiuxinliang/工程区/EDR DEV/AI Agent/edr-agent/CMakeLists.txt;637;add_test;/Users/qiuxinliang/工程区/EDR DEV/AI Agent/edr-agent/CMakeLists.txt;0;")
