# CMake generated Testfile for 
# Source directory: /Users/qiuxinliang/工程区/EDR DEV/AI Agent/edr-agent
# Build directory: /Users/qiuxinliang/工程区/EDR DEV/AI Agent/edr-agent/build_h
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test(edr_agent_help "/Users/qiuxinliang/工程区/EDR DEV/AI Agent/edr-agent/build_h/edr_agent" "--help")
set_tests_properties(edr_agent_help PROPERTIES  _BACKTRACE_TRIPLES "/Users/qiuxinliang/工程区/EDR DEV/AI Agent/edr-agent/CMakeLists.txt;828;add_test;/Users/qiuxinliang/工程区/EDR DEV/AI Agent/edr-agent/CMakeLists.txt;0;")
add_test(edr_p0_golden "/Users/qiuxinliang/工程区/EDR DEV/AI Agent/edr-agent/build_h/edr_p0_golden_test")
set_tests_properties(edr_p0_golden PROPERTIES  ENVIRONMENT "EDR_P0_IR_PATH=/Users/qiuxinliang/工程区/EDR DEV/AI Agent/edr-agent/config/p0_rule_bundle_ir_v1.json" WORKING_DIRECTORY "/Users/qiuxinliang/工程区/EDR DEV/AI Agent/edr-agent/build_h" _BACKTRACE_TRIPLES "/Users/qiuxinliang/工程区/EDR DEV/AI Agent/edr-agent/CMakeLists.txt;887;add_test;/Users/qiuxinliang/工程区/EDR DEV/AI Agent/edr-agent/CMakeLists.txt;0;")
add_test(test_event_bus_mpmc_stress "/Users/qiuxinliang/工程区/EDR DEV/AI Agent/edr-agent/build_h/test_event_bus_mpmc_stress" "250" "4" "64")
set_tests_properties(test_event_bus_mpmc_stress PROPERTIES  LABELS "A4.1;event_bus" TIMEOUT "30" WORKING_DIRECTORY "/Users/qiuxinliang/工程区/EDR DEV/AI Agent/edr-agent/build_h" _BACKTRACE_TRIPLES "/Users/qiuxinliang/工程区/EDR DEV/AI Agent/edr-agent/CMakeLists.txt;924;add_test;/Users/qiuxinliang/工程区/EDR DEV/AI Agent/edr-agent/CMakeLists.txt;0;")
