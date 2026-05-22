# CMake generated Testfile for 
# Source directory: /Users/qiuxinliang/工程区/EDR DEV/AI Agent/edr-agent
# Build directory: /Users/qiuxinliang/工程区/EDR DEV/AI Agent/edr-agent/build_darwin
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test(edr_agent_help "/Users/qiuxinliang/工程区/EDR DEV/AI Agent/edr-agent/build_darwin/edr_agent" "--help")
set_tests_properties(edr_agent_help PROPERTIES  _BACKTRACE_TRIPLES "/Users/qiuxinliang/工程区/EDR DEV/AI Agent/edr-agent/CMakeLists.txt;907;add_test;/Users/qiuxinliang/工程区/EDR DEV/AI Agent/edr-agent/CMakeLists.txt;0;")
add_test(edr_p0_golden "/Users/qiuxinliang/工程区/EDR DEV/AI Agent/edr-agent/build_darwin/edr_p0_golden_test")
set_tests_properties(edr_p0_golden PROPERTIES  ENVIRONMENT "EDR_P0_IR_PATH=/Users/qiuxinliang/工程区/EDR DEV/AI Agent/edr-agent/config/p0_rule_bundle_ir_v1.json" WORKING_DIRECTORY "/Users/qiuxinliang/工程区/EDR DEV/AI Agent/edr-agent/build_darwin" _BACKTRACE_TRIPLES "/Users/qiuxinliang/工程区/EDR DEV/AI Agent/edr-agent/CMakeLists.txt;967;add_test;/Users/qiuxinliang/工程区/EDR DEV/AI Agent/edr-agent/CMakeLists.txt;0;")
add_test(test_event_bus_mpmc_stress "/Users/qiuxinliang/工程区/EDR DEV/AI Agent/edr-agent/build_darwin/test_event_bus_mpmc_stress" "250" "4" "64")
set_tests_properties(test_event_bus_mpmc_stress PROPERTIES  LABELS "A4.1;event_bus" TIMEOUT "30" WORKING_DIRECTORY "/Users/qiuxinliang/工程区/EDR DEV/AI Agent/edr-agent/build_darwin" _BACKTRACE_TRIPLES "/Users/qiuxinliang/工程区/EDR DEV/AI Agent/edr-agent/CMakeLists.txt;1004;add_test;/Users/qiuxinliang/工程区/EDR DEV/AI Agent/edr-agent/CMakeLists.txt;0;")
add_test(edr_p0_ir_record_golden "/Users/qiuxinliang/工程区/EDR DEV/AI Agent/edr-agent/build_darwin/edr_p0_ir_record_golden_test")
set_tests_properties(edr_p0_ir_record_golden PROPERTIES  ENVIRONMENT "EDR_P0_IR_PATH=/Users/qiuxinliang/工程区/EDR DEV/AI Agent/edr-agent/config/p0_rule_bundle_ir_v1.json" WORKING_DIRECTORY "/Users/qiuxinliang/工程区/EDR DEV/AI Agent/edr-agent/build_darwin" _BACKTRACE_TRIPLES "/Users/qiuxinliang/工程区/EDR DEV/AI Agent/edr-agent/CMakeLists.txt;1073;add_test;/Users/qiuxinliang/工程区/EDR DEV/AI Agent/edr-agent/CMakeLists.txt;0;")
add_test(detection_profile_trigger "/Users/qiuxinliang/工程区/EDR DEV/AI Agent/edr-agent/build_darwin/test_detection_profile_trigger")
set_tests_properties(detection_profile_trigger PROPERTIES  WORKING_DIRECTORY "/Users/qiuxinliang/工程区/EDR DEV/AI Agent/edr-agent/build_darwin" _BACKTRACE_TRIPLES "/Users/qiuxinliang/工程区/EDR DEV/AI Agent/edr-agent/CMakeLists.txt;1718;add_test;/Users/qiuxinliang/工程区/EDR DEV/AI Agent/edr-agent/CMakeLists.txt;0;")
add_test(forensic_trigger "/Users/qiuxinliang/工程区/EDR DEV/AI Agent/edr-agent/build_darwin/test_forensic_trigger")
set_tests_properties(forensic_trigger PROPERTIES  WORKING_DIRECTORY "/Users/qiuxinliang/工程区/EDR DEV/AI Agent/edr-agent/build_darwin" _BACKTRACE_TRIPLES "/Users/qiuxinliang/工程区/EDR DEV/AI Agent/edr-agent/CMakeLists.txt;1726;add_test;/Users/qiuxinliang/工程区/EDR DEV/AI Agent/edr-agent/CMakeLists.txt;0;")
