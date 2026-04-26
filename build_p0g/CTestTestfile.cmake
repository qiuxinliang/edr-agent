# CMake generated Testfile for 
# Source directory: /Users/qiuxinliang/工程区/EDR DEV/AI Agent/edr-agent
# Build directory: /Users/qiuxinliang/工程区/EDR DEV/AI Agent/edr-agent/build_p0g
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test(edr_agent_help "/Users/qiuxinliang/工程区/EDR DEV/AI Agent/edr-agent/build_p0g/edr_agent" "--help")
set_tests_properties(edr_agent_help PROPERTIES  _BACKTRACE_TRIPLES "/Users/qiuxinliang/工程区/EDR DEV/AI Agent/edr-agent/CMakeLists.txt;656;add_test;/Users/qiuxinliang/工程区/EDR DEV/AI Agent/edr-agent/CMakeLists.txt;0;")
add_test(edr_p0_golden "/Users/qiuxinliang/工程区/EDR DEV/AI Agent/edr-agent/build_p0g/edr_p0_golden_test")
set_tests_properties(edr_p0_golden PROPERTIES  WORKING_DIRECTORY "/Users/qiuxinliang/工程区/EDR DEV/AI Agent/edr-agent/build_p0g" _BACKTRACE_TRIPLES "/Users/qiuxinliang/工程区/EDR DEV/AI Agent/edr-agent/CMakeLists.txt;683;add_test;/Users/qiuxinliang/工程区/EDR DEV/AI Agent/edr-agent/CMakeLists.txt;0;")
