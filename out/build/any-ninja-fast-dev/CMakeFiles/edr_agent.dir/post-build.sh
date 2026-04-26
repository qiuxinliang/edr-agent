set -e

cd "/Users/qiuxinliang/工程区/EDR DEV/AI Agent/edr-agent/out/build/any-ninja-fast-dev"
/opt/homebrew/bin/cmake -E make_directory /Users/qiuxinliang/工程区/EDR\ DEV/AI\ Agent/edr-agent/out/build/any-ninja-fast-dev/edr_config
/opt/homebrew/bin/cmake -E copy_if_different /Users/qiuxinliang/工程区/EDR\ DEV/AI\ Agent/edr-agent/config/p0_rule_bundle_manifest.json /Users/qiuxinliang/工程区/EDR\ DEV/AI\ Agent/edr-agent/out/build/any-ninja-fast-dev/edr_config/p0_rule_bundle_manifest.json
cd "/Users/qiuxinliang/工程区/EDR DEV/AI Agent/edr-agent/out/build/any-ninja-fast-dev"
/opt/homebrew/bin/cmake -E make_directory /Users/qiuxinliang/工程区/EDR\ DEV/AI\ Agent/edr-agent/out/build/any-ninja-fast-dev/edr_config
/opt/homebrew/bin/cmake -E copy_if_different /Users/qiuxinliang/工程区/EDR\ DEV/AI\ Agent/edr-agent/config/p0_rule_bundle_ir_v1.json /Users/qiuxinliang/工程区/EDR\ DEV/AI\ Agent/edr-agent/out/build/any-ninja-fast-dev/edr_config/p0_rule_bundle_ir_v1.json
