set -e

cd "/Users/qiuxinliang/工程区/EDR DEV/AI Agent/edr-agent/out/build/any-ninja-fast-dev"
/opt/homebrew/bin/cmake --regenerate-during-build -S$(CMAKE_SOURCE_DIR) -B$(CMAKE_BINARY_DIR)
