tomlc99（https://github.com/cktan/tomlc99）

本目录应包含与上游一致的一对文件：
- toml.c
- toml.h

若从 GitHub 更新，可执行：
  curl -fsSL -O https://raw.githubusercontent.com/cktan/tomlc99/master/toml.c
  curl -fsSL -O https://raw.githubusercontent.com/cktan/tomlc99/master/toml.h

`edr_agent` 已通过 CMake 编译 `toml.c`，`src/config/config.c` 使用 `toml_parse_file` 加载 `agent.toml`。
