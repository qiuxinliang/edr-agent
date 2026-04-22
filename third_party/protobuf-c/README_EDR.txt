本目录为官方 protobuf-c 1.5.2 完整源码（vendor），与上游 README.md / CHANGELOG.md 一致。

EDR Agent 使用说明
------------------
方式 A — 系统包（常用）
  macOS: brew install protobuf-c
  Debian/Ubuntu: apt install protobuf-c-compiler libprotobuf-c-dev

方式 B — 本目录源码构建
  cd third_party/protobuf-c && ./autogen.sh && ./configure && make
  将生成的 protoc-gen-c 加入 PATH，或依赖 scripts/regen_event_proto_c.sh 自动探测本目录下的插件。

生成 event.pb-c.{c,h}（在 edr-agent 根目录）:
  ./scripts/regen_event_proto_c.sh

可选：CMake 在检测到 src/proto_c/edr/v1/event.pb-c.c 且找到 libprotobuf-c 时，
可定义 EDR_HAVE_PROTOBUF_C 并链接独立 *_pack 实现（见 scripts/behavior_proto_c_pack.c.in）。
