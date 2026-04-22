# onnx-output（默认安装打包源）

将训练/导出产物放在本目录（与 `scripts/install_static_onnx.sh` 默认源路径一致）：

| 文件 | 用途 |
|------|------|
| `static.onnx` | AVE 静态模型（`model_dir` 下**首个非** `behavior.onnx` 的 `.onnx`） |
| `behavior.onnx` | 行为序列模型（可选；存在则加载） |

**发布构建**：`scripts/sync_onnx_output_to_models.*` 在打包前把本目录下所有 `*.onnx` 复制到 `models/`，再由 Inno / zip 随安装包分发。发布 CI 设置 `EDR_BUNDLE_ONNX_REQUIRED=1` 时，若此处没有任何 `.onnx` 会失败。

大文件建议用 **Git LFS** 跟踪后再提交。
