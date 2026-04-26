# P4：打包、部署与热更（`.avepkg` / `model/releases` / `AVE_ApplyHotfix`）

## 1. `.avepkg` 与端侧 Agent

- **训练/发布流水线**可能将模型打成 **`.avepkg`**（或附带 manifest）；**本仓库 `edr-agent` 进程内不做解包**。
- 运行时唯一需要的是 **`[ave].model_dir`** 目录下**已解压**的 ONNX 文件（至少满足 `AVE_ONNX_CONTRACT.md` 的命名与选择规则：静态为目录内首个非 `behavior.onnx` 的 `.onnx`，行为为 `behavior.onnx`）。
- **平台侧**负责：下发 → 校验 → 解压到 `model_dir`（或下发裸 `.onnx` 至该目录）。若运维将 **`.avepkg` 路径**传给 **`AVE_ApplyHotfix`**，会因非目录且非 `.onnx` 而得到 **`AVE_ERR_INVALID_PARAM`**，**不会**假装成功。

## 2. `model/releases` 与端点

- 仓库 **`model/releases/<release_id>/`** 与 **`releases/current.json`** 描述的是**训练产物布局**（见仓库根 **`model/README.md`**）。
- Agent **不解析** `current.json`；仅将 **`model_dir`** 指到**某一 release 目录**（或平台同步后的等价目录）即可。

## 3. `AVE_ApplyHotfix` 与 ORT 重载

- **`edr_ave_apply_hotfix_path`**：参数为**目录**时，从该目录复制存在的 **`static.onnx`** / **`behavior.onnx`** 到 `cfg->ave.model_dir`；若目录下**两者皆无**，返回 **`EDR_ERR_INVALID_ARG`**（**不再**无操作却返回成功）。
- 参数为**单个 `.onnx` 文件**时，以**源文件 leaf 名**写入 `model_dir`（须含 `.onnx` 后缀）。
- **`AVE_ApplyHotfix`** 在复制成功后调用 **`edr_ave_reload_models`** 并清空 static 推理 LRU，使 **ONNX Runtime 会话**与磁盘一致。
- 观测：调用 **`AVE_GetStatus`**，**`static_model_version`** 为 **`onnx:<文件名>`**（与当前加载的静态 ONNX leaf 名一致），**`behavior_model_version`** 为 **`onnx:<文件名>`** 或回退 **`heuristic_v1`**。

## 4. 脚本与测试

| 用途 | 路径 |
|------|------|
| 全流程 + 扫描 + behavior | `scripts/ave_e2e_release_smoke.sh`、`tests/test_ave_e2e_full.c` |
| 热更 + GetStatus | `scripts/ave_hotfix_release_smoke.sh`、`tests/test_ave_hotfix_smoke.c` |
