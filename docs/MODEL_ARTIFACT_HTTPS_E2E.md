# 模型制品 HTTPS 拉取 E2E（DL-05）

> **产品口径**：平台 **`model_release_artifacts.object_uri`**（或预签名 **`download_url`**）须为 **HTTPS**；终端侧将 zip 落地后校验 **manifest / SHA256**，解压或热更至 **`[ave].model_dir`**，并通过 **`AVE_GetStatus`** 等可观测版本。见 **`PHASE1_PRODUCT_DECISIONS.md`** §4、**`AVE_PACKAGING_P4.md`**。

---

## 1. 平台侧准备

1. 迁移 **`000028_model_release_artifacts`** 已应用。  
2. Worker 或脚本将训练产物上传对象存储，**`POST /api/v1/admin/model/training/artifacts`** 登记 **`object_uri`**（HTTPS）。  
3. **`POST .../admin/model/training/promote`** 将产物标为 **`promoted`**（控制台「模型运维」与 WS **`model.train.promoted`** 对齐）。

从 DB 或 API 响应复制 **HTTPS** 下载 URL（预签名 URL 通常含时效，脚本需在有效期内执行）。

---

## 2. 终端侧路径（本仓库）

- **热更（已解压目录或单 `.onnx`）**：**`AVE_ApplyHotfix`**（见 **`AVE_PACKAGING_P4.md`** §3）。  
- **`.avepkg`**：进程内**不解包**；需运维预解压到 **`model_dir`** 后再指向该目录。  
- **版本可读**：**`AVE_GetStatus`** → **`static_model_version` / `behavior_model_version`**（`onnx:<文件名>` 等）。

---

## 3. 自动化冒烟脚本

仓库脚本：**`edr-backend/scripts/smoke_model_artifact_https_e2e.sh`**

- 输入：**`ARTIFACT_URL`**（HTTPS，指向 **zip**）。  
- 行为：**`curl -fsSL`** 下载 → **`unzip -t`** 完整性测试 → 可选 **`EXPECTED_SHA256`** 与 **`shasum -a 256`** 比对。

与 Agent 联调时，可将 zip 解压到临时目录后调用 **`AVE_ApplyHotfix`**（语言绑定或 CLI），本脚本仅覆盖 **「HTTPS 拉取 + 完整性」** 一段。

---

## 4. 验收记录

在 **`edr-backend/docs/DATA_LINK_GAPS_CHECKLIST.md`** DL-05 节补 **验证记录**（日期、环境、执行人）。
