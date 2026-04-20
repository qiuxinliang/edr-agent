# `fl_samples.db` 最小 Schema（C3）

与《09》《10》对齐的端侧只读库；Agent 通过 SQLite 枚举样本并配合 `AVE_ExportFeatureVector` 拉取向量。

## 表 `fl_samples`

| 列 | 类型 | 说明 |
|----|------|------|
| `sha256` | `TEXT` PK | 64 位十六进制小写/大写均可（查询时规范化） |
| `label` | `INTEGER` | 0=clean, 1=malware（占位） |
| `model_target` | `TEXT` | `static` / `behavior` |
| `feature_blob` | `BLOB` | `float32` 小端，长度 = `dim * 4`；**static 默认 dim=512**；**behavior 默认 dim=256**（与《11_behavior.onnx详细设计》§6.1 **CLS Token** 维数一致；序列长度 **128** 见 `AVE_FL_BEHAVIOR_SEQ_LEN`） |
| `created_ts` | `INTEGER` | Unix 秒 |

```sql
CREATE TABLE IF NOT EXISTS fl_samples (
  sha256 TEXT PRIMARY KEY NOT NULL,
  label INTEGER NOT NULL DEFAULT 0,
  model_target TEXT NOT NULL DEFAULT 'static',
  feature_blob BLOB NOT NULL,
  created_ts INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_fl_samples_target ON fl_samples(model_target);
```

与上表一致的 DDL 片段见仓库 **`tests/fixtures/fl_samples_schema.sql`**（灌库/脚本可 `sqlite3 fl_samples.db < ...`）。

## 测试

`tests/` 中可创建内存库或临时文件并插入一行以验证 `fl_samples` 枚举与特征导出。自动化：`ctest -R fl_ave_samples_bridge`（`tests/test_fl_ave_samples_bridge.c`，需 SQLite）。
