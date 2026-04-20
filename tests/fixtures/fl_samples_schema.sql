-- 与 docs/FL_SAMPLES_SCHEMA.md 一致；集成测试与灌库脚本可引用此文件。
CREATE TABLE IF NOT EXISTS fl_samples (
  sha256 TEXT PRIMARY KEY NOT NULL,
  label INTEGER NOT NULL DEFAULT 0,
  model_target TEXT NOT NULL DEFAULT 'static',
  feature_blob BLOB NOT NULL,
  created_ts INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_fl_samples_target ON fl_samples(model_target);
