#!/usr/bin/env python3
"""
EDR FL 样本库导入工具 — 将外部样本导入 fl_samples.db。

支持的来源：
  1. EMBER/SOREL JSON Lines 特征文件 → static 样本
  2. MalwareBazaar API → 自动下载恶意样本 + 特征提取
  3. 数据增强 → 噪声注入扩充现有样本
  4. 统计查询 → 查看样本库概况

依赖:
  pip install numpy requests
  特征提取 (可选): pip install ember

用法：
  python3 scripts/import_samples_to_db.py ember ember_features.jsonl --limit 10000
  python3 scripts/import_samples_to_db.py malwarebazaar --limit 100
  python3 scripts/import_samples_to_db.py augment --n-augment 3
  python3 scripts/import_samples_to_db.py stats
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import sqlite3
import struct
import sys
import zipfile
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

DB_SCHEMA = """
CREATE TABLE IF NOT EXISTS fl_samples (
  sha256 TEXT PRIMARY KEY NOT NULL,
  label INTEGER NOT NULL DEFAULT 0,
  model_target TEXT NOT NULL DEFAULT 'static',
  feature_blob BLOB NOT NULL,
  created_ts INTEGER NOT NULL DEFAULT (strftime('%s','now'))
);
CREATE INDEX IF NOT EXISTS idx_fl_samples_target ON fl_samples(model_target);
CREATE INDEX IF NOT EXISTS idx_fl_samples_label ON fl_samples(label);
"""

EMBER_KEY_ORDER = [
    "histogram", "byteentropy", "strings", "general",
    "header", "section", "imports", "exports", "datadirectories"
]


def init_db(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.executescript(DB_SCHEMA)
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def insert_sample(conn: sqlite3.Connection, sha256: str, label: int,
                  model_target: str, features: np.ndarray) -> bool:
    blob = features.astype(np.float32).tobytes()
    try:
        conn.execute(
            "INSERT OR IGNORE INTO fl_samples(sha256, label, model_target, feature_blob) "
            "VALUES (?, ?, ?, ?)",
            (sha256, label, model_target, blob)
        )
        return True
    except Exception as e:
        print(f"  [warn] 插入 {sha256[:16]}... 失败: {e}", file=sys.stderr)
        return False


def sha256_exists(conn: sqlite3.Connection, sha256: str) -> bool:
    row = conn.execute("SELECT 1 FROM fl_samples WHERE sha256=?", (sha256,)).fetchone()
    return row is not None


def load_pca_if_available() -> Tuple[Optional[np.ndarray], Optional[np.ndarray]]:
    script_dir = os.path.dirname(os.path.abspath(__file__))
    pca_path = os.path.join(script_dir, "ember_pca_512.npy")
    mean_path = os.path.join(script_dir, "ember_pca_mean.npy")
    if os.path.exists(pca_path) and os.path.exists(mean_path):
        try:
            return np.load(pca_path), np.load(mean_path)
        except Exception:
            pass
    return None, None


def ember_2381_to_512(all_feats: List[float],
                       pca_matrix: Optional[np.ndarray],
                       pca_mean: Optional[np.ndarray]) -> np.ndarray:
    if len(all_feats) < 512:
        all_feats.extend([0.0] * (512 - len(all_feats)))

    if pca_matrix is not None and pca_mean is not None and len(all_feats) >= 2381:
        vec = np.array(all_feats[:2381], dtype=np.float64)
        vec = vec - pca_mean
        return (pca_matrix @ vec).astype(np.float32)

    feats = np.array(all_feats[:512], dtype=np.float32)
    max_val = float(np.max(np.abs(feats)) or 1.0)
    return feats / max_val


# ============================================================
# 来源 1: EMBER JSON Lines
# ============================================================
def import_ember(args) -> int:
    pca_matrix, pca_mean = load_pca_if_available()
    if pca_matrix is not None:
        print("[info] 使用 PCA 降维 2381→512")
    else:
        print("[info] 无 PCA 矩阵，使用前 512 维 + 归一化")

    conn = init_db(args.db)
    count = 0

    with open(args.jsonl, "r") as f:
        for i, line in enumerate(f):
            if args.limit and count >= args.limit:
                break
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue

            sha256 = rec.get("sha256", "")
            if not sha256 or len(sha256) != 64:
                continue

            if sha256_exists(conn, sha256):
                continue

            all_feats = []
            for key in EMBER_KEY_ORDER:
                val = rec.get(key, [])
                if isinstance(val, list):
                    all_feats.extend(val)

            features = ember_2381_to_512(all_feats, pca_matrix, pca_mean)
            label = int(rec.get("label", 0))
            insert_sample(conn, sha256, label, "static", features)
            count += 1

            if count % 1000 == 0:
                conn.commit()
                print(f"  ... 已导入 {count} 条")

    conn.commit()
    conn.close()
    print(f"[done] 共导入 {count} 条 static 样本")
    return 0


# ============================================================
# 来源 2: MalwareBazaar API
# ============================================================
def import_malwarebazaar(args) -> int:
    import requests

    print(f"[info] 从 MalwareBazaar 获取样本 (limit={args.limit})")

    # 获取最近样本列表
    request_data = {"query": "get_recent", "selector": "time"}
    headers = {}
    if args.api_key:
        headers["API-KEY"] = args.api_key

    try:
        resp = requests.post(
            "https://mb-api.abuse.ch/api/v1/",
            data=request_data,
            timeout=30,
            headers=headers,
        )
        resp.raise_for_status()
        samples = resp.json().get("data", [])
    except Exception as e:
        print(f"[error] MalwareBazaar API 请求失败: {e}", file=sys.stderr)
        return 1

    print(f"[info] 获取到 {len(samples)} 条样本信息，将下载前 {args.limit} 条")

    # 尝试加载特征提取器
    try:
        import ember
        extractor = ember.PEFeatureExtractor(feature_version=2)
        print("[info] 使用 EMBER 特征提取器 (2381维)")
    except ImportError:
        print("[error] 需要 pip install ember 用于 PE 特征提取", file=sys.stderr)
        return 1

    pca_matrix, pca_mean = load_pca_if_available()
    conn = init_db(args.db)
    count = 0

    for item in samples:
        if count >= args.limit:
            break

        sha256 = item.get("sha256_hash", "")
        if not sha256 or sha256_exists(conn, sha256):
            continue

        try:
            dl_data = {"query": "get_file", "sha256_hash": sha256}
            dl_resp = requests.post(
                "https://mb-api.abuse.ch/api/v1/",
                data=dl_data,
                timeout=60,
                headers=headers,
            )
            if dl_resp.status_code != 200:
                continue

            zf = zipfile.ZipFile(io.BytesIO(dl_resp.content))
            names = zf.namelist()
            if not names:
                continue
            exe_data = zf.read(names[0], pwd=b"infected")

            raw_feats = extractor.feature_vector(exe_data)
            all_feats = []
            for key in EMBER_KEY_ORDER:
                val = raw_feats.get(key, [])
                if isinstance(val, list):
                    all_feats.extend(val)
            features = ember_2381_to_512(all_feats, pca_matrix, pca_mean)

            insert_sample(conn, sha256, 1, "static", features)
            count += 1

            if count % 10 == 0:
                conn.commit()
                print(f"  ... 已下载并导入 {count} 个样本")

        except Exception as e:
            continue

    conn.commit()
    conn.close()
    print(f"[done] 共从 MalwareBazaar 导入 {count} 个样本")
    return 0


# ============================================================
# 来源 3: 原始 PE 文件目录
# ============================================================
def import_pe_directory(args) -> int:
    try:
        import ember
        extractor = ember.PEFeatureExtractor(feature_version=2)
    except ImportError:
        print("[error] 需要 pip install ember 用于 PE 特征提取", file=sys.stderr)
        return 1

    pca_matrix, pca_mean = load_pca_if_available()
    conn = init_db(args.db)
    count = 0

    for root, dirs, files in os.walk(args.pe_dir):
        for fname in files:
            fpath = os.path.join(root, fname)
            try:
                with open(fpath, "rb") as f:
                    data = f.read()
                if len(data) < 256:
                    continue

                sha256 = hashlib.sha256(data).hexdigest()
                if sha256_exists(conn, sha256):
                    continue

                raw_feats = extractor.feature_vector(data)
                all_feats = []
                for key in EMBER_KEY_ORDER:
                    val = raw_feats.get(key, [])
                    if isinstance(val, list):
                        all_feats.extend(val)
                features = ember_2381_to_512(all_feats, pca_matrix, pca_mean)

                insert_sample(conn, sha256, args.label, "static", features)
                count += 1

                if count % 100 == 0:
                    conn.commit()
                    print(f"  ... 已导入 {count} 个 PE 文件")

            except Exception:
                continue

    conn.commit()
    conn.close()
    print(f"[done] 共导入 {count} 个 PE 文件 (label={args.label})")
    return 0


# ============================================================
# 来源 4: 数据增强
# ============================================================
def augment_samples(args) -> int:
    conn = init_db(args.db)
    rows = conn.execute(
        "SELECT sha256, label, feature_blob FROM fl_samples "
        "WHERE model_target='static' OR model_target='behavior'"
    ).fetchall()

    rng = np.random.RandomState(42)
    new_count = 0
    for sha256, label, blob in rows:
        orig = np.frombuffer(blob, dtype=np.float32)
        feat_dim = len(orig)

        for aug_i in range(args.n_augment):
            noise = rng.randn(feat_dim).astype(np.float32) * args.noise_std
            augmented = orig + noise

            aug_sha256 = hashlib.sha256(
                (sha256 + f"_aug{aug_i}").encode()
            ).hexdigest()
            aug_blob = augmented.tobytes()

            model_target = "static" if feat_dim == 512 else "behavior"
            try:
                conn.execute(
                    "INSERT OR IGNORE INTO fl_samples(sha256, label, model_target, feature_blob) "
                    "VALUES (?, ?, ?, ?)",
                    (aug_sha256, label, model_target, aug_blob)
                )
                new_count += 1
            except Exception:
                continue

        if new_count % 1000 == 0:
            conn.commit()
            print(f"  ... 已生成 {new_count} 条增强样本")

    conn.commit()
    conn.close()
    print(f"[done] 从 {len(rows)} 条原始样本生成 {new_count} 条增强样本 "
          f"(noise_std={args.noise_std}, n_augment={args.n_augment})")
    return 0


# ============================================================
# 来源 5: 合成 behavior 样本（用于快速验证管线）
# ============================================================
def generate_behavior_samples(args) -> int:
    rng = np.random.RandomState(42)
    conn = init_db(args.db)
    count = 0

    for i in range(args.n_samples):
        is_malicious = rng.rand() < 0.3
        if is_malicious:
            seq = rng.randn(args.seq_len, args.feat_dim) * 0.5
            spike_start = args.seq_len * 3 // 4
            seq[spike_start:, :8] += rng.randn(args.seq_len - spike_start, 8) * 2.0
            seq[:, 10:14] *= 1.5
            label = 1
        else:
            seq = rng.randn(args.seq_len, args.feat_dim) * 0.3
            for t in range(1, args.seq_len):
                seq[t] = 0.7 * seq[t - 1] + 0.3 * seq[t]
            label = 0

        features = seq.flatten().astype(np.float32)
        sha256 = hashlib.sha256(features.tobytes()).hexdigest()
        insert_sample(conn, sha256, label, "behavior", features)
        count += 1

        if count % 100 == 0:
            conn.commit()
            print(f"  ... 已生成 {count} 条 behavior 样本")

    conn.commit()
    conn.close()
    print(f"[done] 生成 {count} 条合成 behavior 样本")
    return 0


# ============================================================
# 统计查询
# ============================================================
def show_stats(args) -> int:
    conn = sqlite3.connect(args.db)
    total = conn.execute("SELECT COUNT(*) FROM fl_samples").fetchone()[0]
    if total == 0:
        print("样本库为空")
        conn.close()
        return 0

    print(f"总样本数: {total}\n")

    by_target = conn.execute(
        "SELECT model_target, label, COUNT(*) FROM fl_samples "
        "GROUP BY model_target, label ORDER BY model_target, label"
    ).fetchall()
    for target, label, cnt in by_target:
        tag = "恶意" if label == 1 else "正常"
        print(f"  {target:10s}  {tag}: {cnt:>8}")

    # 特征维度分布
    print("\n特征维度分布:")
    dims = conn.execute(
        "SELECT model_target, LENGTH(feature_blob)/4 AS dim, COUNT(*) "
        "FROM fl_samples GROUP BY model_target, dim ORDER BY model_target"
    ).fetchall()
    for target, dim, cnt in dims:
        print(f"  {target:10s}  dim={int(dim):>4}: {cnt:>8}")

    # 时间分布
    print("\n最近样本:")
    recent = conn.execute(
        "SELECT sha256, label, model_target, created_ts FROM fl_samples "
        "ORDER BY created_ts DESC LIMIT 5"
    ).fetchall()
    for sha256, label, target, ts in recent:
        tag = "恶意" if label == 1 else "正常"
        print(f"  {sha256[:16]}...  {target:10s}  {tag}  ts={ts}")

    conn.close()
    return 0


# ============================================================
# 计算并保存 EMBER PCA 矩阵
# ============================================================
def compute_ember_pca(args) -> int:
    """
    从 EMBER JSONL 计算 PCA 降维矩阵 (2381→512)。
    需要读取大量样本，取前 N 条计算。
    """
    from sklearn.decomposition import PCA

    print(f"[info] 从 {args.jsonl} 读取特征...")
    all_feats_list = []
    with open(args.jsonl, "r") as f:
        for i, line in enumerate(f):
            if args.limit and i >= args.limit:
                break
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue

            row_feats = []
            for key in EMBER_KEY_ORDER:
                val = rec.get(key, [])
                if isinstance(val, list):
                    row_feats.extend(val)
            if len(row_feats) >= 2381:
                all_feats_list.append(row_feats[:2381])
            if (i + 1) % 10000 == 0:
                print(f"  ... 已读取 {i + 1} 条")

    X = np.array(all_feats_list, dtype=np.float64)
    print(f"[info] 矩阵形状: {X.shape}")

    # 均值
    mean_vec = X.mean(axis=0)
    X_centered = X - mean_vec

    # PCA
    print("[info] 计算 PCA (2381→512)...")
    pca = PCA(n_components=512, random_state=42)
    pca.fit(X_centered)

    pca_matrix = pca.components_  # shape: (512, 2381)

    pca_path = os.path.join(os.path.dirname(__file__), "ember_pca_512.npy")
    mean_path = os.path.join(os.path.dirname(__file__), "ember_pca_mean.npy")
    np.save(pca_path, pca_matrix.astype(np.float32))
    np.save(mean_path, mean_vec.astype(np.float32))

    explained = pca.explained_variance_ratio_.sum()
    print(f"[done] PCA 矩阵保存到 {pca_path}")
    print(f"  累计方差解释率: {explained:.3f}")
    return 0


# ============================================================
# CLI
# ============================================================
def main() -> int:
    parser = argparse.ArgumentParser(description="EDR FL 样本库导入工具")
    sub = parser.add_subparsers(dest="cmd")

    ember_p = sub.add_parser("ember", help="导入 EMBER JSON Lines → static 样本")
    ember_p.add_argument("jsonl", help="EMBER JSONL 文件路径")
    ember_p.add_argument("--db", default="fl_samples.db")
    ember_p.add_argument("--limit", type=int, default=0, help="导入上限，0=不限制")

    mb_p = sub.add_parser("malwarebazaar", help="从 MalwareBazaar 下载恶意样本")
    mb_p.add_argument("--db", default="fl_samples.db")
    mb_p.add_argument("--api-key", help="MalwareBazaar API key (可选)")
    mb_p.add_argument("--limit", type=int, default=100)

    pe_p = sub.add_parser("pe", help="从 PE 文件目录导入")
    pe_p.add_argument("pe_dir", help="PE 文件目录路径")
    pe_p.add_argument("--db", default="fl_samples.db")
    pe_p.add_argument("--label", type=int, default=1, help="0=正常, 1=恶意")

    aug_p = sub.add_parser("augment", help="数据增强（噪声注入扩充样本）")
    aug_p.add_argument("--db", default="fl_samples.db")
    aug_p.add_argument("--noise-std", type=float, default=0.01,
                       help="噪声标准差，越小越接近原样本")
    aug_p.add_argument("--n-augment", type=int, default=3,
                       help="每个样本生成的增强副本数")

    gen_p = sub.add_parser("gen-behavior", help="生成合成 behavior 样本")
    gen_p.add_argument("--db", default="fl_samples.db")
    gen_p.add_argument("--n-samples", type=int, default=500)
    gen_p.add_argument("--seq-len", type=int, default=128)
    gen_p.add_argument("--feat-dim", type=int, default=64)

    pca_p = sub.add_parser("compute-pca", help="从 EMBER 数据计算 PCA 降维矩阵")
    pca_p.add_argument("jsonl", help="EMBER JSONL 文件路径")
    pca_p.add_argument("--limit", type=int, default=50000,
                       help="用于计算的样本上限")

    stats_p = sub.add_parser("stats", help="查看数据库统计")
    stats_p.add_argument("--db", default="fl_samples.db")

    args = parser.parse_args()

    if args.cmd == "ember":
        return import_ember(args)
    elif args.cmd == "malwarebazaar":
        return import_malwarebazaar(args)
    elif args.cmd == "pe":
        return import_pe_directory(args)
    elif args.cmd == "augment":
        return augment_samples(args)
    elif args.cmd == "gen-behavior":
        return generate_behavior_samples(args)
    elif args.cmd == "compute-pca":
        return compute_ember_pca(args)
    elif args.cmd == "stats":
        return show_stats(args)
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
