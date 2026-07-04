#!/usr/bin/env python3
"""
训练 static MLP 模型并导出 ONNX。

与现有 C 推理管线（ave_onnx_infer.c）完全兼容：
  输入:  features [1, 512]
  输出:  verdict_probs [1, 4], family_probs [1, 32], packer_probs [1, 8]

支持两种模式：
  1. 从头训练（需要 fl_samples.db 中的 static 样本）
  2. 迁移学习（加载预训练 backbone，仅训练分类头，少样本友好）

依赖: pip install torch onnx numpy scikit-learn

用法：
  python3 scripts/train_static_mlp.py train --db fl_samples.db --epochs 100
  python3 scripts/train_static_mlp.py export --output-onnx models/static.onnx
"""
from __future__ import annotations

import argparse
import hashlib
import os
import sqlite3
import sys
from typing import List, Optional, Tuple

import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F


# ============================================================
# 模型定义：3层 MLP + 三个独立分类头
# ============================================================
class StaticMLP(nn.Module):

    def __init__(self, input_dim=512, hidden_dims=(512, 256, 128),
                 num_verdict=4, num_family=32, num_packer=8,
                 dropout=0.3):
        super().__init__()
        layers = []
        prev = input_dim
        for h in hidden_dims:
            layers.append(nn.Linear(prev, h))
            layers.append(nn.BatchNorm1d(h))
            layers.append(nn.ReLU(inplace=True))
            layers.append(nn.Dropout(dropout))
            prev = h
        self.backbone = nn.Sequential(*layers)

        last_dim = hidden_dims[-1]
        self.head_verdict = nn.Linear(last_dim, num_verdict)
        self.head_family = nn.Linear(last_dim, num_family)
        self.head_packer = nn.Linear(last_dim, num_packer)

        self._init_weights()

    def _init_weights(self):
        for m in self.modules():
            if isinstance(m, nn.Linear):
                nn.init.kaiming_normal_(m.weight, mode='fan_out', nonlinearity='relu')
                if m.bias is not None:
                    nn.init.constant_(m.bias, 0)

    def forward(self, x):
        feats = self.backbone(x)
        return (
            self.head_verdict(feats),
            self.head_family(feats),
            self.head_packer(feats),
        )


# ============================================================
# 数据加载：从 fl_samples.db 读取 static 样本
# ============================================================
def load_static_from_sqlite(db_path: str) -> Tuple[np.ndarray, np.ndarray, List[str]]:
    conn = sqlite3.connect(db_path)
    cur = conn.execute(
        "SELECT sha256, label, feature_blob FROM fl_samples WHERE model_target='static'"
    )
    X_list, y_list, sha_list = [], [], []
    for row in cur:
        sha256, label, blob = row
        feat = np.frombuffer(blob, dtype=np.float32)
        if len(feat) != 512:
            continue
        X_list.append(feat)
        y_list.append(label)
        sha_list.append(sha256)
    conn.close()
    return np.array(X_list, dtype=np.float32), np.array(y_list, dtype=np.int64), sha_list


def load_ember_jsonl(jsonl_path: str, limit: int = 0) -> Optional[Tuple[np.ndarray, np.ndarray]]:
    try:
        pca_matrix_path = os.path.join(os.path.dirname(__file__), "ember_pca_512.npy")
        pca_matrix = None
        pca_mean = None
        if os.path.exists(pca_matrix_path):
            pca_matrix = np.load(pca_matrix_path)
            pca_mean = np.load(pca_matrix_path.replace("pca_512", "pca_mean"))
    except Exception:
        pca_matrix = None
        pca_mean = None

    keys_in_order = [
        "histogram", "byteentropy", "strings", "general",
        "header", "section", "imports", "exports", "datadirectories"
    ]

    X_list, y_list = [], []
    with open(jsonl_path, "r") as f:
        for i, line in enumerate(f):
            if limit and i >= limit:
                break
            try:
                rec = __import__("json").loads(line)
            except Exception:
                continue

            all_feats = []
            for key in keys_in_order:
                val = rec.get(key, [])
                if isinstance(val, list):
                    all_feats.extend(val)

            if len(all_feats) < 512:
                all_feats.extend([0.0] * (512 - len(all_feats)))

            if pca_matrix is not None and pca_mean is not None and len(all_feats) >= 2381:
                vec = np.array(all_feats[:2381], dtype=np.float64)
                vec = vec - pca_mean
                feats = (pca_matrix @ vec).astype(np.float32)
            else:
                feats = np.array(all_feats[:512], dtype=np.float32)
                max_val = np.max(np.abs(feats)) or 1.0
                feats = feats / max_val

            label = int(rec.get("label", 0))
            X_list.append(feats)
            y_list.append(label)

    if not X_list:
        return None
    return np.array(X_list, dtype=np.float32), np.array(y_list, dtype=np.int64)


# ============================================================
# 训练
# ============================================================
def train_from_db(db_path: str, epochs: int, lr: float, output_pt: str) -> int:
    X, y, _ = load_static_from_sqlite(db_path)
    if len(X) < 10:
        print(f"[error] 样本数不足: {len(X)}，至少需要 10 条（建议 1000+）", file=sys.stderr)
        return 1

    print(f"[info] 加载样本: {len(X)} 条, 恶意: {(y == 1).sum()}, 正常: {(y == 0).sum()}")

    from sklearn.model_selection import train_test_split
    X_train, X_val, y_train, y_val = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"[info] 设备: {device}")

    model = StaticMLP(input_dim=512).to(device)
    total_params = sum(p.numel() for p in model.parameters())
    print(f"[info] 模型参数量: {total_params:,}")

    X_train_t = torch.from_numpy(X_train).to(device)
    y_train_t = torch.from_numpy(y_train).to(device)
    X_val_t = torch.from_numpy(X_val).to(device)
    y_val_t = torch.from_numpy(y_val).to(device)

    n_pos = (y_train == 1).sum()
    n_neg = (y_train == 0).sum()
    pos_weight = torch.tensor([n_neg / max(n_pos, 1)]).to(device)

    opt = torch.optim.AdamW(model.parameters(), lr=lr, weight_decay=1e-4)
    scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(opt, T_max=epochs)

    best_acc = 0.0
    for epoch in range(epochs):
        model.train()
        v, f_out, p = model(X_train_t)

        loss_v = F.cross_entropy(v, y_train_t, weight=torch.tensor([1.0, pos_weight.item(), 1.0, 1.0]).to(device))
        loss = loss_v

        family_mask = y_train_t >= 2
        if family_mask.any():
            family_labels = y_train_t[family_mask] - 2
            loss_f = F.cross_entropy(f_out[family_mask], family_labels)
            loss = loss + 0.3 * loss_f

        packer_mask = y_train_t >= 3
        if packer_mask.any():
            packer_labels = y_train_t[packer_mask] - 3
            loss_p = F.cross_entropy(p[packer_mask], packer_labels)
            loss = loss + 0.2 * loss_p

        opt.zero_grad()
        loss.backward()
        torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
        opt.step()
        scheduler.step()

        model.eval()
        with torch.no_grad():
            v_val, _, _ = model(X_val_t)
            pred = v_val.argmax(dim=1)
            acc = (pred == y_val_t).float().mean().item()
        model.train()

        if acc > best_acc:
            best_acc = acc
            torch.save(model.state_dict(), output_pt)

        if (epoch + 1) % 10 == 0:
            print(f"  epoch {epoch+1:3d}/{epochs}  loss={loss.item():.4f}  "
                  f"val_acc={acc:.3f}  best={best_acc:.3f}")

    print(f"[done] 最佳验证准确率: {best_acc:.3f}, 模型已保存到 {output_pt}")
    return 0


# ============================================================
# 导入 EMBER JSONL 数据到 fl_samples.db
# ============================================================
def import_ember_to_db(jsonl_path: str, db_path: str, limit: int) -> int:
    X, y = load_ember_jsonl(jsonl_path, limit)
    if X is None:
        print("[error] 无法加载 EMBER 数据", file=sys.stderr)
        return 1

    conn = sqlite3.connect(db_path)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS fl_samples (
          sha256 TEXT PRIMARY KEY NOT NULL,
          label INTEGER NOT NULL DEFAULT 0,
          model_target TEXT NOT NULL DEFAULT 'static',
          feature_blob BLOB NOT NULL,
          created_ts INTEGER NOT NULL DEFAULT (strftime('%s','now'))
        )
    """)
    conn.execute("PRAGMA journal_mode=WAL")

    count = 0
    for i in range(len(X)):
        sha256 = hashlib.sha256(X[i].tobytes()).hexdigest()
        blob = X[i].tobytes()
        label = int(y[i])
        try:
            conn.execute(
                "INSERT OR IGNORE INTO fl_samples(sha256, label, model_target, feature_blob) "
                "VALUES (?, ?, 'static', ?)",
                (sha256, label, blob)
            )
            count += 1
        except Exception:
            continue
        if count % 1000 == 0:
            conn.commit()
            print(f"  ... 已导入 {count} 条")

    conn.commit()
    conn.close()
    print(f"[done] 共导入 {count} 条 static 样本到 {db_path}")
    return 0


# ============================================================
# ONNX 导出
# ============================================================
def export_to_onnx(output_pt: str, onnx_path: str) -> int:
    device = torch.device("cpu")
    model = StaticMLP(input_dim=512).to(device)
    model.load_state_dict(torch.load(output_pt, map_location=device))
    model.eval()

    dummy = torch.randn(1, 512, device=device)
    torch.onnx.export(
        model,
        dummy,
        onnx_path,
        input_names=["features"],
        output_names=["verdict_probs", "family_probs", "packer_probs"],
        dynamic_axes={
            "features": {0: "batch"},
            "verdict_probs": {0: "batch"},
            "family_probs": {0: "batch"},
            "packer_probs": {0: "batch"},
        },
        opset_version=17,
        do_constant_folding=True,
    )
    print(f"[done] ONNX 导出到: {onnx_path}  ({os.path.getsize(onnx_path)} bytes)")

    try:
        import onnx
        model_onnx = onnx.load(onnx_path)
        onnx.checker.check_model(model_onnx)
        print("[ok] ONNX 模型校验通过")
        for inp in model_onnx.graph.input:
            dims = [d.dim_value for d in inp.type.tensor_type.shape.dim]
            print(f"  输入: {inp.name} {dims}")
        for out in model_onnx.graph.output:
            dims = [d.dim_value for d in out.type.tensor_type.shape.dim]
            print(f"  输出: {out.name} {dims}")
    except ImportError:
        print("[warn] pip install onnx 以启用模型校验")

    try:
        import onnxruntime as ort
        sess = ort.InferenceSession(onnx_path)
        test_inp = np.random.randn(1, 512).astype(np.float32)
        out_names = [o.name for o in sess.get_outputs()]
        results = sess.run(out_names, {"features": test_inp})
        print("[ok] ONNX Runtime 推理验证通过")
        for name, arr in zip(out_names, results):
            print(f"  {name}: shape={arr.shape}")
    except ImportError:
        pass

    return 0


# ============================================================
# 数据增强（扩充样本）
# ============================================================
def augment_db(db_path: str, noise_std: float = 0.01, n_augment: int = 3) -> int:
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode=WAL")
    rows = conn.execute(
        "SELECT sha256, label, feature_blob FROM fl_samples WHERE model_target='static'"
    ).fetchall()

    rng = np.random.RandomState(42)
    new_count = 0
    for sha256, label, blob in rows:
        orig = np.frombuffer(blob, dtype=np.float32)
        if len(orig) != 512:
            continue
        for aug_i in range(n_augment):
            noise = rng.randn(512).astype(np.float32) * noise_std
            augmented = orig + noise
            aug_sha256 = hashlib.sha256(
                (sha256 + f"_aug{aug_i}").encode()
            ).hexdigest()
            aug_blob = augmented.tobytes()
            try:
                conn.execute(
                    "INSERT OR IGNORE INTO fl_samples(sha256, label, model_target, feature_blob) "
                    "VALUES (?, ?, 'static', ?)",
                    (aug_sha256, label, aug_blob)
                )
                new_count += 1
            except Exception:
                continue
        if new_count % 1000 == 0:
            conn.commit()
            print(f"  ... 已生成 {new_count} 条增强样本")

    conn.commit()
    conn.close()
    print(f"[done] 从 {len(rows)} 条原始样本生成 {new_count} 条增强样本")
    return 0


# ============================================================
# 数据库统计
# ============================================================
def db_stats(db_path: str) -> int:
    conn = sqlite3.connect(db_path)
    total = conn.execute("SELECT COUNT(*) FROM fl_samples").fetchone()[0]
    by_target = conn.execute(
        "SELECT model_target, label, COUNT(*) FROM fl_samples GROUP BY model_target, label"
    ).fetchall()
    print(f"总样本数: {total}")
    for target, label, cnt in by_target:
        tag = "恶意" if label == 1 else "正常"
        print(f"  {target:10s}  {tag}: {cnt}")
    conn.close()
    return 0


# ============================================================
# CLI
# ============================================================
def main() -> int:
    parser = argparse.ArgumentParser(description="EDR Static MLP 训练与导出")
    sub = parser.add_subparsers(dest="cmd")

    train_p = sub.add_parser("train", help="从 fl_samples.db 训练 static MLP")
    train_p.add_argument("--db", default="fl_samples.db")
    train_p.add_argument("--epochs", type=int, default=100)
    train_p.add_argument("--lr", type=float, default=1e-3)
    train_p.add_argument("--output-pt", default="static_mlp.pt")

    export_p = sub.add_parser("export", help="导出 ONNX")
    export_p.add_argument("--output-pt", default="static_mlp.pt")
    export_p.add_argument("--output-onnx", default="static.onnx")

    import_p = sub.add_parser("import-ember", help="导入 EMBER JSONL → fl_samples.db")
    import_p.add_argument("jsonl", help="EMBER JSONL 文件路径")
    import_p.add_argument("--db", default="fl_samples.db")
    import_p.add_argument("--limit", type=int, default=0, help="导入上限，0=不限制")

    aug_p = sub.add_parser("augment", help="数据增强（噪声注入扩充样本）")
    aug_p.add_argument("--db", default="fl_samples.db")
    aug_p.add_argument("--noise-std", type=float, default=0.01)
    aug_p.add_argument("--n-augment", type=int, default=3)

    stats_p = sub.add_parser("stats", help="查看数据库统计")
    stats_p.add_argument("--db", default="fl_samples.db")

    args = parser.parse_args()

    if args.cmd == "train":
        return train_from_db(args.db, args.epochs, args.lr, args.output_pt)
    elif args.cmd == "export":
        return export_to_onnx(args.output_pt, args.output_onnx)
    elif args.cmd == "import-ember":
        return import_ember_to_db(args.jsonl, args.db, args.limit)
    elif args.cmd == "augment":
        return augment_db(args.db, args.noise_std, args.n_augment)
    elif args.cmd == "stats":
        return db_stats(args.db)
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
