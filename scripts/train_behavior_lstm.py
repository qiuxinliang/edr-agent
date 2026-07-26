#!/usr/bin/env python3
"""
训练 behavior LSTM+Attention 模型并导出 ONNX。

与现有 C 推理管线（ave_onnx_infer.c）完全兼容：
  输入:  features [1, 128, 64]  — 128 步行为序列，每步 64 维特征
  输出:  anomaly_score [1, 1], tactic_probs [1, 14]

模型架构:
  LayerNorm → BiLSTM(2层) → LayerNorm → MultiHeadSelfAttn(4头)
  → GlobalMaxPool+AvgPool → MLP → anomaly_score / tactic_probs

支持:
  1. 从 fl_samples.db 加载 behavior 样本训练
  2. 无真实数据时使用合成数据验证管线

依赖: pip install torch onnx numpy scikit-learn

用法：
  python3 scripts/train_behavior_lstm.py train --db fl_samples.db --epochs 100
  python3 scripts/train_behavior_lstm.py train --synthetic-samples 500 --epochs 50
  python3 scripts/train_behavior_lstm.py export --output-onnx models/behavior.onnx
"""
from __future__ import annotations

import argparse
import os
import sqlite3
import sys
from typing import Optional, Tuple

import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.nn.utils.rnn import pad_sequence


# ============================================================
# 模型定义: BiLSTM + MultiHeadAttention + 双输出头
# ============================================================
class BehaviorLSTM(nn.Module):

    def __init__(self, feat_dim=64, lstm_hidden=128, lstm_layers=2,
                 attn_heads=4, mlp_hidden=128, dropout=0.2):
        super().__init__()
        self.feat_dim = feat_dim
        self.lstm_hidden = lstm_hidden

        self.input_norm = nn.LayerNorm(feat_dim)

        self.lstm = nn.LSTM(
            input_size=feat_dim,
            hidden_size=lstm_hidden,
            num_layers=lstm_layers,
            batch_first=True,
            bidirectional=True,
            dropout=dropout if lstm_layers > 1 else 0.0,
        )
        lstm_out_dim = lstm_hidden * 2

        self.lstm_norm = nn.LayerNorm(lstm_out_dim)

        self.attn = nn.MultiheadAttention(
            embed_dim=lstm_out_dim,
            num_heads=attn_heads,
            dropout=dropout,
            batch_first=True,
        )

        pool_dim = lstm_out_dim * 2

        self.mlp = nn.Sequential(
            nn.Linear(pool_dim, mlp_hidden),
            nn.ReLU(inplace=True),
            nn.Dropout(dropout),
        )

        self.head_anomaly = nn.Linear(mlp_hidden, 1)
        self.head_tactic = nn.Linear(mlp_hidden, 14)

        self._init_weights()

    def _init_weights(self):
        for name, param in self.lstm.named_parameters():
            if "weight_ih" in name:
                nn.init.xavier_uniform_(param)
            elif "weight_hh" in name:
                nn.init.orthogonal_(param)
            elif "bias" in name:
                n = param.size(0)
                param.data.fill_(0)
                param.data[n // 4: n // 2].fill_(1)
        for m in self.modules():
            if isinstance(m, nn.Linear) and m is not self.head_anomaly and m is not self.head_tactic:
                nn.init.kaiming_normal_(m.weight, mode='fan_out', nonlinearity='relu')
                if m.bias is not None:
                    nn.init.constant_(m.bias, 0)
        nn.init.xavier_uniform_(self.head_anomaly.weight)
        nn.init.constant_(self.head_anomaly.bias, 0)
        nn.init.xavier_uniform_(self.head_tactic.weight)
        nn.init.constant_(self.head_tactic.bias, 0)

    def forward(self, x):
        x = self.input_norm(x)

        lstm_out, _ = self.lstm(x)
        lstm_out = self.lstm_norm(lstm_out)

        attn_out, _ = self.attn(lstm_out, lstm_out, lstm_out)

        pooled_max, _ = attn_out.max(dim=1)
        pooled_avg = attn_out.mean(dim=1)
        pooled = torch.cat([pooled_max, pooled_avg], dim=1)

        feats = self.mlp(pooled)

        anomaly = self.head_anomaly(feats)
        tactic = self.head_tactic(feats)

        return anomaly, tactic


# ============================================================
# 1D-TemporalCNN 备选模型（无需 LSTM，兼容性更好的降级方案）
# ============================================================
class BehaviorCNN(nn.Module):

    def __init__(self, feat_dim=64, mlp_hidden=128, dropout=0.2):
        super().__init__()
        self.input_norm = nn.LayerNorm(feat_dim)

        self.conv = nn.Sequential(
            nn.Conv1d(feat_dim, 128, kernel_size=3, padding=1),
            nn.BatchNorm1d(128),
            nn.ReLU(inplace=True),
            nn.Conv1d(128, 128, kernel_size=5, padding=2),
            nn.BatchNorm1d(128),
            nn.ReLU(inplace=True),
            nn.Conv1d(128, 256, kernel_size=7, padding=3),
            nn.BatchNorm1d(256),
            nn.ReLU(inplace=True),
        )

        pool_dim = 256 * 2

        self.mlp = nn.Sequential(
            nn.Linear(pool_dim, mlp_hidden),
            nn.ReLU(inplace=True),
            nn.Dropout(dropout),
        )

        self.head_anomaly = nn.Linear(mlp_hidden, 1)
        self.head_tactic = nn.Linear(mlp_hidden, 14)

        self._init_weights()

    def _init_weights(self):
        for m in self.modules():
            if isinstance(m, nn.Conv1d):
                nn.init.kaiming_normal_(m.weight, mode='fan_out', nonlinearity='relu')
            elif isinstance(m, nn.Linear) and m is not self.head_anomaly and m is not self.head_tactic:
                nn.init.kaiming_normal_(m.weight, mode='fan_out', nonlinearity='relu')
                if m.bias is not None:
                    nn.init.constant_(m.bias, 0)
        nn.init.xavier_uniform_(self.head_anomaly.weight)
        nn.init.constant_(self.head_anomaly.bias, 0)
        nn.init.xavier_uniform_(self.head_tactic.weight)
        nn.init.constant_(self.head_tactic.bias, 0)

    def forward(self, x):
        x = self.input_norm(x)
        x = x.permute(0, 2, 1)

        conv_out = self.conv(x)

        pooled_max, _ = conv_out.max(dim=2)
        pooled_avg = conv_out.mean(dim=2)
        pooled = torch.cat([pooled_max, pooled_avg], dim=1)

        feats = self.mlp(pooled)

        anomaly = self.head_anomaly(feats)
        tactic = self.head_tactic(feats)

        return anomaly, tactic


# ============================================================
# 数据加载
# ============================================================
def load_behavior_from_sqlite(db_path: str, seq_len: int = 128,
                              feat_dim: int = 64) -> Tuple[np.ndarray, np.ndarray]:
    conn = sqlite3.connect(db_path)
    cur = conn.execute(
        "SELECT sha256, label, feature_blob FROM fl_samples WHERE model_target='behavior'"
    )
    sequences, labels = [], []
    for row in cur:
        _, label, blob = row
        feat = np.frombuffer(blob, dtype=np.float32)
        expected = seq_len * feat_dim
        if len(feat) == expected:
            feat = feat.reshape(seq_len, feat_dim)
        elif len(feat) % feat_dim == 0:
            actual_seq = len(feat) // feat_dim
            feat = feat.reshape(actual_seq, feat_dim)
            if actual_seq > seq_len:
                feat = feat[-seq_len:, :]
            else:
                pad = np.zeros((seq_len - actual_seq, feat_dim), dtype=np.float32)
                feat = np.concatenate([feat, pad], axis=0)
        else:
            continue
        sequences.append(feat)
        labels.append(label)
    conn.close()
    return np.array(sequences, dtype=np.float32), np.array(labels, dtype=np.int64)


def generate_synthetic_behavior(n_samples: int = 500, seq_len: int = 128,
                                feat_dim: int = 64) -> Tuple[np.ndarray, np.ndarray]:
    """
    生成合成行为序列数据。
    正常序列: 低方差、平稳
    恶意序列: 特征突变多，后半段异常 spike
    """
    rng = np.random.RandomState(42)
    X, y = [], []

    for i in range(n_samples):
        is_malicious = rng.rand() < 0.3
        if is_malicious:
            seq = rng.randn(seq_len, feat_dim) * 0.5
            spike_start = seq_len * 3 // 4
            seq[spike_start:, :8] += rng.randn(seq_len - spike_start, 8) * 2.0
            seq[:, 10:14] *= 1.5
            label = 1
        else:
            seq = rng.randn(seq_len, feat_dim) * 0.3
            for t in range(1, seq_len):
                seq[t] = 0.7 * seq[t - 1] + 0.3 * seq[t]
            label = 0
        X.append(seq)
        y.append(label)

    return np.array(X, dtype=np.float32), np.array(y, dtype=np.int64)


# ============================================================
# 训练
# ============================================================
def train_model(args) -> int:
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"[info] 设备: {device}")

    if os.path.exists(args.db):
        X, y = load_behavior_from_sqlite(args.db, args.seq_len, args.feat_dim)
        print(f"[info] 从 {args.db} 加载 {len(X)} 条 behavior 样本")
    else:
        print(f"[warn] {args.db} 不存在，使用合成数据训练演示模型")
        X, y = generate_synthetic_behavior(args.synthetic_samples, args.seq_len, args.feat_dim)
        print(f"[info] 生成 {len(X)} 条合成样本")

    if len(X) < 10:
        print(f"[error] 样本数不足: {len(X)}", file=sys.stderr)
        return 1

    from sklearn.model_selection import train_test_split
    X_train, X_val, y_train, y_val = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    n_pos = (y_train == 1).sum()
    n_neg = (y_train == 0).sum()
    print(f"[info] 训练集: {len(X_train)} (恶意:{n_pos} 正常:{n_neg}), 验证集: {len(X_val)}")

    if args.model_type == "cnn":
        model = BehaviorCNN(feat_dim=args.feat_dim, dropout=args.dropout)
    else:
        model = BehaviorLSTM(feat_dim=args.feat_dim, dropout=args.dropout)

    model = model.to(device)
    total_params = sum(p.numel() for p in model.parameters())
    print(f"[info] 模型类型: {args.model_type}, 参数量: {total_params:,}")

    X_train_t = torch.from_numpy(X_train).to(device)
    y_train_t = torch.from_numpy(y_train).float().to(device)
    X_val_t = torch.from_numpy(X_val).to(device)
    y_val_t = torch.from_numpy(y_val).float().to(device)

    pos_weight = torch.tensor([n_neg / max(n_pos, 1)]).to(device)
    bce_loss = nn.BCEWithLogitsLoss(pos_weight=pos_weight)

    opt = torch.optim.AdamW(model.parameters(), lr=args.lr, weight_decay=1e-4)
    scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(opt, T_max=args.epochs)

    best_auc = 0.0
    for epoch in range(args.epochs):
        model.train()
        perm = torch.randperm(len(X_train_t))
        total_loss = 0.0
        n_batches = 0

        for i in range(0, len(X_train_t), args.batch_size):
            idx = perm[i:i + args.batch_size]
            bx = X_train_t[idx]
            by = y_train_t[idx]

            anomaly, tactic = model(bx)
            loss = bce_loss(anomaly.squeeze(-1), by)

            opt.zero_grad()
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            opt.step()

            total_loss += loss.item()
            n_batches += 1

        scheduler.step()

        model.eval()
        with torch.no_grad():
            anomaly_val, _ = model(X_val_t)
            probs = torch.sigmoid(anomaly_val.squeeze(-1)).cpu().numpy()
            try:
                from sklearn.metrics import roc_auc_score
                auc = roc_auc_score(y_val, probs)
            except ValueError:
                auc = 0.5
            pred = (probs > 0.5).astype(np.float32)
            acc = (pred == y_val).mean()
        model.train()

        if auc > best_auc:
            best_auc = auc
            torch.save(model.state_dict(), args.output_pt)

        if (epoch + 1) % 10 == 0:
            avg_loss = total_loss / max(n_batches, 1)
            print(f"  epoch {epoch+1:3d}/{args.epochs}  loss={avg_loss:.4f}  "
                  f"val_auc={auc:.3f}  val_acc={acc:.3f}  best_auc={best_auc:.3f}")

    print(f"[done] 最佳验证 AUC: {best_auc:.3f}, 模型已保存到 {args.output_pt}")
    return 0


# ============================================================
# ONNX 导出
# ============================================================
def export_to_onnx(args) -> int:
    device = torch.device("cpu")

    if args.model_type == "cnn":
        model = BehaviorCNN(feat_dim=args.feat_dim)
    else:
        model = BehaviorLSTM(feat_dim=args.feat_dim)

    model.load_state_dict(torch.load(args.output_pt, map_location=device))
    model.eval()

    dummy = torch.randn(1, args.seq_len, args.feat_dim, device=device)

    torch.onnx.export(
        model,
        dummy,
        args.output_onnx,
        input_names=["features"],
        output_names=["anomaly_score", "tactic_probs"],
        dynamic_axes={
            "features": {0: "batch"},
            "anomaly_score": {0: "batch"},
            "tactic_probs": {0: "batch"},
        },
        opset_version=17,
        do_constant_folding=True,
    )
    print(f"[done] ONNX 导出到: {args.output_onnx}  ({os.path.getsize(args.output_onnx)} bytes)")

    try:
        import onnx
        model_onnx = onnx.load(args.output_onnx)
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
        sess = ort.InferenceSession(args.output_onnx)
        test_inp = np.random.randn(1, args.seq_len, args.feat_dim).astype(np.float32)
        out_names = [o.name for o in sess.get_outputs()]
        results = sess.run(out_names, {"features": test_inp})
        print("[ok] ONNX Runtime 推理验证通过")
        for name, arr in zip(out_names, results):
            print(f"  {name}: shape={arr.shape}")
    except ImportError:
        pass

    return 0


# ============================================================
# CLI
# ============================================================
def main() -> int:
    parser = argparse.ArgumentParser(description="EDR Behavior LSTM 训练与导出")
    sub = parser.add_subparsers(dest="cmd")

    train_p = sub.add_parser("train", help="训练 behavior 模型")
    train_p.add_argument("--db", default="fl_samples.db")
    train_p.add_argument("--seq-len", type=int, default=128)
    train_p.add_argument("--feat-dim", type=int, default=64)
    train_p.add_argument("--epochs", type=int, default=100)
    train_p.add_argument("--lr", type=float, default=1e-3)
    train_p.add_argument("--batch-size", type=int, default=32)
    train_p.add_argument("--dropout", type=float, default=0.2)
    train_p.add_argument("--synthetic-samples", type=int, default=500,
                         help="无真实数据时生成的合成样本数")
    train_p.add_argument("--model-type", choices=["lstm", "cnn"], default="lstm",
                         help="模型类型: lstm (时序建模强) / cnn (兼容性更好)")
    train_p.add_argument("--output-pt", default="behavior_model.pt")

    export_p = sub.add_parser("export", help="导出 ONNX")
    export_p.add_argument("--output-pt", default="behavior_model.pt")
    export_p.add_argument("--output-onnx", default="behavior.onnx")
    export_p.add_argument("--seq-len", type=int, default=128)
    export_p.add_argument("--feat-dim", type=int, default=64)
    export_p.add_argument("--model-type", choices=["lstm", "cnn"], default="lstm")

    args = parser.parse_args()

    if args.cmd == "train":
        return train_model(args)
    elif args.cmd == "export":
        return export_to_onnx(args)
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
