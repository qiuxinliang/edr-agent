#!/usr/bin/env python3
"""生成 tests/fixtures/behavior_dual_minimal.onnx：64 维输入 + anomaly_score + tactic_probs（14）。"""
from __future__ import annotations

import os
import random
import sys

try:
    from onnx import TensorProto, helper, save_model
except ImportError:
    print("需要: pip install onnx", file=sys.stderr)
    sys.exit(1)


def f32_list(n: int, seed: int) -> list[float]:
    rng = random.Random(seed)
    return [rng.gauss(0.0, 0.001) for _ in range(n)]


def main() -> int:
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    out = os.path.join(root, "tests", "fixtures", "behavior_dual_minimal.onnx")
    os.makedirs(os.path.dirname(out), exist_ok=True)

    # 均值头：与 1×64 特征相乘得标量异常分
    w_mean = [1.0 / 64.0] * 64
    w_t = f32_list(64 * 14, 46)
    b_t = [0.0] * 14
    b_t[0] = 0.55

    tensors = [
        helper.make_tensor("W_mean", TensorProto.FLOAT, [64, 1], w_mean),
        helper.make_tensor("W_t", TensorProto.FLOAT, [64, 14], w_t),
        helper.make_tensor("b_t", TensorProto.FLOAT, [14], b_t),
    ]

    features = helper.make_tensor_value_info("features", TensorProto.FLOAT, [1, 64])
    anomaly_score = helper.make_tensor_value_info("anomaly_score", TensorProto.FLOAT, [1, 1])
    tactic_probs = helper.make_tensor_value_info("tactic_probs", TensorProto.FLOAT, [1, 14])

    nodes = [
        helper.make_node("MatMul", ["features", "W_mean"], ["anomaly_score"]),
        helper.make_node("MatMul", ["features", "W_t"], ["_logits"]),
        helper.make_node("Add", ["_logits", "b_t"], ["tactic_probs"]),
    ]

    graph = helper.make_graph(
        nodes,
        "behavior_dual_minimal",
        [features],
        [anomaly_score, tactic_probs],
        initializer=tensors,
    )
    model = helper.make_model_gen_version(graph, opset_imports=[helper.make_opsetid("", 17)])
    save_model(model, out)
    print("wrote", out, "bytes", os.path.getsize(out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
