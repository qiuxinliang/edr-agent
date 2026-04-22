#!/usr/bin/env python3
"""生成 tests/fixtures/behavior_seq128_dual_minimal.onnx：输入 (1,128,64)，权重仅 64×1 / 64×14。

须将 **b_t** 经 **Add** 接到 tactic 支路；若只放在 initializer 而不连线，ORT 会剔除该张量，
ReduceMean 后 logits 可正可负，集成测试 `tactic_probs[0] > 0` 不稳定（与 ORT 版本无关）。
与 **gen_minimal_behavior_dual_onnx.py** 中 MatMul+Add 结构对齐。
"""
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
    out = os.path.join(root, "tests", "fixtures", "behavior_seq128_dual_minimal.onnx")
    os.makedirs(os.path.dirname(out), exist_ok=True)

    shape_128_64 = helper.make_tensor("shape_128_64", TensorProto.INT64, [2], [128, 64])
    w_mean = [1.0 / 64.0] * 64
    w_t = f32_list(64 * 14, 47)
    b_t = [0.0] * 14
    b_t[0] = 0.52

    tensors = [
        shape_128_64,
        helper.make_tensor("W_mean", TensorProto.FLOAT, [64, 1], w_mean),
        helper.make_tensor("W_t", TensorProto.FLOAT, [64, 14], w_t),
        helper.make_tensor("b_t", TensorProto.FLOAT, [14], b_t),
    ]

    features = helper.make_tensor_value_info("features", TensorProto.FLOAT, [1, 128, 64])
    anomaly_score = helper.make_tensor_value_info("anomaly_score", TensorProto.FLOAT, [1, 1])
    tactic_probs = helper.make_tensor_value_info("tactic_probs", TensorProto.FLOAT, [1, 14])

    nodes = [
        helper.make_node("Reshape", ["features", "shape_128_64"], ["X"]),
        helper.make_node("MatMul", ["X", "W_mean"], ["z128"]),
        helper.make_node("ReduceMean", ["z128"], ["anomaly_score"], axes=[0], keepdims=True),
        helper.make_node("MatMul", ["X", "W_t"], ["Y128"]),
        helper.make_node("ReduceMean", ["Y128"], ["t14"], axes=[0], keepdims=False),
        helper.make_node("Add", ["t14", "b_t"], ["t14b"]),
        helper.make_node("Reshape", ["t14b", "shape_1_14"], ["tactic_probs"]),
    ]
    shape_1_14 = helper.make_tensor("shape_1_14", TensorProto.INT64, [2], [1, 14])
    tensors.append(shape_1_14)

    graph = helper.make_graph(
        nodes,
        "behavior_seq128_dual_minimal",
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
