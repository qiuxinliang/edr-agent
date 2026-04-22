#!/usr/bin/env python3
"""生成 tests/fixtures/static_triple_minimal.onnx（仅依赖 onnx 包，无需 numpy）。"""
from __future__ import annotations

import os
import random
import struct
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
    out = os.path.join(root, "tests", "fixtures", "static_triple_minimal.onnx")
    os.makedirs(os.path.dirname(out), exist_ok=True)

    Wv = f32_list(512 * 4, 42)
    bv = [2.0, 0.5, 0.3, 0.1]
    Wf = f32_list(512 * 32, 43)
    bf = [0.0] * 32
    bf[0] = 0.55
    Wp = f32_list(512 * 8, 44)
    bp = [0.0] * 8
    bp[2] = 0.65

    tensors = [
        helper.make_tensor("Wv", TensorProto.FLOAT, [512, 4], Wv),
        helper.make_tensor("bv", TensorProto.FLOAT, [4], bv),
        helper.make_tensor("Wf", TensorProto.FLOAT, [512, 32], Wf),
        helper.make_tensor("bf", TensorProto.FLOAT, [32], bf),
        helper.make_tensor("Wp", TensorProto.FLOAT, [512, 8], Wp),
        helper.make_tensor("bp", TensorProto.FLOAT, [8], bp),
    ]

    features = helper.make_tensor_value_info("features", TensorProto.FLOAT, [1, 512])
    verdict = helper.make_tensor_value_info("verdict_probs", TensorProto.FLOAT, [1, 4])
    family = helper.make_tensor_value_info("family_probs", TensorProto.FLOAT, [1, 32])
    packer = helper.make_tensor_value_info("packer_probs", TensorProto.FLOAT, [1, 8])

    nodes = [
        helper.make_node("MatMul", ["features", "Wv"], ["_mv"]),
        helper.make_node("Add", ["_mv", "bv"], ["verdict_probs"]),
        helper.make_node("MatMul", ["features", "Wf"], ["_mf"]),
        helper.make_node("Add", ["_mf", "bf"], ["family_probs"]),
        helper.make_node("MatMul", ["features", "Wp"], ["_mp"]),
        helper.make_node("Add", ["_mp", "bp"], ["packer_probs"]),
    ]

    graph = helper.make_graph(
        nodes,
        "static_triple_minimal",
        [features],
        [verdict, family, packer],
        initializer=tensors,
    )
    model = helper.make_model_gen_version(graph, opset_imports=[helper.make_opsetid("", 17)])
    save_model(model, out)
    print("wrote", out, "bytes", os.path.getsize(out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
