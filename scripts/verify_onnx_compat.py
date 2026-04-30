"""
模拟 C 代码 ave_onnx_infer.c 的 ONNX 模型加载与推理流程，
验证新导出的 static.onnx 和 behavior.onnx 的接口兼容性。
"""
import numpy as np
import onnxruntime as ort
import sys


def str_contains_ci(haystack, needle):
    return needle.lower() in haystack.lower()


def verify_static_model(onnx_path):
    print("=" * 60)
    print(f"[验证] static 模型: {onnx_path}")
    sess = ort.InferenceSession(onnx_path)

    ti = sess.get_inputs()[0]
    print(f"  输入名称: {ti.name}")
    print(f"  输入形状: {ti.shape}")
    print(f"  输入类型: {ti.type}")

    dims = ti.shape
    n_elem = 1
    for d in dims:
        if isinstance(d, str) or d is None or d <= 0:
            d_val = 1
        else:
            d_val = d
        n_elem *= d_val
    print(f"  首输入元素数: {n_elem}")

    outputs = sess.get_outputs()
    print(f"  输出数: {len(outputs)}")
    g_verdict = g_family = g_packer = None
    for o in outputs:
        nm = o.name
        shape = o.shape
        print(f"    输出: {nm:20s} shape={shape}")
        if not g_verdict and str_contains_ci(nm, "verdict"):
            g_verdict = nm
        if not g_family and str_contains_ci(nm, "family"):
            g_family = nm
        if not g_packer and str_contains_ci(nm, "packer"):
            g_packer = nm

    triple_ok = g_verdict and g_family and g_packer
    print(f"  triple 绑定: verdict='{g_verdict}' family='{g_family}' packer='{g_packer}' => {'✅' if triple_ok else '❌'}")

    test_input = np.random.randn(1, 512).astype(np.float32)
    results = sess.run([g_verdict, g_family, g_packer], {"features": test_input})

    for name, arr in zip([g_verdict, g_family, g_packer], results):
        print(f"  {name}: shape={arr.shape} min={arr.min():.4f} max={arr.max():.4f}")

    print(f"  verdict argmax: {results[0].argmax()}")
    print(f"  ✅ static 模型接口兼容验证通过")
    return triple_ok


def verify_behavior_model(onnx_path):
    print("\n" + "=" * 60)
    print(f"[验证] behavior 模型: {onnx_path}")
    sess = ort.InferenceSession(onnx_path)

    ti = sess.get_inputs()[0]
    print(f"  输入名称: {ti.name}")
    print(f"  输入形状: {ti.shape}")
    print(f"  输入类型: {ti.type}")

    dims = ti.shape
    n_elem = 1
    for d in dims:
        if isinstance(d, str) or d is None or d <= 0:
            d_val = 1
        else:
            d_val = d
        n_elem *= d_val
    print(f"  首输入元素数: {n_elem}")

    ndim = len(dims)
    has_3d = (ndim == 3)
    print(f"  维度数: {ndim} {'✅ 3D (batch,seq,feat)' if has_3d else '⚠️' }")

    outputs = sess.get_outputs()
    print(f"  输出数: {len(outputs)}")
    g_anomaly = g_tactic = None
    for o in outputs:
        nm = o.name
        shape = o.shape
        print(f"    输出: {nm:20s} shape={shape}")
        if str_contains_ci(nm, "tactic"):
            if not g_tactic:
                g_tactic = nm
        if str_contains_ci(nm, "anomaly") or str_contains_ci(nm, "anomaly_score"):
            if not g_anomaly:
                g_anomaly = nm

    dual_ok = g_anomaly and g_tactic
    print(f"  dual 绑定: anomaly='{g_anomaly}' tactic='{g_tactic}' => {'✅' if dual_ok else '❌'}")

    test_input = np.random.randn(1, 128, 64).astype(np.float32)
    results = sess.run([g_anomaly, g_tactic], {"features": test_input})

    for name, arr in zip([g_anomaly, g_tactic], results):
        print(f"  {name}: shape={arr.shape} value={arr.flatten()[:5]}...")

    print(f"  anomaly_score value: {results[0].item():.6f}")
    print(f"  ✅ behavior 模型接口兼容验证通过")
    return dual_ok


def main():
    static_path = "/tmp/static.onnx"
    behavior_path = "/tmp/behavior.onnx"

    print("EDR ONNX 模型 C 推理接口兼容性验证")
    print(f"ONNX Runtime 版本: {ort.__version__}")
    print()

    s_ok = verify_static_model(static_path)
    b_ok = verify_behavior_model(behavior_path)

    print("\n" + "=" * 60)
    print("总结:")
    print(f"  static 模型: {'✅ 兼容' if s_ok else '❌ 不兼容'}")
    print(f"  behavior 模型: {'✅ 兼容' if b_ok else '❌ 不兼容'}")
    print()

    if s_ok and b_ok:
        print("与 C 推理代码集成步骤:")
        print("  cp models/static.onnx /opt/edr/models/")
        print("  cp models/behavior.onnx /opt/edr/models/")
        print("  # 重启 edr_agent，ORT 自动加载新图，零代码改动")
    return 0 if (s_ok and b_ok) else 1


if __name__ == "__main__":
    raise SystemExit(main())
