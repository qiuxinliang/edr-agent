/**
 * 可选 LibTorch：对 (N×dim) 特征矩阵按行维求均值（与纯 C 路径数值一致，便于后续接入真实 backward）。
 * T-015：`[fl.frozen_layers]` 在 **全图反向 / 按张量训练** 路径上应对 ONNX 子模块 `requires_grad_(false)`；
 * 当前文件仅为 **reduce_mean**，冻结名由配置解析并经 HTTP `frozen_layer_names` 上报，见 `fl_frozen_layers.c`。
 */
#include <torch/torch.h>

#include <cstring>

extern "C" int fl_local_train_torch_reduce_mean(const float *matrix, size_t n_rows, size_t dim,
                                                float *out_mean) {
  if (!matrix || !out_mean || n_rows == 0u || dim == 0u || dim > 8192u) {
    return -1;
  }
  try {
    torch::Tensor t = torch::from_blob(const_cast<float *>(matrix), {(long)n_rows, (long)dim},
                                       torch::TensorOptions().dtype(torch::kFloat32))
                          .clone();
    torch::Tensor m = t.mean(0);
    std::memcpy(out_mean, m.data_ptr<float>(), dim * sizeof(float));
    return 0;
  } catch (...) {
    return -2;
  }
}
