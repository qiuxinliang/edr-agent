#ifndef EDR_AVE_HOTFIX_H
#define EDR_AVE_HOTFIX_H

#include "edr/error.h"

struct EdrConfig;

/**
 * 将热更包（目录下 `static.onnx` / `behavior.onnx`，或单个 `.onnx` 文件）复制到 `cfg->ave.model_dir`。
 * 目录模式下若两者均不存在则返回 **`EDR_ERR_INVALID_ARG`**（避免无操作却成功）。
 * **不支持** `.avepkg` 解包；调用方应在成功后执行 `edr_ave_reload_models`。
 */
EdrError edr_ave_apply_hotfix_path(const struct EdrConfig *cfg, const char *path);

#endif
