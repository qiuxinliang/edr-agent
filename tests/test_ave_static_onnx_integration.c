/*
 * Release gate for the checked static_triple_minimal.onnx fixture.
 *
 * This deliberately loads the same fixture that the Windows release workflow
 * pins by SHA-256.  Merely compiling against ONNX Runtime is insufficient:
 * the test proves that the model can be opened and that the Agent's named
 * three-output path (verdict/family/packer) executes successfully.
 */
#include "ave_onnx_infer.h"
#include "edr/ave.h"
#include "edr/config.h"
#include "edr/error.h"

#include <stdio.h>
#include <string.h>

#ifndef EDR_TEST_FIXTURE_ONNX
#error "EDR_TEST_FIXTURE_ONNX must name the checked static ONNX fixture"
#endif

static int fail(const char *message) {
  fprintf(stderr, "test_ave_static_onnx_integration: %s\n", message);
  edr_onnx_runtime_cleanup();
  return 1;
}

int main(void) {
  EdrConfig cfg;
  EdrAveInferResult result;
  memset(&cfg, 0, sizeof(cfg));
  memset(&result, 0, sizeof(result));
  cfg.ave.scan_threads = 1;

  if (edr_onnx_runtime_load(EDR_TEST_FIXTURE_ONNX, &cfg) != EDR_OK) {
    return fail("checked static ONNX fixture did not load");
  }
  if (!edr_onnx_runtime_ready()) {
    return fail("ONNX Runtime did not report a ready static session");
  }
  if (edr_onnx_infer_file(&cfg, __FILE__, &result) != EDR_OK) {
    return fail("static ONNX inference did not complete");
  }
  if (result.onnx_layout != 1) {
    return fail("static ONNX fixture did not use the named triple-output contract");
  }
  if (result.label != 0 || result.verdict_probs[0] <= result.verdict_probs[1] ||
      result.verdict_probs[0] <= result.verdict_probs[2] ||
      result.verdict_probs[0] <= result.verdict_probs[3]) {
    return fail("static ONNX verdict output is not the deterministic fixture result");
  }
  if (result.family_probs[0] <= result.family_probs[1] ||
      result.packer_probs[2] <= result.packer_probs[0]) {
    return fail("static ONNX family or packer output is not the deterministic fixture result");
  }
  if (strncmp(result.detail, "static_onnx triple", strlen("static_onnx triple")) != 0) {
    return fail("static ONNX inference did not report the triple-output detail");
  }

  edr_onnx_runtime_cleanup();
  return 0;
}
