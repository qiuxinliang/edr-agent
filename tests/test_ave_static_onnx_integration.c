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

/*
 * `edr_config_load` applies the Windows listener-cache settings after a
 * successful parse.  This ONNX contract test exercises configuration solely
 * to supply AVE options; it neither owns nor needs the listener table.  Keep
 * the platform hook local to the test, as test_config_fp does, so the target
 * remains a focused ONNX link/run gate instead of pulling network-enumeration
 * and WinSock dependencies into the test binary.
 */
#ifdef _WIN32
void edr_win_listen_apply_config(const EdrConfig *cfg) { (void)cfg; }
#endif

static int fail(const char *message) {
  fprintf(stderr, "test_ave_static_onnx_integration: %s\n", message);
  edr_onnx_runtime_cleanup();
  return 1;
}

static void report_result(const EdrAveInferResult *result) {
  if (!result) {
    return;
  }
  fprintf(stderr,
          "static ONNX result: layout=%d label=%d score=%.7g detail=%s\n"
          "  verdict=[%.7g, %.7g, %.7g, %.7g]\n"
          "  family=[%.7g, %.7g]\n"
          "  packer=[%.7g, %.7g, %.7g]\n",
          result->onnx_layout, result->label, result->score, result->detail, result->verdict_probs[0],
          result->verdict_probs[1], result->verdict_probs[2], result->verdict_probs[3], result->family_probs[0],
          result->family_probs[1], result->packer_probs[0], result->packer_probs[1], result->packer_probs[2]);
}

static int write_deterministic_input(const char *path) {
  FILE *file = fopen(path, "wb");
  if (!file) {
    return 0;
  }
  for (unsigned int index = 0; index < 8192u; ++index) {
    unsigned char byte = (unsigned char)((index * 37u + 13u) & 0xffu);
    if (fputc((int)byte, file) == EOF) {
      fclose(file);
      (void)remove(path);
      return 0;
    }
  }
  if (fclose(file) != 0) {
    (void)remove(path);
    return 0;
  }
  return 1;
}

int main(void) {
  const char *input_path = "edr_static_onnx_integration_input.bin";
  EdrConfig cfg;
  EdrAveInferResult result;
  memset(&cfg, 0, sizeof(cfg));
  memset(&result, 0, sizeof(result));
  cfg.ave.scan_threads = 1;

  EdrError error = edr_onnx_runtime_load(EDR_TEST_FIXTURE_ONNX, &cfg);
  if (error != EDR_OK) {
    fprintf(stderr, "static ONNX load error=%d fixture=%s\n", (int)error, EDR_TEST_FIXTURE_ONNX);
    return fail("checked static ONNX fixture did not load");
  }
  if (!edr_onnx_runtime_ready()) {
    return fail("ONNX Runtime did not report a ready static session");
  }
  if (!write_deterministic_input(input_path)) {
    return fail("could not create deterministic static ONNX input");
  }
  error = edr_onnx_infer_file(&cfg, input_path, &result);
  if (error != EDR_OK) {
    (void)remove(input_path);
    fprintf(stderr, "static ONNX inference error=%d source=%s\n", (int)error, input_path);
    return fail("static ONNX inference did not complete");
  }
  (void)remove(input_path);
  if (result.onnx_layout != 1) {
    report_result(&result);
    return fail("static ONNX fixture did not use the named triple-output contract");
  }
  if (result.label != 0 || result.verdict_probs[0] <= result.verdict_probs[1] ||
      result.verdict_probs[0] <= result.verdict_probs[2] ||
      result.verdict_probs[0] <= result.verdict_probs[3]) {
    report_result(&result);
    return fail("static ONNX verdict output is not the deterministic fixture result");
  }
  if (result.family_probs[0] <= result.family_probs[1] ||
      result.packer_probs[2] <= result.packer_probs[0]) {
    report_result(&result);
    return fail("static ONNX family or packer output is not the deterministic fixture result");
  }
  if (strncmp(result.detail, "static_onnx triple", strlen("static_onnx triple")) != 0) {
    report_result(&result);
    return fail("static ONNX inference did not report the triple-output detail");
  }

  edr_onnx_runtime_cleanup();
  return 0;
}
