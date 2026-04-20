/**
 * 联邦学习 C0/C7：AVE_ExportFeatureVector / ExportFeatureVectorEx / ExportModelWeights / ImportModelWeights 自检。
 */
#include "edr/ave_sdk.h"
#include "edr/fl_feature_provider.h"

#include "ave_onnx_infer.h"
#include "edr/error.h"

#include <stdio.h>
#include <stdlib.h>

static int fail(const char *msg) {
  fprintf(stderr, "FAIL: %s\n", msg);
  return 1;
}

int main(void) {
  float vec[512];
  size_t sz = 1024;
  char dummy[16];

  if (AVE_ExportFeatureVector(NULL, vec) != AVE_ERR_NOT_INITIALIZED) {
    return fail("ExportFeatureVector before init should be NOT_INITIALIZED");
  }

  AVEConfig cfg = {0};
  cfg.model_dir = ".";
  cfg.max_concurrent_scans = 1;
  if (AVE_Init(&cfg) != AVE_OK) {
    return fail("AVE_Init");
  }

  if (AVE_ExportFeatureVector(NULL, vec) != AVE_ERR_INVALID_PARAM) {
    return fail("ExportFeatureVector null sha256");
  }
  if (AVE_ExportFeatureVector("not64hex", vec) != AVE_ERR_INVALID_PARAM) {
    return fail("ExportFeatureVector bad hex length");
  }

  const char *valid64 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  if (AVE_ExportFeatureVector(valid64, NULL) != AVE_ERR_INVALID_PARAM) {
    return fail("ExportFeatureVector null out");
  }
  if (AVE_ExportFeatureVector(valid64, vec) != AVE_OK) {
    return fail("ExportFeatureVector stub should return OK");
  }
  for (int i = 0; i < 512; i++) {
    if (vec[i] != 0.0f) {
      return fail("stub vector should be zeros");
    }
  }

  {
    float vex[64];
    if (AVE_ExportFeatureVectorEx(NULL, vex, 64, EDR_FL_TARGET_STATIC) != AVE_ERR_INVALID_PARAM) {
      return fail("ExportFeatureVectorEx null sha256");
    }
    if (AVE_ExportFeatureVectorEx(valid64, vex, 0, EDR_FL_TARGET_STATIC) != AVE_ERR_INVALID_PARAM) {
      return fail("ExportFeatureVectorEx dim 0");
    }
    if (AVE_ExportFeatureVectorEx(valid64, vex, 64, EDR_FL_TARGET_STATIC) != AVE_OK) {
      return fail("ExportFeatureVectorEx stub OK");
    }
  }

  {
    int st = AVE_ExportModelWeights("static", NULL, &sz);
    if (st != AVE_OK && st != AVE_ERR_NOT_IMPL) {
      return fail("ExportModelWeights static unexpected return");
    }
    if (st == AVE_OK && sz == 0u) {
      return fail("ExportModelWeights static size query should be >0 when OK");
    }
  }
  if (AVE_ExportModelWeights("behavior", dummy, &sz) != AVE_ERR_NOT_IMPL) {
    return fail("ExportModelWeights behavior without loaded model should be NOT_IMPL");
  }
  if (AVE_ImportModelWeights("static", dummy, 0) != AVE_ERR_NOT_IMPL) {
    return fail("ImportModelWeights C0 stub NOT_IMPL");
  }
  {
    char stubbuf[] = "FLSTUB1";
    if (AVE_ImportModelWeights("static", stubbuf, sizeof(stubbuf) - 1u) != AVE_OK) {
      return fail("ImportModelWeights FLSTUB1 verify path");
    }
  }
  {
    char fl2buf[] = "FL2";
    if (AVE_ImportModelWeights("static", fl2buf, 4u) != AVE_OK) {
      return fail("ImportModelWeights FL2 header verify path");
    }
  }
  {
    unsigned char fl3hdr[] = {'F', 'L', '3', 2};
    if (AVE_ImportModelWeights("static", fl3hdr, sizeof(fl3hdr)) != AVE_ERR_NOT_SUPPORTED) {
      return fail("ImportModelWeights FL3 not weight blob");
    }
  }
  if (AVE_ExportModelWeights("unknown", dummy, &sz) != AVE_ERR_INVALID_PARAM) {
    return fail("ExportModelWeights bad target");
  }

#ifdef EDR_TEST_BEH_ONNX
  {
    size_t ne = 0;
    if (AVE_ExportBehaviorFlTrainableTensors(NULL, &ne, NULL, 0) != AVE_ERR_NOT_IMPL) {
      return fail("tensor export without behavior path should be NOT_IMPL");
    }
    if (edr_onnx_behavior_load(EDR_TEST_BEH_ONNX, NULL) != EDR_OK) {
      return fail("edr_onnx_behavior_load fixture");
    }
    char man[4096];
    if (edr_onnx_behavior_export_fl_trainable_floats(NULL, &ne, man, sizeof(man)) != 0) {
      return fail("tensor export size query");
    }
    if (ne > 0u) {
      float *tmp = (float *)malloc(ne * sizeof(float));
      if (!tmp) {
        return fail("malloc tensor buf");
      }
      size_t n2 = ne;
      if (edr_onnx_behavior_export_fl_trainable_floats(tmp, &n2, NULL, 0) != 0 || n2 != ne) {
        free(tmp);
        return fail("tensor export copy");
      }
      free(tmp);
    }
    if (AVE_ExportBehaviorFlTrainableTensors(NULL, &ne, NULL, 0) != AVE_OK) {
      return fail("AVE_ExportBehaviorFlTrainableTensors size query");
    }
  }
#endif

  AVE_Shutdown();
  return 0;
}
