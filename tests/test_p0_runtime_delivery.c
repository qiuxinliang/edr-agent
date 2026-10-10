/* Synthetic delivery regression: no production rule bodies are build inputs. */
#include "edr/encrypt_p0_rules.h"
#include "edr/p0_rule_ir.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int write_bytes(const char *path, const unsigned char *bytes, size_t len) {
  FILE *file = fopen(path, "wb");
  if (!file) return 0;
  int ok = fwrite(bytes, 1u, len, file) == len;
  return fclose(file) == 0 && ok;
}

int main(void) {
  static const char fixture[] =
      "{\"kind\":\"edr_p0_rule_bundle_ir_v1\",\"ir_schema_version\":8,"
      "\"rules_bundle_version\":\"synthetic-runtime-delivery\",\"rule_count\":1,"
      "\"sensor_interest_manifest_sha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\","
      "\"sensor_interest_manifest_hash_mode\":\"raw-json-v1-p0-artifact-sha256-zeroed\","
      "\"rules\":[{\"id\":\"SYNTHETIC-RUNTIME\",\"effect\":\"security_alert\","
      "\"event_type\":\"process_create\",\"condition\":{\"process_name_in\":[\"test-delivery.exe\"]}}]}";
  char directory[] = "/tmp/edr-p0-runtime-delivery-XXXXXX";
  char parent[1024], cache[1200], stage[1200], purpose_path[1400], before_sha[65] = "";
  char invalid_parent[1024], invalid_cache[1200];
  struct stat info;
  unsigned char *envelope = NULL;
  size_t envelope_len = 0u;
  const char *sha = NULL;
  EdrP0RuleIrBinding binding;
  int ok = 0;
  if (!mkdtemp(directory)) return 2;
  snprintf(parent, sizeof(parent), "%s/edr_config", directory);
  snprintf(cache, sizeof(cache), "%s/cache.enc", parent);
  snprintf(stage, sizeof(stage), "%s/stage.enc", parent);
  snprintf(invalid_parent, sizeof(invalid_parent), "%s/invalid-parent", directory);
  snprintf(invalid_cache, sizeof(invalid_cache), "%s/cache.enc", invalid_parent);
  if (setenv("EDR_P0_IR_PATH", cache, 1)) goto done;
  edr_p0_rule_ir_lazy_init();
  if (edr_p0_rule_ir_is_ready() ||
      edr_p0_rule_ir_get_binding(&binding)) goto done;
  /* The installer no longer creates edr_config by shipping rule files. The
   * production poll prepares it before the first bounded HTTP stage write. */
  if (lstat(parent, &info) == 0 ||
      !edr_p0_rule_ir_prepare_download_path(cache) ||
      lstat(parent, &info) != 0 || !S_ISDIR(info.st_mode) ||
      (info.st_mode & 0777) != 0700) goto done;
  if (edr_p0_encrypt_encrypt_edr1_for_test((const unsigned char *)fixture,
          sizeof(fixture) - 1u, &envelope, &envelope_len) != 0 ||
      !write_bytes(stage, envelope, envelope_len) ||
      !edr_p0_rule_ir_install_staged_bundle(stage, cache) ||
      !edr_p0_rule_ir_is_ready() ||
      !edr_p0_rule_ir_get_binding(&binding) ||
      binding.rule_count != 1u || strcmp(binding.rules_bundle_version, "synthetic-runtime-delivery")) goto done;
  snprintf(before_sha, sizeof(before_sha), "%s", binding.artifact_sha256);
  if (!write_bytes(invalid_parent, (const unsigned char *)"file", 4u) ||
      edr_p0_rule_ir_prepare_download_path(invalid_cache)) goto done;
  unlink(invalid_parent);
  if (symlink(parent, invalid_parent) != 0 ||
      edr_p0_rule_ir_prepare_download_path(invalid_cache) ||
      !edr_p0_rule_ir_is_ready()) goto done;
  unlink(invalid_parent);
  if (chmod(parent, 0777) != 0 ||
      edr_p0_rule_ir_prepare_download_path(cache) ||
      chmod(parent, 0700) != 0 || !edr_p0_rule_ir_is_ready()) goto done;
  envelope[envelope_len - 1u] ^= 1u;
  if (!write_bytes(stage, envelope, envelope_len) ||
      edr_p0_rule_ir_install_staged_bundle(stage, cache) ||
      !edr_p0_rule_ir_is_ready() ||
      !edr_p0_rule_ir_get_bundle_info(NULL, NULL, &sha) || strcmp(before_sha, sha)) goto done;
  edr_p0_rule_ir_shutdown();
  edr_p0_rule_ir_lazy_init();
  if (!edr_p0_rule_ir_is_ready() ||
      !edr_p0_rule_ir_get_bundle_info(NULL, NULL, &sha) || strcmp(before_sha, sha)) goto done;
  ok = 1;
done:
  edr_p0_rule_ir_shutdown();
  free(envelope);
  unlink(stage);
  unlink(cache);
  unlink(invalid_parent);
  if (before_sha[0]) {
    snprintf(purpose_path, sizeof(purpose_path), "%s.purpose-%s.edr1", cache, before_sha);
    unlink(purpose_path);
  }
  rmdir(parent);
  rmdir(directory);
  if (!ok) fprintf(stderr, "FAIL: cold readiness, delivery, rejection or cached restart\n");
  else puts("PASS: cold missing-cache-parent delivery; unsafe parents rejected; last-good offline restart; tampered update rejected");
  return ok ? 0 : 1;
}
