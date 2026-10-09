#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../src/preprocess/parent_context_snapshot.h"

static uint64_t filetime(uint64_t ns) {
  return UINT64_C(116444736000000000) + ns / 100u;
}
static void reset(void) { edr_pt_cache_shutdown(); edr_pt_cache_init(); }
static void put(uint32_t pid, uint64_t key, uint64_t birth, const char *name,
                 const char *command) {
  assert(edr_pt_cache_put_generation(pid, 0u, name, command, name, NULL,
      birth, key, filetime(birth)) == 0);
}
static EdrBehaviorRecord *child(uint64_t birth) {
  EdrBehaviorRecord *r = calloc(1u, sizeof(*r)); assert(r);
  edr_behavior_record_init(r); r->type = EDR_EVENT_PROCESS_CREATE;
  r->pid = 7002u; r->ppid = 7001u; r->parent_pid_state = EDR_PARENT_PID_KNOWN;
  r->process_start_key = 200u; r->process_creation_filetime_100ns = filetime(birth);
  r->event_time_ns = (int64_t)birth;
  strcpy(r->process_name, "powershell.exe");
  strcpy(r->cmdline, "powershell.exe -enc QQ==");
  strcpy(r->exe_path, "C:/isolated/powershell.exe");
  strcpy(r->image_path_raw, r->exe_path); strcpy(r->image_path_canonical, r->exe_path);
  strcpy(r->image_path_resolution_status, "RESOLVED");
  strcpy(r->image_path_resolution_source, "synthetic_fixture");
  strcpy(r->endpoint_id, "synthetic-parent-audit-endpoint");
  strcpy(r->tenant_id, "synthetic-parent-audit-tenant");
  return r;
}
static void save_record(const char *directory, const char *name, EdrBehaviorRecord *r) {
  if (!directory) return;
  char path[2048]; assert(snprintf(path, sizeof(path), "%s/%s", directory, name) > 0);
  FILE *f = fopen(path, "wb"); assert(f); assert(fwrite(r, sizeof(*r), 1u, f) == 1u);
  assert(fclose(f) == 0);
}

int main(int argc, char **argv) {
  const uint64_t a = UINT64_C(2000000000000000000);
  const uint64_t i = a + UINT64_C(2000000000);
  const uint64_t c = a + UINT64_C(3000000000);
  const uint64_t b = a + UINT64_C(4000000000);
  const char *output_directory = argc == 2 ? argv[1] : NULL;
  ProcessTreeEntry parent;
  EdrBehaviorRecord *r;

  reset(); put(7001u, 100u, a, "parent-A.exe", "A_SYNTHETIC_TEXT");
  put(7001u, 300u, b, "parent-B.exe", "B_SYNTHETIC_TEXT");
  assert(edr_pt_cache_snapshot_parent_at(7001u, c, &parent) == -2);
  r = child(c); assert(r->ppid == 7001u && r->parent_pid_state == EDR_PARENT_PID_KNOWN);
  assert(!r->parent_name[0] && !r->parent_path[0] && !r->parent_cmdline[0]);
  strcpy(r->event_id, "synthetic-parent-fixed-inferred-gap");
  strcpy(r->parent_resolution_source, "parent_generation_unproven");
  strcpy(r->parent_resolution_status, "NOT_EVALUABLE");
  save_record(output_directory, "inferred-gap.synthetic.bin", r); free(r);

  reset(); put(7001u, 100u, a, "parent-A.exe", "A_SYNTHETIC_TEXT");
  assert(edr_pt_cache_mark_exit_generation(7001u, 100u, c + 100u) == 0);
  put(7001u, 300u, b, "parent-B.exe", "B_SYNTHETIC_TEXT");
  assert(edr_pt_cache_snapshot_parent_at(7001u, c, &parent) == 0);
  assert(parent.exit_time_observed && parent.process_start_key == 100u);
  r = child(c); assert(p0_adopt_parent_snapshot(r, &parent, c, 0));
  assert(!strcmp(r->parent_name, "parent-A.exe") && !strcmp(r->parent_path, "parent-A.exe"));
  assert(!strcmp(r->parent_cmdline, "A_SYNTHETIC_TEXT"));
  assert(!strcmp(r->parent_resolution_source, "process_tree_cache_verified"));
  strcpy(r->event_id, "synthetic-parent-fixed-proved-parent");
  save_record(output_directory, "proved-parent.synthetic.bin", r); free(r);

  reset(); put(7001u, 150u, i, "parent-I.exe", "I_SYNTHETIC_TEXT");
  assert(edr_pt_cache_snapshot_parent_at(7001u, c, &parent) == -2);
  assert(edr_pt_cache_mark_alive_generation(7001u, 150u, filetime(i), c + 100u) == 0);
  assert(edr_pt_cache_snapshot_parent_at(7001u, c, &parent) == 0);
  r = child(c); assert(p0_adopt_parent_snapshot(r, &parent, c, 0));
  assert(r->parent_process_start_key == 150u && !strcmp(r->parent_cmdline, "I_SYNTHETIC_TEXT")); free(r);

  /* The adopted name/path/command are the same immutable snapshot even when
   * another metadata writer runs after selection. No second PID-only fill. */
  put(7001u, 100u, a, "late-parent-A.exe", "LATE_A_SYNTHETIC_TEXT");
  r = child(c); assert(p0_adopt_parent_snapshot(r, &parent, c, 0));
  assert(r->parent_process_start_key == 150u && !strcmp(r->parent_name, "parent-I.exe") &&
      !strcmp(r->parent_path, "parent-I.exe") && !strcmp(r->parent_cmdline, "I_SYNTHETIC_TEXT")); free(r);

  reset(); put(7001u, 100u, a, "parent-A.exe", "A_SYNTHETIC_TEXT");
  assert(edr_pt_cache_mark_alive_generation(7001u, 100u, filetime(a), c) == 0);
  put(7001u, 101u, a, "ambiguous.exe", "CONTRADICTORY_SYNTHETIC_TEXT");
  assert(edr_pt_cache_snapshot_parent_at(7001u, c, &parent) == -2);
  assert(edr_pt_cache_mark_alive_generation(7001u, 101u, filetime(a), c) != 0);
  assert(edr_pt_cache_snapshot_generation_at(7001u, 100u, a, &parent) == 0);
  assert(parent.generation_conflict);
  r = child(c); assert(!p0_adopt_parent_snapshot(r, &parent, c, 1));
  assert(r->ppid == 7001u && r->parent_pid_state == EDR_PARENT_PID_KNOWN &&
         !r->parent_name[0] && !r->parent_cmdline[0]); free(r);

  reset(); put(7001u, 100u, a, "parent-A.exe", "A_SYNTHETIC_TEXT");
  assert(edr_pt_cache_mark_alive_generation(7001u, 100u, filetime(a), c) == 0);
  put(7001u, 150u, i, "overlapping.exe", "OVERLAP_SYNTHETIC_TEXT");
  assert(edr_pt_cache_snapshot_parent_at(7001u, c, &parent) == -2);

  reset(); assert(edr_pt_cache_put_generation_with_parent_state(7002u, 299u,
      "child", NULL, "child", NULL, c, 200u, filetime(c), 0u, EDR_PARENT_PID_KNOWN) == 0);
  assert(edr_pt_cache_put_generation_with_parent_state(7002u, 0u, NULL, NULL,
      NULL, NULL, c + 100u, 200u, filetime(c), 0u, EDR_PARENT_PID_UNKNOWN) == 0);
  assert(edr_pt_cache_snapshot_generation_at(7002u, 200u, c + 100u, &parent) == 0);
  assert(parent.ppid == 299u && parent.parent_pid_state == EDR_PARENT_PID_KNOWN);
  assert(edr_pt_cache_put_generation_with_parent_state(7002u, 4242u, NULL, NULL,
      NULL, NULL, c + 200u, 200u, filetime(c), 0u, EDR_PARENT_PID_KNOWN) == 0);
  assert(edr_pt_cache_put_generation_with_parent_state(7002u, 299u, NULL, NULL,
      NULL, NULL, c + 300u, 200u, filetime(c), 0u, EDR_PARENT_PID_KNOWN) == 0);
  assert(edr_pt_cache_snapshot_generation_at(7002u, 200u, c + 300u, &parent) == 0);
  assert(parent.ppid == 299u && parent.parent_pid_state == EDR_PARENT_PID_CONFLICT);
  r = child(c); r->parent_pid_state = EDR_PARENT_PID_CONFLICT;
  assert(!p0_adopt_parent_snapshot(r, &parent, c, 0) && r->parent_pid_state == EDR_PARENT_PID_CONFLICT); free(r);
  edr_pt_cache_shutdown(); puts("test_parent_context_binding: ok"); return 0;
}
