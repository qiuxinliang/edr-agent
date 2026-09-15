#ifndef EDR_PROCESS_COMMAND_PREVIEW_H
#define EDR_PROCESS_COMMAND_PREVIEW_H

#include "edr/behavior_record.h"
#include "etw_slot_text.h"

/* Bounded hot-path preview, not an authoritative full process fact. The
 * historical process cache owns full facts; keep this cache's budget stable. */
typedef struct {
  char text[1024];
  uint8_t truncated;
} EdrProcessCommandPreview;

static inline void edr_process_command_preview_store(
    EdrProcessCommandPreview *preview, const EdrBehaviorRecord *record) {
  size_t len = strlen(record->cmdline), copied = len;
  if (!len) return;
  if (copied >= sizeof(preview->text)) {
    copied = sizeof(preview->text) - 1u;
    /* Do not leave half a UTF-8 code point at the preview boundary. */
    while (copied && ((unsigned char)record->cmdline[copied] & 0xc0u) == 0x80u)
      --copied;
  }
  memcpy(preview->text, record->cmdline, copied);
  preview->text[copied] = '\0';
  preview->truncated = (uint8_t)(copied < len ||
      edr_behavior_source_field_truncated(record, "source.cmdline"));
}

/* Caller must first prove the immutable process generation matches. */
static inline void edr_process_command_preview_fill(
    const EdrProcessCommandPreview *preview, EdrBehaviorRecord *record) {
  if (record->cmdline[0] || !preview->text[0]) return;
  snprintf(record->cmdline, sizeof(record->cmdline), "%s", preview->text);
  snprintf(record->command_line_origin, sizeof(record->command_line_origin), "%s",
           preview->truncated ? "collector_pid_cache_preview" : "collector_pid_cache");
  if (preview->truncated) edr_behavior_mark_source_truncated(record, "source.cmdline");
}

/* Command and its provenance travel together. On capacity failure retain any
 * diagnostics that fit, but never publish a preview as an unlabelled fact.
 * Used by FileRead and registry writeback, which used to drop this metadata. */
static inline EdrSlotKvResult edr_collector_slot_append_command(
    EdrEventSlot *slot, const EdrBehaviorRecord *record) {
  EdrSlotKvResult result;
  if (!record->cmdline[0]) return EDR_SLOT_KV_EMPTY;
  if (record->source_truncated_fields[0]) {
    result = edr_collector_slot_append_kv(slot, "source_truncated_fields",
                                          record->source_truncated_fields);
    if (result != EDR_SLOT_KV_APPENDED) return result;
  }
  if (record->source_completeness[0]) {
    result = edr_collector_slot_append_kv(slot, "source_completeness",
                                          record->source_completeness);
    if (result != EDR_SLOT_KV_APPENDED) return result;
  }
  if (record->command_line_origin[0]) {
    result = edr_collector_slot_append_kv(slot, "command_line_origin",
                                          record->command_line_origin);
    if (result != EDR_SLOT_KV_APPENDED) return result;
  }
  return edr_collector_slot_append_kv(slot, "cmd", record->cmdline);
}

#endif
