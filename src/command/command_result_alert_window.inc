/* Called only after checking the signed purpose, command type and byte cap.
 * Validate the entire closed receipt before copying it into the durable result.
 * Every allowed key is required on its branch, so an extra or missing key fails. */
static int window_literal_ip(const char *address) {
  unsigned char binary[16];
  if (!address || !*address || strchr(address, '%')) return 0;
#ifdef _WIN32
  return InetPtonA(AF_INET, address, binary) == 1 || InetPtonA(AF_INET6, address, binary) == 1;
#else
  return inet_pton(AF_INET, address, binary) == 1 || inet_pton(AF_INET6, address, binary) == 1;
#endif
}

static int window_result_row(const cJSON *row, const EdrAlertWindowQuery *q, uint64_t from, uint64_t until,
                             const cJSON *rows) {
  uint64_t stamp, start, birth;
  uint32_t pid, slot = 0, port;
  const char *id = NULL;
  if (!cJSON_IsObject(row) || !window_decimal(row, "event_time_ns", INT64_MAX, &stamp) || stamp < from ||
      stamp > until || stamp < (uint64_t)q->from_ns || stamp > (uint64_t)q->until_ns ||
      !window_uint(row, "pid", 1, UINT32_MAX, &pid) || pid != q->pid ||
      !window_decimal(row, "process_start_key", UINT64_MAX, &start) || start != q->process_start_key ||
      !window_decimal(row, "process_creation_filetime_100ns", UINT64_MAX, &birth) ||
      birth != q->process_creation_filetime_100ns)
    return 0;
  const char *phase = result_text(row, "phase");
  if (!strcmp(phase, "pre")) {
    if (stamp > (uint64_t)q->source_time_ns || !window_uint(row, "slot", q->pre_start_slot, 31, &slot)) return 0;
  } else if (!strcmp(phase, "post")) {
    if (q->pre_snapshot_sha256) return 0;
    id = window_string(row, "fact_id");
    if (stamp < (uint64_t)q->source_time_ns || !id || strlen(id) != 64 || strspn(id, "0123456789abcdef") != 64)
      return 0;
  } else
    return 0;
  for (const cJSON *prior = rows->child; prior != row; prior = prior->next) {
    uint32_t previous;
    if (id ? !strcmp(id, result_text(prior, "fact_id"))
           : (window_uint(prior, "slot", 0, 31, &previous) && (q->pre_snapshot_sha256 ? previous >= slot : previous == slot)))
      return 0;
  }
  if (!strcmp(q->kind, "network"))
    return cJSON_GetArraySize(row) == 8 && window_literal_ip(window_string(row, "remote_ip")) &&
           window_uint(row, "remote_port", 1, 65535, &port);
  return cJSON_GetArraySize(row) == 9 && *result_text(row, "registry_key") && window_string(row, "registry_value") &&
         result_member(result_text(row, "registry_op"), "set_value|create_key|delete_key|delete_value");
}

static cJSON *result_alert_window(const cJSON *root, const cJSON *contract,
                                  const EdrCommandResultAuthorization *auth) {
  EdrAlertWindowQuery scope = {0}, echo = {0};
  const cJSON *rows = cJSON_GetObjectItemCaseSensitive(root, "rows");
  const cJSON *gaps = cJSON_GetObjectItemCaseSensitive(root, "gap_reasons");
  const cJSON *scan = cJSON_GetObjectItemCaseSensitive(root, "scan_limited");
  const cJSON *truncated = cJSON_GetObjectItemCaseSensitive(root, "output_truncated");
  if (!cJSON_IsObject(root) || !window_scope(cJSON_GetObjectItemCaseSensitive(contract, "request"), &scope) ||
      strcmp(result_text(root, "schema"), scope.pre_snapshot_sha256 ? EDR_WINDOW_PRE_PAGE_SCHEMA : "edr.alert-window.v1") ||
      strcmp(scope.endpoint_id, auth->endpoint_id) || strcmp(scope.tenant_id, auth->tenant_id) ||
      !result_integer(contract, "max_bytes", scope.max_bytes, scope.max_bytes, NULL) ||
      !result_integer(contract, "max_rows", scope.limit, scope.limit, NULL) ||
      !window_scope(cJSON_GetObjectItemCaseSensitive(root, "scope"), &echo) || !window_same_scope(&scope, &echo) ||
      !cJSON_IsArray(rows) || (unsigned)cJSON_GetArraySize(rows) > scope.limit || !cJSON_IsBool(scan) ||
      !cJSON_IsBool(truncated) || !cJSON_IsArray(gaps) || cJSON_GetArraySize(gaps) < 1 ||
      cJSON_GetArraySize(gaps) > 5)
    return NULL;
  int owner_missing = 0, unknown = 0;
  for (const cJSON *item = gaps->child; item; item = item->next) {
    const char *reason = cJSON_GetStringValue(item);
    if (!reason ||
        !result_member(reason,
                       "unknown|owner_unavailable|pre_window_truncated|window_interrupted|registry_fields_missing") ||
        (!strcmp(reason, "registry_fields_missing") && strcmp(scope.kind, "registry")) ||
        (item == gaps->child && strcmp(reason, result_text(root, "gap_reason"))))
      return NULL;
    for (const cJSON *prior = gaps->child; prior != item; prior = prior->next)
      if (!strcmp(reason, prior->valuestring)) return NULL;
    owner_missing |= !strcmp(reason, "owner_unavailable");
    unknown |= !strcmp(reason, "unknown");
  }
  if (owner_missing) {
    if (cJSON_GetArraySize(root) != 8 || strcmp(result_text(root, "coverage"), "owner_unavailable") || rows->child ||
        cJSON_GetArraySize(gaps) != 1 || cJSON_IsTrue(scan) || cJSON_IsTrue(truncated))
      return NULL;
  } else {
    uint64_t from, until;
    if (scope.pre_snapshot_sha256) {
      const char *digest = window_string(root, "snapshot_sha256");
      uint32_t last = 0;
      if (!edr_window_hex(digest, 64) || (scope.pre_start_slot && strcmp(digest, scope.pre_snapshot_sha256)) ||
          cJSON_IsTrue(scan) || (cJSON_IsTrue(truncated) && (!rows->child ||
             !window_uint(rows->child->prev, "slot", scope.pre_start_slot, 30, &last)))) return NULL;
    }
    if (cJSON_GetArraySize(root) != (scope.pre_snapshot_sha256 ? 11 : 10) || !unknown || strcmp(result_text(root, "coverage"), "retained_window") ||
        !window_decimal(root, "window_from_ns", INT64_MAX, &from) ||
        !window_decimal(root, "window_until_ns", INT64_MAX, &until) || from < (uint64_t)scope.from_ns ||
        from > (uint64_t)scope.source_time_ns || (uint64_t)scope.source_time_ns - from < UINT64_C(30000000000) ||
        ((uint64_t)scope.source_time_ns - from) % UINT64_C(1000000000) || until <= (uint64_t)scope.source_time_ns ||
        until > (uint64_t)scope.until_ns)
      return NULL;
    for (const cJSON *row = rows->child; row; row = row->next)
      if (!window_result_row(row, &scope, from, until, rows)) return NULL;
  }
  return cJSON_Duplicate(root, 1);
}
