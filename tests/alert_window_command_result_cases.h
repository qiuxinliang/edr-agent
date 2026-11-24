static const char window_request[] =
    "{\"tenant_id\":\"tenant\",\"endpoint_id\":\"ep\",\"alert_id\":\"a\",\"source_event_id\":\"evt\",\"pid\":42,"
    "\"process_start_key\":\"18446744073709551615\",\"process_creation_filetime_100ns\":\"133700000000000001\","
    "\"source_time_ns\":\"1700000000000000001\",\"kind\":\"network\",\"from_ns\":\"1699999880000000001\","
    "\"until_ns\":\"1700000120000000001\",\"limit\":50,\"max_bytes\":8192}";
static const char window_row[] =
    "{\"phase\":\"post\",\"event_time_ns\":\"1700000000000000002\",\"pid\":42,"
    "\"process_start_key\":\"18446744073709551615\",\"process_creation_filetime_100ns\":\"133700000000000001\","
    "\"fact_id\":\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\","
    "\"remote_ip\":\"2001:db8::5\",\"remote_port\":443}";

static void assert_window_project(const EdrCommandResultAuthorization *a, cJSON *r, int pass) {
  char *raw = cJSON_PrintUnformatted(r), out[8197];
  CHECK(raw);
  CHECK((edr_command_result_project_detail(a, "alert_window_query_v2", 1, 0, raw, out, sizeof(out)) == 0) == pass);
  cJSON_free(raw);
}

static void assert_registry_page_projection(EdrCommandResultAuthorization a, const cJSON *mixed, int64_t issued) {
  const char digest[] = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
  cJSON *r = cJSON_Duplicate(mixed, 1);
  CHECK(r);
  cJSON *q = cJSON_GetObjectItemCaseSensitive(r, "scope");
  cJSON *page = cJSON_AddObjectToObject(q, "pre_page");
  CHECK(page && cJSON_AddNumberToObject(page, "start_slot", 4));
  CHECK(cJSON_AddStringToObject(page, "snapshot_sha256", digest));
  CHECK(cJSON_AddStringToObject(page, "previous_task_id", "lcq-0123456789abcdef0123456789abcdef0123456789abcdef"));
  CHECK(cJSON_AddStringToObject(page, "previous_result_sha256", digest));
  char *request = cJSON_PrintUnformatted(q);
  CHECK(request && edr_command_result_bind_contract(&a, (const uint8_t *)request, strlen(request), issued) == 0);
  cJSON_free(request);
  assert_window_project(&a, r, 0);
  CHECK(cJSON_SetValuestring(cJSON_GetObjectItemCaseSensitive(r, "schema"), "edr.alert-window.pre-page.v1"));
  CHECK(cJSON_AddStringToObject(r, "snapshot_sha256", digest));
  assert_window_project(&a, r, 0); /* post is outside this page */
  cJSON *rows = cJSON_GetObjectItemCaseSensitive(r, "rows");
  cJSON *row = cJSON_GetArrayItem(rows, 0);
  cJSON_DeleteItemFromObject(row, "fact_id");
  CHECK(cJSON_SetValuestring(cJSON_GetObjectItemCaseSensitive(row, "phase"), "pre"));
  CHECK(cJSON_SetValuestring(cJSON_GetObjectItemCaseSensitive(row, "event_time_ns"), "1700000000000000000"));
  cJSON *slot = cJSON_AddNumberToObject(row, "slot", 4);
  CHECK(slot && cJSON_ReplaceItemInObjectCaseSensitive(r, "output_truncated", cJSON_CreateTrue()));
  assert_window_project(&a, r, 1);
  cJSON_SetNumberValue(slot, 3); assert_window_project(&a, r, 0);
  cJSON_SetNumberValue(slot, 31); assert_window_project(&a, r, 0);
  cJSON_SetNumberValue(slot, 4);
  CHECK(cJSON_SetValuestring(cJSON_GetObjectItemCaseSensitive(q, "alert_id"), "other"));
  assert_window_project(&a, r, 0);
  CHECK(cJSON_SetValuestring(cJSON_GetObjectItemCaseSensitive(q, "alert_id"), "a"));
  CHECK(cJSON_SetValuestring(cJSON_GetObjectItemCaseSensitive(r, "snapshot_sha256"),
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
  assert_window_project(&a, r, 0);
  CHECK(cJSON_SetValuestring(cJSON_GetObjectItemCaseSensitive(r, "snapshot_sha256"), digest));
  cJSON_DeleteItemFromArray(rows, 0);
  assert_window_project(&a, r, 0);
  cJSON_Delete(r);
}

static void assert_file_window_projection(EdrCommandResultAuthorization a, const cJSON *network,
                                          int64_t issued) {
  cJSON *result = cJSON_Duplicate(network, 1);
  CHECK(result);
  cJSON *scope = cJSON_GetObjectItemCaseSensitive(result, "scope");
  CHECK(cJSON_SetValuestring(cJSON_GetObjectItemCaseSensitive(scope, "kind"), "file_write"));
  char *request = cJSON_PrintUnformatted(scope);
  CHECK(request && edr_command_result_bind_contract(&a, (const uint8_t *)request, strlen(request), issued) == 0);
  cJSON_free(request);

  cJSON *row = cJSON_GetArrayItem(cJSON_GetObjectItemCaseSensitive(result, "rows"), 0);
  cJSON_DeleteItemFromObjectCaseSensitive(row, "remote_ip");
  cJSON_DeleteItemFromObjectCaseSensitive(row, "remote_port");
  cJSON *path = cJSON_AddStringToObject(row, "file_path", "C:/synthetic/file.bin");
  cJSON *quality = cJSON_AddStringToObject(row, "file_path_quality", "unconfirmed");
  CHECK(path && quality);
  CHECK(cJSON_SetValuestring(cJSON_GetObjectItemCaseSensitive(result, "gap_reason"), "activation_gap"));
  cJSON *gaps = cJSON_GetObjectItemCaseSensitive(result, "gap_reasons");
  CHECK(cJSON_InsertItemInArray(gaps, 0, cJSON_CreateString("activation_gap")));
  assert_window_project(&a, result, 1);
  CHECK(cJSON_SetValuestring(cJSON_GetObjectItemCaseSensitive(scope, "alert_id"), "other"));
  assert_window_project(&a, result, 0);
  CHECK(cJSON_SetValuestring(cJSON_GetObjectItemCaseSensitive(scope, "alert_id"), "a"));
  CHECK(cJSON_SetValuestring(cJSON_GetObjectItemCaseSensitive(row, "process_start_key"), "3"));
  assert_window_project(&a, result, 0);
  CHECK(cJSON_SetValuestring(cJSON_GetObjectItemCaseSensitive(row, "process_start_key"), "18446744073709551615"));
  CHECK(cJSON_SetValuestring(quality, "observed"));
  assert_window_project(&a, result, 0); /* Old post path never proves the write target. */
  CHECK(cJSON_SetValuestring(quality, "missing"));
  assert_window_project(&a, result, 0);
  CHECK(cJSON_SetValuestring(path, ""));
  assert_window_project(&a, result, 1);

  cJSON_DeleteItemFromObjectCaseSensitive(row, "fact_id");
  CHECK(cJSON_AddNumberToObject(row, "slot", 0));
  CHECK(cJSON_SetValuestring(cJSON_GetObjectItemCaseSensitive(row, "phase"), "pre"));
  CHECK(cJSON_SetValuestring(cJSON_GetObjectItemCaseSensitive(row, "event_time_ns"), "1700000000000000000"));
  char boundary[257];
  memset(boundary, 'a', sizeof(boundary) - 1u);
  boundary[sizeof(boundary) - 1u] = 0;
  CHECK(cJSON_SetValuestring(path, boundary));
  CHECK(cJSON_SetValuestring(quality, "unconfirmed"));
  assert_window_project(&a, result, 0);
  CHECK(cJSON_SetValuestring(quality, "truncated"));
  assert_window_project(&a, result, 0);
  boundary[255] = 0;
  CHECK(cJSON_SetValuestring(path, boundary));
  assert_window_project(&a, result, 1);
  CHECK(cJSON_SetValuestring(quality, "observed"));
  assert_window_project(&a, result, 0);
  boundary[254] = 0;
  CHECK(cJSON_SetValuestring(path, boundary));
  assert_window_project(&a, result, 1);

  char *raw = cJSON_PrintUnformatted(result), out[8197];
  CHECK(raw && edr_command_result_project_detail(&a, "alert_window_query_v1", 1, 0, raw, out, sizeof(out)) != 0);
  CHECK(edr_command_result_project_detail(&a, "rtq_query", 1, 0, raw, out, sizeof(out)) != 0);
  cJSON_free(raw);
  cJSON_Delete(result);
}

static int alert_window_command_results(void) {
  const char *type = "alert_window_query_v2", *id = "synthetic-window";
  char path[256];
  snprintf(path, sizeof(path), "./alert-window-egress-%ld", (long)pid());
  env("EDR_COMMAND_STATE_DIR", path);
  edr_egress_set_command_result_validator(edr_command_state_result_authorized);
  EdrSoarCommandMeta m = {0};
  EdrCommandResultAuthorization *a = &m.result_authorization;
  strcpy(a->command_type, type);
  strcpy(a->command_id, id);
  strcpy(a->tenant_id, "tenant");
  strcpy(a->endpoint_id, "ep");
  m.issued_at_unix_ms = (int64_t)time(NULL) * 1000;
  m.deadline_ms = 60000;
  strcpy(m.soar_correlation_id,id);
  a->expires_unix_ms = m.issued_at_unix_ms + 60000;
  char detail[4096];
  snprintf(detail, sizeof(detail),
           "{\"schema\":\"edr.alert-window.v1\",\"scope\":%s,\"rows\":[%s],"
           "\"coverage\":\"retained_window\",\"gap_reason\":\"unknown\",\"gap_reasons\":[\"unknown\"],"
           "\"scan_limited\":false,\"output_truncated\":false,\"window_from_ns\":\"1699999970000000001\","
           "\"window_until_ns\":\"1700000000000000003\"}",
           window_request, window_row);
  int bound = edr_command_result_bind_contract(a, (const uint8_t *)window_request, strlen(window_request),
                                               m.issued_at_unix_ms);
  cJSON *r = cJSON_Parse(detail);
  CHECK(r);
  CHECK(bound == 0);
  EdrCommandResultAuthorization wrong = *a;
  strcpy(wrong.tenant_id, "other");
  CHECK(edr_command_result_bind_contract(&wrong, (const uint8_t *)window_request, strlen(window_request),
                                         m.issued_at_unix_ms) != 0);
  assert_window_project(a, r, 1);
  assert_file_window_projection(*a, r, m.issued_at_unix_ms);
  cJSON *port_result = cJSON_Duplicate(r, 1);
  CHECK(port_result);
  cJSON *port_scope = cJSON_GetObjectItemCaseSensitive(port_result, "scope");
  CHECK(cJSON_SetValuestring(cJSON_GetObjectItemCaseSensitive(port_scope, "kind"), "network_port"));
  CHECK(cJSON_AddNumberToObject(port_scope, "remote_port", 443));
  char *port_request = cJSON_PrintUnformatted(port_scope);
  EdrCommandResultAuthorization port_auth = *a;
  CHECK(port_request && !edr_command_result_bind_contract(&port_auth, (const uint8_t *)port_request, strlen(port_request), m.issued_at_unix_ms));
  cJSON_free(port_request);
  assert_window_project(&port_auth, port_result, 1);
  cJSON *selected_port = cJSON_GetObjectItemCaseSensitive(cJSON_GetArrayItem(cJSON_GetObjectItemCaseSensitive(port_result, "rows"), 0), "remote_port");
  cJSON_SetNumberValue(selected_port, 444); assert_window_project(&port_auth, port_result, 0);
  cJSON_SetNumberValue(selected_port, 443);
  cJSON_SetNumberValue(cJSON_GetObjectItemCaseSensitive(port_scope, "remote_port"), 444);
  assert_window_project(&port_auth, port_result, 0);
  cJSON_SetNumberValue(cJSON_GetObjectItemCaseSensitive(port_scope, "remote_port"), 443);
  CHECK(cJSON_AddObjectToObject(port_scope, "pre_page")); assert_window_project(&port_auth, port_result, 0);
  cJSON_Delete(port_result);
  cJSON *from = cJSON_GetObjectItemCaseSensitive(r, "window_from_ns");
  CHECK(cJSON_SetValuestring(from, "1699999970000000000"));
  assert_window_project(a, r, 0);
  CHECK(cJSON_SetValuestring(from, "1699999980000000001"));
  assert_window_project(a, r, 0);
  CHECK(cJSON_SetValuestring(from, "1699999879000000001"));
  assert_window_project(a, r, 0);
  CHECK(cJSON_SetValuestring(from, "1699999970000000001"));
  assert_window_project(a, r, 1);
  CHECK(edr_command_state_finish(id, type, &m, "ok", 1, 0, detail, "", 1) == 0);
  char *b = persisted_body(id, type);
  char why[128];
  CHECK(!allowed("tenant","ep",b));
  CHECK(edr_egress_request_validate_for_scope("POST",EDR_ALERT_WINDOW_RESULT_SUFFIX,"application/json",
        b,strlen(b),"tenant","ep",why,sizeof(why))==0);
  CHECK(edr_egress_request_validate_for_scope("POST",EDR_ALERT_WINDOW_RESULT_SUFFIX,"application/json",
        b,strlen(b),"other","ep",why,sizeof(why))!=0);
  free(b);
  cJSON *rows = cJSON_GetObjectItemCaseSensitive(r, "rows"), *row = cJSON_GetArrayItem(rows, 0);
  CHECK(cJSON_AddItemToArray(rows, cJSON_Duplicate(row, 1)));
  assert_window_project(a, r, 0);
  cJSON_DeleteItemFromArray(rows, 1);
  CHECK(cJSON_AddStringToObject(row, "cmdline", "synthetic-private"));
  assert_window_project(a, r, 0);
  cJSON_DeleteItemFromObject(row, "cmdline");
  const char *bad_ip[] = {"host.example", "127.0.0.1:21", "fe80::1%12", "300.1.2.3", "::1 secret", ""};
  for (unsigned i = 0; i < sizeof(bad_ip) / sizeof(bad_ip[0]); i++) {
    CHECK(cJSON_SetValuestring(cJSON_GetObjectItemCaseSensitive(row, "remote_ip"), bad_ip[i]));
    assert_window_project(a, r, 0);
  }
  CHECK(cJSON_SetValuestring(cJSON_GetObjectItemCaseSensitive(row, "remote_ip"), "192.0.2.9"));
  assert_window_project(a, r, 1);
  CHECK(cJSON_SetValuestring(cJSON_GetObjectItemCaseSensitive(row, "event_time_ns"), "1700000000000000000"));
  assert_window_project(a, r, 0);
  CHECK(cJSON_SetValuestring(cJSON_GetObjectItemCaseSensitive(row, "event_time_ns"), "1700000000000000004"));
  assert_window_project(a, r, 0);
  CHECK(cJSON_SetValuestring(cJSON_GetObjectItemCaseSensitive(row, "event_time_ns"), "1700000000000000002"));
  cJSON *scope = cJSON_GetObjectItemCaseSensitive(r, "scope");
  CHECK(cJSON_SetValuestring(cJSON_GetObjectItemCaseSensitive(scope, "source_event_id"), "other"));
  assert_window_project(a, r, 0);
  CHECK(cJSON_SetValuestring(cJSON_GetObjectItemCaseSensitive(scope, "source_event_id"), "evt"));
  CHECK(cJSON_SetValuestring(cJSON_GetObjectItemCaseSensitive(scope, "kind"), "registry"));
  char *reg = cJSON_PrintUnformatted(scope);
  CHECK(reg);
  CHECK(edr_command_result_bind_contract(a, (const uint8_t *)reg, strlen(reg), m.issued_at_unix_ms) == 0);
  cJSON_free(reg);
  assert_window_project(a, r, 0);
  cJSON_DeleteItemFromObject(row, "remote_ip");
  cJSON_DeleteItemFromObject(row, "remote_port");
  CHECK(cJSON_AddStringToObject(row, "registry_key", "HKCU\\Example"));
  CHECK(cJSON_AddStringToObject(row, "registry_value", ""));
  CHECK(cJSON_AddStringToObject(row, "registry_op", "set_value"));
  assert_window_project(a, r, 1);
  CHECK(cJSON_AddBoolToObject(row,"default_observed",1));
  assert_window_project(a,r,0);
  puts("verified real final validator rejects prior ten-field default row");
  cJSON_DeleteItemFromObjectCaseSensitive(row,"default_observed");
  assert_window_project(a,r,1);
  assert_registry_page_projection(*a, r, m.issued_at_unix_ms);
  CHECK(cJSON_AddStringToObject(row, "value_data", "secret"));
  assert_window_project(a, r, 0);
  cJSON_DeleteItemFromObject(row, "value_data");
  cJSON_DeleteItemFromArray(rows, 0);
  cJSON_DeleteItemFromObject(r, "window_from_ns");
  cJSON_DeleteItemFromObject(r, "window_until_ns");
  CHECK(cJSON_SetValuestring(cJSON_GetObjectItemCaseSensitive(r, "coverage"), "owner_unavailable"));
  assert_window_project(a, r, 0);
  CHECK(cJSON_SetValuestring(cJSON_GetObjectItemCaseSensitive(r, "gap_reason"), "owner_unavailable"));
  CHECK(cJSON_SetValuestring(cJSON_GetArrayItem(cJSON_GetObjectItemCaseSensitive(r, "gap_reasons"), 0),
                             "owner_unavailable"));
  assert_window_project(a, r, 1);
  CHECK(cJSON_AddStringToObject(r, "raw_detail", "secret"));
  assert_window_project(a, r, 0);
  cJSON_Delete(r);
  puts("alert window result authorization and final egress passed");
  return 0;
}
