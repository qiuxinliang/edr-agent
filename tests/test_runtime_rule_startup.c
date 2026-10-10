/* Exercise the production polling owner with clock/readiness boundaries and
 * a failing cache-preparation I/O boundary. No verified rule cache is mutated. */
#define edr_monotonic_ns fixture_monotonic_ns
#define edr_p0_rule_ir_is_ready fixture_p0_is_ready
#define edr_p0_rule_ir_prepare_download_path fixture_prepare_rule_cache
#define edr_sensor_interest_get_status fixture_sensor_status
#include "../src/core/agent.c"
#undef edr_monotonic_ns
#undef edr_p0_rule_ir_is_ready
#undef edr_p0_rule_ir_prepare_download_path
#undef edr_sensor_interest_get_status
#include <assert.h>

static uint64_t fixture_now = 900000000000ULL;
static int fixture_loaded;
uint64_t fixture_monotonic_ns(void) { return fixture_now; }
int fixture_p0_is_ready(void) { return fixture_loaded; }
int fixture_prepare_rule_cache(const char *path) { (void)path; return 0; }
void fixture_sensor_status(EdrSensorInterestStatus *status) {
  memset(status, 0, sizeof(*status));
  status->loaded = fixture_loaded;
}

static void fixture_environment(const char *key, const char *value) {
#ifdef _WIN32
  assert(_putenv_s(key, value) == 0);
#else
  assert(setenv(key, value, 1) == 0);
#endif
}

static void check_first_pull(int loaded, int sensor) {
  EdrAgent *agent = edr_agent_create();
  assert(agent);
  fixture_loaded = loaded;
  fixture_now = 900000000000ULL;
  snprintf(agent->cfg.agent.endpoint_id, sizeof(agent->cfg.agent.endpoint_id), "ep-one");
  uint64_t last_pull = 0u;
  unsigned slot = sensor ? 3u : 2u;
  void (*poll)(EdrAgent *, uint64_t *) = sensor ? edr_agent_poll_sensor_interest : edr_agent_poll_p0_bundle;
  poll(agent, &last_pull);
  if (loaded) {
    assert(last_pull == 0u);
    assert(agent->maintenance_schedule[slot].next_ns > fixture_now);
    assert(agent->maintenance_schedule[slot].next_ns <= fixture_now + 30000000000ULL);
    fixture_now = agent->maintenance_schedule[slot].next_ns;
    poll(agent, &last_pull);
    assert(last_pull == fixture_now);
  } else {
    assert(last_pull == fixture_now);
    assert(agent->maintenance_schedule[slot].next_ns > fixture_now + 1770000000000ULL);
    assert(agent->maintenance_schedule[slot].next_ns <= fixture_now + 1800000000000ULL);
  }
  uint64_t previous = last_pull;
  fixture_now += 1000000000ULL;
  poll(agent, &last_pull);
  assert(last_pull == previous); /* Failure does not bypass the regular period. */
  fixture_now = agent->maintenance_schedule[slot].next_ns;
  poll(agent, &last_pull);
  assert(last_pull == fixture_now);
  assert(agent->maintenance_schedule[slot].next_ns == fixture_now + 1800000000000ULL);
  free(agent);
}

int main(void) {
  fixture_environment("EDR_P0_BUNDLE_URL", "unsupported-fixture://p0");
  fixture_environment("EDR_SENSOR_INTEREST_URL", "unsupported-fixture://sensor");
  fixture_environment("EDR_P0_BUNDLE_AUTO_PULL", "1");
  fixture_environment("EDR_SENSOR_INTEREST_AUTO_PULL", "1");
  fixture_environment("EDR_P0_BUNDLE_POLL_S", "1800");
  fixture_environment("EDR_SENSOR_INTEREST_POLL_S", "1800");
  for (int loaded = 0; loaded < 2; ++loaded)
    for (int sensor = 0; sensor < 2; ++sensor) check_first_pull(loaded, sensor);
  puts("runtime rule startup: PASS (cold immediate, loaded bounded phase, regular retry cadence)");
  return 0;
}
