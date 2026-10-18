/* Real PMFE workers, synthetic unavailable generation, no service/collector
 * startup and no external connections. Compile-time checkpoints only control
 * thread timing; scan, admission, and shutdown remain production code. */
#include "edr/pmfe.h"
#include "edr/config.h"
#include "edr/event_bus.h"
#include "edr/behavior_from_slot.h"
#include "edr/time_util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <windows.h>
typedef HANDLE TestThread;
typedef LONG TestCounter;
typedef DWORD (WINAPI *TestMain)(void *);
#define THREAD_RESULT DWORD WINAPI
#define THREAD_RETURN return 0
static void pause_ms(unsigned ms) { Sleep(ms); }
static int start_thread(TestThread *t, TestMain fn, void *arg) {
  *t=CreateThread(NULL,0,fn,arg,0,NULL); return *t!=NULL;
}
static void join_thread(TestThread t) { WaitForSingleObject(t,INFINITE); CloseHandle(t); }
static volatile LONG accepted, rejected, controller_errors;
static void count(volatile LONG *n) { InterlockedIncrement(n); }
static long value(volatile LONG *n) { return InterlockedCompareExchange(n,0,0); }
static HANDLE checkpoint_reached, checkpoint_release;
#else
#include <pthread.h>
#include <time.h>
typedef pthread_t TestThread;
typedef long TestCounter;
typedef void *(*TestMain)(void *);
#define THREAD_RESULT void *
#define THREAD_RETURN return NULL
static void pause_ms(unsigned ms) {
  struct timespec ts={(time_t)(ms/1000u),(long)(ms%1000u)*1000000L}; nanosleep(&ts,NULL);
}
static int start_thread(TestThread *t, TestMain fn, void *arg) { return pthread_create(t,NULL,fn,arg)==0; }
static void join_thread(TestThread t) { pthread_join(t,NULL); }
static volatile long accepted, rejected, controller_errors;
static void count(volatile long *n) { (void)__atomic_add_fetch(n,1,__ATOMIC_RELAXED); }
static long value(volatile long *n) { return __atomic_load_n(n,__ATOMIC_RELAXED); }
static pthread_mutex_t checkpoint_mu=PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t checkpoint_cv=PTHREAD_COND_INITIALIZER;
static int checkpoint_reached, checkpoint_release;
#endif
static int checkpoint_phase;
static unsigned failures;
static EdrConfig enabled_config, disabled_config;
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"FAIL line %d: %s\n",__LINE__,#x); ++failures; } } while (0)

static void set_enabled_override(int enabled) {
#ifdef _WIN32
  _putenv_s("EDR_PMFE_ENABLED",enabled ? "1" : "");
#else
  if (enabled) setenv("EDR_PMFE_ENABLED","1",1); else unsetenv("EDR_PMFE_ENABLED");
#endif
}
static void checkpoint(int phase) {
  if (phase!=checkpoint_phase) return;
#ifdef _WIN32
  SetEvent(checkpoint_reached);
  WaitForSingleObject(checkpoint_release,INFINITE);
#else
  pthread_mutex_lock(&checkpoint_mu);
  checkpoint_reached=1; pthread_cond_broadcast(&checkpoint_cv);
  while (!checkpoint_release) pthread_cond_wait(&checkpoint_cv,&checkpoint_mu);
  pthread_mutex_unlock(&checkpoint_mu);
#endif
}
static void arm_checkpoint(int phase) {
  checkpoint_phase=phase;
#ifdef _WIN32
  ResetEvent(checkpoint_reached); ResetEvent(checkpoint_release);
#else
  checkpoint_reached=checkpoint_release=0;
#endif
  edr_pmfe_set_lifecycle_test_hook(checkpoint);
}
static void wait_checkpoint(void) {
#ifdef _WIN32
  CHECK(WaitForSingleObject(checkpoint_reached,5000)==WAIT_OBJECT_0);
#else
  struct timespec ts; clock_gettime(CLOCK_REALTIME,&ts); ts.tv_sec+=5;
  pthread_mutex_lock(&checkpoint_mu);
  while (!checkpoint_reached) {
    if (pthread_cond_timedwait(&checkpoint_cv,&checkpoint_mu,&ts)!=0) break;
  }
  CHECK(checkpoint_reached);
  pthread_mutex_unlock(&checkpoint_mu);
#endif
}
static void release_checkpoint(void) {
#ifdef _WIN32
  SetEvent(checkpoint_release);
#else
  pthread_mutex_lock(&checkpoint_mu);
  checkpoint_release=1; pthread_cond_broadcast(&checkpoint_cv);
  pthread_mutex_unlock(&checkpoint_mu);
#endif
}
static EdrPmfeFollowupTask task(unsigned id) {
  EdrPmfeFollowupTask t; memset(&t,0,sizeof(t));
  snprintf(t.association_id,sizeof(t.association_id),"synthetic-lifecycle-%u",id);
  snprintf(t.source_alert_id,sizeof(t.source_alert_id),"synthetic-source-%u",id);
  strcpy(t.endpoint_id,"synthetic-endpoint"); strcpy(t.tenant_id,"synthetic-tenant");
  /* UINT32_MAX cannot equal the Windows self PID (PID values are aligned),
   * so host-policy self exclusion cannot make this failure fixture flaky. */
  t.pid=UINT32_MAX; t.process_start_key=UINT64_C(0xfedcba9876543210);
  t.process_creation_filetime_100ns=UINT64_C(133444000000000000);
  t.source_event_time_ns=INT64_C(1700000000000000000); t.band=EDR_PMFE_BAND_P0;
  return t;
}
static EdrError init_result;
static THREAD_RESULT init_thread(void *arg) { (void)arg; init_result=edr_pmfe_init(); THREAD_RETURN; }
static int delayed_result;
static THREAD_RESULT delayed_submit(void *arg) {
  (void)arg; EdrPmfeFollowupTask t=task(2); delayed_result=edr_pmfe_submit_associated_scan(&t); THREAD_RETURN;
}
static void test_ready_publication(void) {
  TestThread t; arm_checkpoint(EDR_PMFE_TEST_INIT_WORKERS);
  CHECK(start_thread(&t,init_thread,NULL)); wait_checkpoint();
  CHECK(!edr_pmfe_is_running());
  EdrPmfeFollowupTask f=task(1); CHECK(edr_pmfe_submit_associated_scan(&f)==-1);
  release_checkpoint(); join_thread(t); edr_pmfe_set_lifecycle_test_hook(NULL);
  CHECK(init_result==EDR_OK); CHECK(edr_pmfe_is_running()); edr_pmfe_shutdown();
}
static void test_policy_withdrawal(void) {
  set_enabled_override(0); edr_pmfe_bind_config(&enabled_config);
  CHECK(edr_pmfe_init()==EDR_OK); CHECK(edr_pmfe_is_running());
  TestThread t; arm_checkpoint(EDR_PMFE_TEST_SUBMIT_LOCK);
  CHECK(start_thread(&t,delayed_submit,NULL)); wait_checkpoint();
  /* Withdraw the authoritative policy while the old ready observation is in
   * flight. The queue lock must recheck the newly disabled admission. */
  edr_pmfe_bind_config(&disabled_config);
  release_checkpoint(); join_thread(t); edr_pmfe_set_lifecycle_test_hook(NULL);
  CHECK(delayed_result==-1); CHECK(edr_pmfe_queue_depth()==0);
  edr_pmfe_shutdown(); CHECK(!edr_pmfe_is_running());
  EdrPmfeFollowupTask f=task(3); CHECK(edr_pmfe_submit_associated_scan(&f)==-1);
  CHECK(edr_pmfe_init()==EDR_OK); CHECK(!edr_pmfe_is_running());
  edr_pmfe_bind_config(&enabled_config); CHECK(edr_pmfe_init()==EDR_OK);
  CHECK(edr_pmfe_submit_associated_scan(&f)==0); edr_pmfe_shutdown();
}
static THREAD_RESULT producer(void *arg) {
  unsigned producer_id=(unsigned)(uintptr_t)arg;
  for (unsigned i=0;i<50;++i) {
    EdrPmfeFollowupTask f=task(100+producer_id*100+i);
    int r=edr_pmfe_submit_associated_scan(&f);
    if (!r) count(&accepted); else if (r==-1) count(&rejected); else count(&controller_errors);
    pause_ms(1);
  }
  THREAD_RETURN;
}
static THREAD_RESULT controller(void *arg) {
  (void)arg;
  for (unsigned i=0;i<6;++i) {
    if (edr_pmfe_init()!=EDR_OK) count(&controller_errors);
    pause_ms(3); edr_pmfe_shutdown(); pause_ms(1);
  }
  THREAD_RETURN;
}
static void test_concurrent_workers(EdrEventBus *bus) {
  set_enabled_override(1); edr_pmfe_bind_config(&enabled_config);
  unsigned long before_submitted=0,before_completed=0;
  edr_pmfe_get_stats(&before_submitted,&before_completed,NULL);
  CHECK(edr_pmfe_init()==EDR_OK);
  EdrPmfeFollowupTask first=task(99); CHECK(edr_pmfe_submit_associated_scan(&first)==0);
  TestThread ps[3],cs[2];
  for (unsigned i=0;i<3;++i) CHECK(start_thread(&ps[i],producer,(void *)(uintptr_t)i));
  for (unsigned i=0;i<2;++i) CHECK(start_thread(&cs[i],controller,NULL));
  for (unsigned i=0;i<3;++i) join_thread(ps[i]);
  for (unsigned i=0;i<2;++i) join_thread(cs[i]);
  edr_pmfe_shutdown();
  CHECK(!edr_pmfe_is_running()); CHECK(edr_pmfe_queue_depth()==0);
  CHECK(value(&controller_errors)==0); CHECK(value(&accepted)+value(&rejected)==150);
  unsigned long submitted=0,completed=0; edr_pmfe_get_stats(&submitted,&completed,NULL);
  CHECK(submitted-before_submitted==(unsigned long)value(&accepted)+1);
  CHECK(completed-before_completed==submitted-before_submitted);
  EdrPmfeRuntimeStats runtime; edr_pmfe_get_runtime_stats(&runtime); CHECK(runtime.active==0);
  EdrPmfeFollowupTask stopped=task(999); CHECK(edr_pmfe_submit_associated_scan(&stopped)==-1);
  CHECK(edr_event_bus_dropped_total(bus)==0);
}
/* A full queue must reject new work without making a caller wait for worker
 * progress. Hold both actual workers in the existing public server callback;
 * no lifecycle checkpoint or mock queue controls this case. */
static volatile TestCounter full_arrived, full_callbacks, full_bad_results;
static volatile TestCounter full_associated_done, full_submit_done, full_etw_done, full_seen[67];
static int full_associated_result=-99, full_submit_result=-99, full_etw_result=-99;
static int wait_full_count(volatile TestCounter *counter, long expected, unsigned timeout_ms) {
  uint64_t deadline=edr_monotonic_ns()+(uint64_t)timeout_ms*1000000ull;
  while (value(counter)<expected && edr_monotonic_ns()<deadline) pause_ms(1);
  return value(counter)>=expected;
}
static int submit_full_task(unsigned index) {
  char id[80]; snprintf(id,sizeof(id),"synthetic-full-%u",index);
  /* This unavailable PID cannot match a Windows PID or a positive pid_t. */
  return edr_pmfe_submit_server_scan(id,UINT32_MAX);
}
static void full_result_callback(const char *id, uint32_t pid, int status, const char *detail,
                                 const EdrPmfeScanResult *result,
                                 const EdrPmfeCommandContext *context) {
  (void)context;
  unsigned index=67u; char suffix=0;
  if (!id || sscanf(id,"synthetic-full-%u%c",&index,&suffix)!=1 || index>=67u) {
    count(&full_bad_results);
  } else {
    count(&full_seen[index]);
    if (value(&full_seen[index])!=1) count(&full_bad_results);
  }
  if (pid!=UINT32_MAX || status==0 || !detail || !detail[0] || !result ||
      strcmp(result->verdict,"inconclusive")) count(&full_bad_results);
  count(&full_callbacks);
  if (index<2u) {
    count(&full_arrived);
#ifdef _WIN32
    if (WaitForSingleObject(checkpoint_release,INFINITE)!=WAIT_OBJECT_0) count(&full_bad_results);
#else
    pthread_mutex_lock(&checkpoint_mu);
    while (!checkpoint_release) pthread_cond_wait(&checkpoint_cv,&checkpoint_mu);
    pthread_mutex_unlock(&checkpoint_mu);
#endif
  }
}
static THREAD_RESULT submit_full_overflow(void *arg) {
  (void)arg;
  EdrPmfeFollowupTask associated=task(2000u);
  full_associated_result=edr_pmfe_submit_associated_scan(&associated);
  count(&full_associated_done);
  full_submit_result=submit_full_task(66u);
  count(&full_submit_done);
  full_etw_result=edr_pmfe_submit_etw_scan_ex("synthetic-full-etw",UINT32_MAX-4u,
                                             EDR_PMFE_BAND_P1,0ull);
  count(&full_etw_done);
  THREAD_RETURN;
}
static void test_full_queue_nonblocking(EdrEventBus *bus) {
  unsigned before_failures=failures;
  unsigned long before_submitted=0,before_completed=0,before_dropped=0;
  edr_pmfe_get_stats(&before_submitted,&before_completed,&before_dropped);
#ifdef _WIN32
  ResetEvent(checkpoint_release);
#else
  checkpoint_release=0;
#endif
  set_enabled_override(1); edr_pmfe_bind_config(&enabled_config);
  edr_pmfe_set_event_bus(NULL);
  edr_pmfe_set_server_scan_result_callback(full_result_callback);
  CHECK(edr_pmfe_init()==EDR_OK);
  int running=edr_pmfe_is_running(); CHECK(running);
  if (!running) goto restore;
  int first=submit_full_task(0u),second=submit_full_task(1u);
  CHECK(first==0); CHECK(second==0);
  int held=wait_full_count(&full_arrived,2,5000); CHECK(held);
  if (!held) goto shutdown;
  for (unsigned i=2u;i<66u;++i) CHECK(submit_full_task(i)==0);
  CHECK(edr_pmfe_queue_depth()==64u);
  TestThread t;
  int created=start_thread(&t,submit_full_overflow,NULL); CHECK(created);
  int returned_before_release=0;
  if (created) {
    int associated_done=wait_full_count(&full_associated_done,1,100);
    CHECK(associated_done);
    returned_before_release=wait_full_count(&full_submit_done,1,100);
    CHECK(returned_before_release);
    CHECK(wait_full_count(&full_etw_done,1,100));
  }
  CHECK(edr_pmfe_queue_depth()==64u);
  /* Also on an unfixed owner, release our own barrier before joining the
   * submitter. The regression fails finitely, then drains accepted work. */
  release_checkpoint();
  if (created) join_thread(t);
  edr_pmfe_shutdown();
  unsigned long submitted=0,completed=0,dropped=0;
  edr_pmfe_get_stats(&submitted,&completed,&dropped);
  CHECK(full_submit_result==-1); CHECK(full_associated_result==-1); CHECK(full_etw_result==-1);
  CHECK(submitted-before_submitted==66u);
  CHECK(completed-before_completed==submitted-before_submitted);
  CHECK(dropped-before_dropped==3u);
  CHECK(value(&full_callbacks)==(long)(submitted-before_submitted));
  for (unsigned i=0;i<66u;++i) CHECK(value(&full_seen[i])==1);
  CHECK(value(&full_seen[66])==0); CHECK(value(&full_bad_results)==0);
  CHECK(!edr_pmfe_is_running()); CHECK(edr_pmfe_queue_depth()==0u);
  printf("PMFE full queue: returned_before_release=%d ordinary_result=%d associated_result=%d etw_result=%d "
         "accepted=%lu completed=%lu callbacks=%ld dropped=%lu failures=%u\n",
         returned_before_release,full_submit_result,full_associated_result,full_etw_result,
         submitted-before_submitted,completed-before_completed,value(&full_callbacks),
         dropped-before_dropped,failures-before_failures);
  goto restore;
shutdown:
  release_checkpoint(); edr_pmfe_shutdown();
restore:
  edr_pmfe_set_server_scan_result_callback(NULL);
  edr_pmfe_set_event_bus(bus);
}

int main(int argc, char **argv) {
  int all=argc==1;
  int ready=all || (argc==2 && !strcmp(argv[1],"--ready"));
  int policy=all || (argc==2 && !strcmp(argv[1],"--policy"));
  int full=all || (argc==2 && !strcmp(argv[1],"--full"));
  if (!ready && !policy && !full) return 2;
#ifdef _WIN32
  checkpoint_reached=CreateEvent(NULL,TRUE,FALSE,NULL);
  checkpoint_release=CreateEvent(NULL,TRUE,FALSE,NULL);
  CHECK(checkpoint_reached && checkpoint_release);
#endif
  enabled_config.detection.pmfe_mode=1; enabled_config.resource_limit.pmfe_scans_per_min=60;
  set_enabled_override(1);
  EdrEventBus *bus=edr_event_bus_create(512); CHECK(bus!=NULL); if (!bus) return 1;
  edr_pmfe_set_event_bus(bus);
  if (ready) test_ready_publication();
  if (policy) test_policy_withdrawal();
  if (all) test_concurrent_workers(bus);
  /* All scans use an intentionally unavailable generation. Actual worker
   * output remains inconclusive; policy restarts must never turn it positive. */
  unsigned emitted=0; EdrEventSlot slot;
  EdrBehaviorRecord *record=calloc(1,sizeof(*record)); CHECK(record!=NULL);
  while (edr_event_bus_try_pop(bus,&slot)) {
    CHECK(slot.type==EDR_EVENT_PMFE_SCAN_RESULT);
    if (record) {
      edr_behavior_from_slot(&slot,record);
      CHECK(strstr(record->script_snippet,"pmfe_verdict=inconclusive")!=NULL);
      CHECK(!strcmp(record->process_generation_source,"pmfe_followup_expected_generation"));
      CHECK(record->process_start_key==UINT64_C(0xfedcba9876543210));
      CHECK(record->process_creation_filetime_100ns==UINT64_C(133444000000000000));
    }
    ++emitted;
  }
  if (all) CHECK(emitted==(unsigned)value(&accepted)+2);
  free(record);
  if (full) test_full_queue_nonblocking(bus);
  edr_pmfe_set_event_bus(NULL); edr_event_bus_destroy(bus);
#ifdef _WIN32
  CloseHandle(checkpoint_reached); CloseHandle(checkpoint_release);
#endif
  printf("PMFE lifecycle: actual_worker_results=%u concurrent_accepted=%ld rejected=%ld failures=%u\n",
         emitted,value(&accepted),value(&rejected),failures);
  return failures ? 1 : 0;
}
