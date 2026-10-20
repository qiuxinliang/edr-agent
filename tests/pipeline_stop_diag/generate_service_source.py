"""Generate an opt-in real-Service pipeline/cache diagnostic; never edit product source.

Use: generate_service_source.py AGENT_SOURCE_ROOT OUTPUT_DIRECTORY
The source is read once as raw UTF-8 and every output is written as bytes, so
Windows newline conversion cannot invalidate the recorded inverse/hash proof.
"""
from pathlib import Path
import re, json, hashlib, sys
if len(sys.argv) != 3:
    raise SystemExit('usage: generate_service_source.py AGENT_SOURCE_ROOT OUTPUT_DIRECTORY')
template_base = Path(__file__).resolve().parent
root = Path(sys.argv[1]).resolve()
output = Path(sys.argv[2]).resolve()
source = root/'src/preprocess/preprocess_pipeline.c'
raw = source.read_bytes()
s = raw.decode('utf-8')
source_newline = '\r\n' if '\r\n' in s else '\n'
assert '\r' not in s.replace('\r\n', ''), 'unsupported bare carriage return in source'
assert not ('\r\n' in s and s.count('\n') != s.count('\r\n')), 'unsupported mixed source line endings'
def source_marker(text):
    return text.replace('\n', source_newline)
output.mkdir(parents=True, exist_ok=True)
# String/comment masking leaves every source byte offset and newline in place.
def mask_c(text):
 return re.sub(r'//[^\n]*|/\*.*?\*/|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'',lambda m:''.join('\n' if c=='\n' else ' ' for c in m[0]),text,flags=re.S)
masked=mask_c(s)
functions=[]
for m in re.finditer(r'(?m)^static\s+[A-Za-z_][A-Za-z0-9_ \t*]*?\b([A-Za-z_]\w*)\s*\([^;{}]*\)\s*\{',masked):
 name=m[1]
 if name=='preprocess_main':continue # Its #ifdef alternative headers share one body.
 opened=m.end()-1;depth=1;i=opened+1
 while depth:
  depth+=(masked[i]=='{')-(masked[i]=='}');i+=1
 functions.append({'name':name,'start':m.start(),'open':opened,'end':i,'calls':[]})
mapping={}
def add(stage,kind,names):
 for name in names.split():assert name not in mapping;mapping[name]=(stage,kind)
add(1,'VOID','edr_behavior_from_slot')
add(2,'VOID','enrich_process_integrity_context')
add(2,'INT','p0_bind_process_generation p0_bind_file_read_cached_generation edr_process_generation_query_live edr_process_generation_validate_live edr_process_parent_pid_query_live')
add(3,'INT','enrich_process_token_identity')
add(4,'VOID','edr_local_evidence_cache_observe_process edr_local_evidence_cache_enrich_behavior edr_local_evidence_cache_resolve_commands')
add(4,'INT','edr_local_evidence_cache_save_command_fact edr_local_evidence_cache_pmfe_apply_scope edr_local_evidence_cache_is_candidate edr_local_evidence_cache_pmfe_result_pending')
add(5,'INT','apply_process_evidence edr_process_evidence_request edr_process_evidence_pending_take edr_process_evidence_pending_add edr_process_evidence_poll')
add(5,'VOID','apply_process_evidence_result')
add(6,'INT','p0_process_collector_evidence_gate p0_process_evidence_candidate p0_process_create_candidate edr_p0_rule_try_emit_status edr_p0_rule_try_emit_with_command_facts_status edr_p0_rule_try_emit edr_p0_rule_emit_ruleset_evaluation_gate edr_p0_rule_emit_pre_evaluation_gate edr_p0_rule_emit_collector_evidence_gate edr_p0_rule_ir_evaluate_record edr_p0_rule_ir_br_matches_any edr_p0_rule_ir_file_read_path_may_match edr_p0_rule_ir_process_create_command_pending')
add(6,'VOID','edr_p0_rule_ir_evaluation_free')
add(7,'VOID','edr_correlation_evaluate edr_net_fanout_on_event')
add(8,'VOID','process_one_record process_enriched_record process_ready_record edr_local_evidence_cache_record_behavior edr_detection_decision_evaluate_after_p0')
add(8,'INT','edr_preprocess_admit_telemetry')
changes=[]
for name,(stage,kind) in mapping.items():
 for m in re.finditer(r'\b'+name+r'\s*\(',masked):
  owner=next((f for f in functions if f['open']<m.start()<f['end']),None)
  if owner is None:continue
  depth=1;i=m.end()
  while depth:
   depth+=(masked[i]=='(')-(masked[i]==')');i+=1
  index=len(owner['calls']);prior=f'substage_previous[{index}]';old=s[m.start():i]
  c={'start':m.start(),'end':i,'old':old,'previous':prior,'stage':stage,'kind':kind,'owner':owner['name'],'line':s.count('\n',0,m.start())+1}
  owner['calls'].append(c);changes.append(c)
changes.sort(key=lambda c:c['start']);assert all(a['end']<=c['start'] for a,c in zip(changes,changes[1:]))
assert len(changes) == 79, 'review fixed pipeline IDs 1..79 before changing probes'
for callsite_id,c in enumerate(changes,1):
 c['callsite_id']=callsite_id
 c['new']=f"PREPROCESS_SUBSTAGE_{c['kind']}({c['stage']}u, {callsite_id}u, {c['previous']}, {c['old']})"
insertions=[]
for f in functions:
 if f['calls']:
  text='\n  /* Each callsite owns its previous frontiers on this worker stack. */\n  uint64_t substage_previous['+str(len(f['calls']))+'];'
  changes.append({'start':f['open']+1,'end':f['open']+1,'old':'','new':text,'declaration':True,'owner':f['name']});insertions.append(text)
changed=s
for c in sorted(changes,key=lambda c:c['start'],reverse=True):changed=changed[:c['start']]+c['new']+changed[c['end']:]
header=(template_base/'service_substage_frontier.inc').read_bytes().decode('utf-8')
needle=source_marker('static atomic_uint s_worker_phase;');assert changed.count(needle)==1;changed=changed.replace(needle,needle+'\n'+header)
old='static void process_one_slot(const EdrEventSlot *slot) {';new='static void process_one_slot_impl(const EdrEventSlot *slot) {';assert changed.count(old)==1;changed=changed.replace(old,new)
wrapper='''/* Preserve every early-return path in the slot body, and clear its frontier
 * only after that exact invocation returns. No stop or dispatch rule changes. */
static void process_one_slot(const EdrEventSlot *slot) {
  preprocess_substage_clear();
  process_one_slot_impl(slot);
  preprocess_substage_clear();
}

'''
needle=source_marker('#ifdef _WIN32\nstatic DWORD WINAPI preprocess_main(void *arg) {');assert changed.count(needle)==1;changed=changed.replace(needle,wrapper+needle)
entry='#ifdef _WIN32\n  preprocess_substage_worker_enter();\n#endif\n'
needle=source_marker('  (void)arg;\n  for (;;) {');assert changed.count(needle)==1;changed=changed.replace(needle,entry+needle)
exit_hook='  preprocess_substage_worker_exit();\n'
needle=source_marker('  atomic_store(&s_preprocess_exited, 1);\n  return 0;');assert changed.count(needle)==1;changed=changed.replace(needle,exit_hook+needle)
wait_original=source_marker('    const DWORD wait_result = WaitForSingleObject(s_thread, 60000);')
wait_generated='''    PreprocessJoinSamples join_samples;
    DWORD sampled_wait_error;
    const DWORD wait_result = preprocess_join_sampled_wait(s_thread, &sampled_wait_error, &join_samples);
    preprocess_join_samples_print(&join_samples);'''
assert changed.count(wait_original)==1;changed=changed.replace(wait_original,wait_generated)
error_original='const DWORD wait_error = wait_result == WAIT_FAILED ? GetLastError() : 0u;'
error_generated='const DWORD wait_error = sampled_wait_error;'
assert changed.count(error_original)==1;changed=changed.replace(error_original,error_generated)
before='  const unsigned substage_before = atomic_load_explicit(&s_worker_substage, memory_order_relaxed);\n'
needle=source_marker('  const unsigned phase_before = atomic_load_explicit(&s_worker_phase, memory_order_relaxed);\n');assert changed.count(needle)==1;changed=changed.replace(needle,needle+before)
after='      const unsigned substage_after = atomic_load_explicit(&s_worker_substage, memory_order_relaxed);\n'
needle='      '+error_generated+source_newline;assert changed.count(needle)==1;changed=changed.replace(needle,needle+after)
log='''      /* Separate versioned closed-set projection; old join/queue lines stay exact. */
      fprintf(stderr, "[preprocess] worker substage diagnostic version=1 substage_before=%u substage_after=%u\\n",
              substage_before, substage_after);
'''
needle=source_marker('      /* Diagnostic reads only: busy bus snapshots are unknown, PMFE queue\n');assert changed.count(needle)==1;changed=changed.replace(needle,log+needle)
# Prove all wrapped calls can be stripped to the original byte-exact source.
restored=changed.replace(log,'',1).replace(before,'',1).replace(after,'',1).replace(wrapper,'',1).replace(new,old,1).replace('\n'+header,'',1)
restored=restored.replace(entry,'',1).replace(exit_hook,'',1).replace(wait_generated,wait_original,1).replace(error_generated,error_original,1)
for text in insertions:assert text in restored;restored=restored.replace(text,'',1)
for c in reversed(sorted((c for c in changes if not c.get('declaration')),key=lambda c:c['start'])):
 assert c['new'] in restored;restored=restored.replace(c['new'],c['old'],1)
assert restored==s

encoded = changed.encode('utf-8')
reversed_raw = restored.encode('utf-8')
assert reversed_raw == raw
assert source.read_bytes() == raw, 'pipeline source changed during generation'
target = output/'pipeline.service.instrumented.c'
target.write_bytes(encoded)
actual = target.read_bytes()
assert actual == encoded
manifest = {
    'schema': 'edr.test.service-substage-source.v2',
    'source': str(source), 'output': str(target),
    'source_sha256': hashlib.sha256(raw).hexdigest(),
    'generated_sha256': hashlib.sha256(actual).hexdigest(),
    'reversed_sha256': hashlib.sha256(reversed_raw).hexdigest(),
    'inverse_raw_exact': reversed_raw == raw,
    'generator_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    'template_sha256': hashlib.sha256((template_base/'service_substage_frontier.inc').read_bytes()).hexdigest(),
    'closed_set': {'0':'unknown','1':'decode','2':'generation','3':'token',
                   '4':'cache','5':'evidence','6':'P0','7':'correlation','8':'record'},
    'callsite_inventory': {'unknown':0,'count':79,'order':'ascending raw decoded source offset',
                          'phase_bins':13,'callsite_bins':128},
    'join_sampling': {'version':2,'interval_ms':10,'sample_cap':6001,'absolute_deadline_ns':60000000000,
                      'clock_owner':'stop observer only','new_threads':0,
                      'deadline_boundary':'post-wait now >= deadline returns WAIT_TIMEOUT; WAIT_FAILED preserves original error',
                      'line_prefix':'[preprocess] worker join samples version=2',
                      'writer_gate':'preprocess_main registered Windows thread ID'},
    'changes': [c for c in changes if not c.get('declaration')],
    'local_previous_arrays': [{'owner': f['name'], 'size':len(f['calls'])}
                              for f in functions if f['calls']],
    'raw_reversal': {'remove_header': '\n'+header, 'remove_wrapper':wrapper,
                     'rename_header_from':new, 'rename_header_to':old,
                     'remove_local_declarations':insertions,
                     'remove_observer_before':before,'remove_observer_after':after,
                     'remove_timeout_log':log,'remove_worker_entry':entry,'remove_worker_exit':exit_hook,
                     'wait_generated':wait_generated,'wait_original':wait_original,
                     'error_generated':error_generated,'error_original':error_original},
    'offset_unit': 'Python Unicode code point in exact decoded source, not UTF-8 byte offset',
    'limitations': ['only for EXCLUDE_FROM_ALL diagnostic target; not a release source',
                    'independent relaxed frontier loads, not atomic stack or timing',
                    'business calls and timeout unchanged; observer uses bounded sampling waits',
                    'frontier writes require the registered preprocess worker thread',
                    'only a normal slot-body return guarantees the wrapper clears zero',
                    'nominal wait samples, not exact durations or an atomic phase/callsite stack',
                    'observer scheduling after the deadline can conservatively reject an earlier worker exit',
                    'unwrapped external calls retain their nearest wrapped caller ID',
                    'non-Windows generated code does not publish Windows callsite frontiers']}
# The second owner is generated independently. Only this public void body is
# renamed; the original ABI wrapper restores every return/goto through one scope.
cache_source = root/'src/storage/local_evidence_cache.c'
cache_raw = cache_source.read_bytes()
cache_text = cache_raw.decode('utf-8')
assert '\r' not in cache_text.replace('\r\n', ''), 'unsupported cache bare CR'
assert not ('\r\n' in cache_text and cache_text.count('\n') != cache_text.count('\r\n')), 'unsupported mixed cache line endings'
cache_masked = mask_c(cache_text)
cache_old_header = 'void edr_local_evidence_cache_record_behavior(const EdrBehaviorRecord *r) {'
cache_new_header = 'static void service_diag_record_behavior_impl(const EdrBehaviorRecord *r) {'
assert cache_text.count(cache_old_header) == 1
cache_start = cache_text.index(cache_old_header)
cache_open = cache_start + len(cache_old_header) - 1
cache_depth, cache_end = 1, cache_open + 1
while cache_depth:
 cache_depth += (cache_masked[cache_end] == '{') - (cache_masked[cache_end] == '}');cache_end += 1
cache_mapping = {}
def cache_add(kind, semantic, names):
 for name in names.split():
  assert name not in cache_mapping
  cache_mapping[name] = (kind, semantic)
cache_add('VOID', 'lock_acquire', 'evidence_cache_lock')
cache_add('VOID', 'lock_release', 'evidence_cache_unlock')
cache_add('INT', 'value_classify', 'evidence_should_store_record evidence_is_low_value_file_noise candidate_dedupe_reuse evidence_cache_pressure_active')
cache_add('U32', 'context_match', 'context_window_matches context_before_count')
cache_add('INT', 'ordinary_coalesce', 'ordinary_aggregate_should_coalesce')
cache_add('VOID', 'hot_ring_copy', 'context_ring_capture ring_record')
cache_add('VOID', 'metric_or_failure_may_flush_sql', 'record_metric_drop record_persistence_failure')
cache_add('INT', 'candidate_lookup_or_budget_may_maintain', 'sqlite_candidate_exists sqlite_size_budget_allow_mode')
cache_add('INT', 'candidate_transaction', 'sqlite_record_candidate')
cache_add('VOID', 'candidate_post_commit', 'promote_context_before_window mark_context_window candidate_dedupe_admit')
cache_add('INT', 'context_prepare_budget_transaction', 'sqlite_record_budgeted_context_artifacts')
cache_changes = []
for name, (kind, semantic) in cache_mapping.items():
 for m in re.finditer(r'\b'+name+r'\s*\(', cache_masked):
  if not cache_open < m.start() < cache_end: continue
  depth, end = 1, m.end()
  while depth:
   depth += (cache_masked[end] == '(') - (cache_masked[end] == ')');end += 1
  cache_changes.append({'start':m.start(), 'end':end, 'old':cache_text[m.start():end],
                        'kind':kind, 'semantic':semantic, 'owner':'edr_local_evidence_cache_record_behavior',
                        'line':cache_text.count('\n', 0, m.start())+1})
cache_changes.sort(key=lambda c:c['start'])
assert len(cache_changes) == 44, 'review the fixed direct-call cache inventory'
assert all(a['end'] <= c['start'] for a,c in zip(cache_changes, cache_changes[1:]))
for index,c in enumerate(cache_changes):
 site = 81 + index
 assert site < 128, 'fixed namespace exhausted; stop instead of growing it'
 c.update(callsite_id=site, stage=8, previous=f'cache_previous[{index}]')
 c['new'] = f"SERVICE_CACHE_{c['kind']}({site}u, {c['previous']}, {c['old']})"
cache_declaration = '\n  uint64_t cache_previous[44];'
cache_bridge = '''/* Test-only cross-TU bridge: the pipeline owns the sole frontier state. */
extern uint64_t preprocess_substage_enter(unsigned substage, unsigned callsite);
extern void preprocess_substage_leave(uint64_t previous);
static int service_cache_int_leave(uint64_t previous, int result) {
  preprocess_substage_leave(previous); return result;
}
static uint32_t service_cache_u32_leave(uint64_t previous, uint32_t result) {
  preprocess_substage_leave(previous); return result;
}
#define SERVICE_CACHE_VOID(site, previous, call) \\
  ((previous) = preprocess_substage_enter(8u, site), (call), preprocess_substage_leave(previous))
#define SERVICE_CACHE_INT(site, previous, call) \\
  ((previous) = preprocess_substage_enter(8u, site), service_cache_int_leave((previous), (call)))
#define SERVICE_CACHE_U32(site, previous, call) \\
  ((previous) = preprocess_substage_enter(8u, site), service_cache_u32_leave((previous), (call)))
'''
cache_wrapper = '''
/* One envelope covers NULL/early returns and every original goto-done path. */
void edr_local_evidence_cache_record_behavior(const EdrBehaviorRecord *r) {
  const uint64_t previous = preprocess_substage_enter(8u, 80u);
  service_diag_record_behavior_impl(r);
  preprocess_substage_leave(previous);
}
'''
# These three function envelopes deliberately cover all invocations, not just
# record_behavior's direct callsites. Their original conditional-compilation
# scope and complete return paths remain inside the renamed implementation.
nested_envelopes = []
for site, name, semantic, arguments in [
 (125, 'sqlite_prepare_context_artifacts', 'context_prepare_reads', 'r, candidate_ids, candidate_count, prepared'),
 (126, 'sqlite_size_budget_allow', 'capacity_admission_may_maintain', ''),
 (127, 'sqlite_record_context_artifacts', 'context_transaction', 'r, candidate_ids, prepared')]:
 matches = list(re.finditer(r'(?m)^static int '+name+r'\s*\([^;{}]*\)\s*\{', cache_masked))
 assert len(matches) == 1, 'nested helper definition must be unique: '+name
 match = matches[0]
 opened, end, depth = match.end()-1, match.end(), 1
 while depth:
  depth += (cache_masked[end] == '{') - (cache_masked[end] == '}');end += 1
 original_header = cache_text[match.start():match.end()]
 generated_header = original_header.replace(name, 'service_diag_'+name+'_impl', 1)
 wrapper = ('\n/* Nested helper envelope; every original return restores its caller. */\n'+
            original_header+'\n'+
            f'  const uint64_t previous = preprocess_substage_enter(8u, {site}u);\n'+
            f'  const int result = service_diag_{name}_impl({arguments});\n'+
            '  preprocess_substage_leave(previous);\n  return result;\n}\n')
 nested_envelopes.append({'callsite_id':site, 'name':name, 'owner':name, 'kind':'INT',
                          'semantic':semantic, 'line':cache_text.count('\n',0,match.start())+1,
                          'start':match.start(), 'end':end, 'header_end':match.end(),
                          'original_header':original_header, 'generated_header':generated_header,
                          'wrapper':wrapper, 'arguments':arguments})
# The first helper precedes record_behavior's existing bridge, inside the
# original SQLite branch. Declarations introduce no non-SQLite dependency.
nested_bridge = ('/* Test-only nested helpers share the pipeline-owned frontier. */\n'
                 'extern uint64_t preprocess_substage_enter(unsigned substage, unsigned callsite);\n'
                 'extern void preprocess_substage_leave(uint64_t previous);\n')
first_nested = min(c['start'] for c in nested_envelopes)
cache_changed = cache_text
cache_edits = cache_changes + [
 {'start':cache_open+1,'end':cache_open+1,'old':'','new':cache_declaration},
 {'start':cache_start,'end':cache_start+len(cache_old_header),'old':cache_old_header,'new':cache_bridge+cache_new_header},
 {'start':cache_end,'end':cache_end,'old':'','new':cache_wrapper}]
for c in nested_envelopes:
 cache_edits += [
  {'start':c['start'], 'end':c['header_end'], 'old':c['original_header'],
   'new':(nested_bridge if c['start'] == first_nested else '')+c['generated_header']},
  {'start':c['end'], 'end':c['end'], 'old':'', 'new':c['wrapper']}]
for c in sorted(cache_edits, key=lambda c:c['start'], reverse=True):
 cache_changed = cache_changed[:c['start']] + c['new'] + cache_changed[c['end']:]
cache_restored = cache_changed.replace(cache_wrapper, '', 1).replace(cache_bridge+cache_new_header, cache_old_header, 1).replace(cache_declaration, '', 1)
assert cache_restored.count(nested_bridge) == 1
cache_restored = cache_restored.replace(nested_bridge, '', 1)
for c in nested_envelopes:
 assert cache_restored.count(c['wrapper']) == 1
 cache_restored = cache_restored.replace(c['wrapper'], '', 1)
 assert cache_restored.count(c['generated_header']) == 1
 cache_restored = cache_restored.replace(c['generated_header'], c['original_header'], 1)
for c in reversed(cache_changes):
 assert cache_restored.count(c['new']) == 1
 cache_restored = cache_restored.replace(c['new'], c['old'], 1)
assert cache_restored.encode('utf-8') == cache_raw
assert cache_source.read_bytes() == cache_raw, 'cache source changed during generation'
cache_target = output/'cache.service.instrumented.c'
cache_target.write_bytes(cache_changed.encode('utf-8'))
assert cache_target.read_bytes() == cache_changed.encode('utf-8')
namespace = {'phase_bins':13, 'callsite_bins':128, 'unknown':0,
             'pipeline_range':[1,79], 'cache_envelope':80, 'cache_direct_range':[81,124],
             'cache_nested_range':[125,127], 'max_assigned_id':127, 'unassigned_range':[],
             'single_frontier_owner':'generated pipeline registered preprocess worker',
             'sampling_version':2}
manifest['namespace'] = namespace
cache_manifest = {
 'schema':'edr.test.service-cache-source.v2', 'source':str(cache_source), 'output':str(cache_target),
 'source_sha256':hashlib.sha256(cache_raw).hexdigest(),
 'generated_sha256':hashlib.sha256(cache_target.read_bytes()).hexdigest(),
 'reversed_sha256':hashlib.sha256(cache_restored.encode('utf-8')).hexdigest(),
 'inverse_raw_exact':True, 'generator_sha256':manifest['generator_sha256'],
 'template_sha256':manifest['template_sha256'], 'namespace':namespace,
 'changes':cache_changes,
 'nested_envelopes':nested_envelopes,
 'raw_reversal':{'remove_wrapper':cache_wrapper, 'generated_header':cache_bridge+cache_new_header,
                 'original_header':cache_old_header, 'remove_local_declaration':cache_declaration,
                 'remove_nested_bridge':nested_bridge, 'nested_envelopes':nested_envelopes},
 'offset_unit':manifest['offset_unit'],
 'limitations':['unshipped diagnostic only; production cache source and API unchanged',
                'same pipeline thread gate and state; non-owner calls publish nothing',
                'envelope80 means cache-internal work not covered by a direct-call probe',
                'site54 also covers work after record_behavior, including should_emit',
                'metric/failure helpers may flush SQL; budget may run maintenance',
                'context helper includes reads/budget/transaction and exact replay may not write',
                'nested125/126/127 cover preparation/capacity/transaction helpers, not individual SQL or fsync',
                'function envelopes cover every registered-worker call, including record_alert_context; not only site114',
                'one frontier identifies the innermost wrapped helper, not its complete caller stack; do not add nested populations',
                'lock-acquire probe includes existing production lock timing work',
                'nominal samples are not exact time, SQL attribution or additive nested costs']}
for filename, proof in [('SERVICE-SOURCE-TRANSFORM-v2.json',manifest),
                        ('SERVICE-CACHE-SOURCE-TRANSFORM-v2.json',cache_manifest)]:
 (output/filename).write_bytes((json.dumps(proof, indent=2)+'\n').encode('utf-8'))
print(json.dumps({'source_count':2,'pipeline_call_transforms':79,'cache_call_transforms':44,
                  'cache_nested_envelopes':3,
                  'inverse_raw_exact':True, 'max_assigned_id':127, 'callsite_bins':128,
                  'generated_sha256':manifest['generated_sha256'],
                  'cache_generated_sha256':cache_manifest['generated_sha256']}))
