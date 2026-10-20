from pathlib import Path
import re,json,hashlib,sys
template_base=Path(__file__).resolve().parent
base=Path(sys.argv[2]).resolve() if len(sys.argv)>2 else template_base
base.mkdir(parents=True,exist_ok=True)
if len(sys.argv)<2:raise SystemExit('usage: generate_diagnostic_source.py SOURCE_DIR [OUTPUT_DIR]')
root=Path(sys.argv[1]).resolve()
stages=[('process_one_slot','VOID'),('process_pending_process_creates','VOID'),('process_one_record','VOID'),('enrich_process_integrity_context','VOID'),('apply_process_evidence','INT'),('process_enriched_record','VOID'),('edr_local_evidence_cache_observe_process','VOID'),('edr_local_evidence_cache_enrich_behavior','VOID'),('edr_local_evidence_cache_save_command_fact','INT'),('edr_p0_rule_try_emit_status','INT'),('edr_p0_rule_try_emit_with_command_facts_status','INT'),('edr_p0_rule_try_emit','INT'),('edr_correlation_evaluate','VOID'),('edr_ave_cross_engine_feed_from_record','VOID'),('edr_command_dispatch_recommended_forensics','INT'),('edr_local_evidence_cache_is_candidate','INT'),('edr_local_evidence_cache_record_behavior','VOID'),('edr_local_evidence_cache_pmfe_apply_scope','INT'),('edr_local_evidence_cache_poll_maintenance','VOID'),('poll_p0_source_only_durable_retry','VOID'),('edr_event_batch_poll_timeout','VOID'),('edr_correlation_poll_maintenance','VOID'),('poll_summary_flush','VOID'),('poll_pending_process_evidence','VOID'),('poll_pmfe_followup_recovery','VOID'),('edr_local_evidence_cache_resolve_commands','VOID'),('enrich_process_token_identity','INT'),('p0_bind_process_generation','INT'),('p0_resolve_live_parent_generation','INT'),('edr_behavior_from_slot','VOID'),('edr_local_evidence_cache_pmfe_result_pending','INT'),('process_ready_record','VOID'),('edr_process_evidence_request','INT'),('edr_storage_queue_p0_source_only_latch_prepare_local','INT'),('edr_storage_queue_p0_source_only_commit_local_typed_handoff','INT'),('edr_storage_queue_p0_source_only_commit_local','INT'),('p0_source_only_prepare_record','INT'),('p0_source_only_enqueue_record','INT'),('edr_storage_queue_p0_source_only_commit_local_group','INT')]
api='''#ifndef EDR_PRIVATE_DIAG_API_H
#define EDR_PRIVATE_DIAG_API_H
void diag_enter(unsigned id);
void diag_leave(unsigned id);
int diag_int_leave(unsigned id,int rc);
#define DIAG_VOID(id, call) (diag_enter(id), (call), diag_leave(id))
#define DIAG_INT(id, call) (diag_enter(id), diag_int_leave(id, (call)))
#endif
'''
(base/'diag_api.h').write_bytes(api.encode('utf-8'))
header='''/* Private numeric diagnostics only; original calls execute exactly once. */
#include <assert.h>
#include <errno.h>
#include "edr/time_util.h"
#include "diag_api.h"
typedef struct { uint64_t calls,total_ns,max_ns; } DiagMetric;
static DiagMetric diag_metrics[40];
static struct { unsigned stage; uint64_t start; } diag_stack[128];
static unsigned diag_depth,diag_enabled,diag_current_incoming_slot_type;
void diag_enter(unsigned id) { int prior_errno=errno;
#ifdef _WIN32
DWORD prior_error=GetLastError();
#endif
if(diag_enabled){assert(id>0 && id<40 && diag_depth<128);diag_stack[diag_depth].stage=id;diag_stack[diag_depth++].start=edr_monotonic_ns();}
#ifdef _WIN32
SetLastError(prior_error);
#endif
errno=prior_errno; }
void diag_leave(unsigned id) { int prior_errno=errno;
#ifdef _WIN32
DWORD prior_error=GetLastError();
#endif
if(diag_enabled){assert(diag_depth && diag_stack[diag_depth-1].stage==id);uint64_t elapsed=edr_monotonic_ns()-diag_stack[--diag_depth].start;diag_metrics[id].calls++;diag_metrics[id].total_ns+=elapsed;if(elapsed>diag_metrics[id].max_ns)diag_metrics[id].max_ns=elapsed;}
#ifdef _WIN32
SetLastError(prior_error);
#endif
errno=prior_errno; }
int diag_int_leave(unsigned id,int rc) {diag_leave(id);return rc;}
'''
def transform(relative,filename,top):
 source=root/relative;original_bytes=source.read_bytes();original=original_bytes.decode('utf-8');changes=[]
 for n,(name,kind) in enumerate(stages,1):
  for m in re.finditer(r'\b'+name+r'\s*\(',original):
   line=original[original.rfind('\n',0,m.start())+1:m.start()]
   if re.match(r'^(?:static\s+)?(?:const\s+)?(?:void|int|EdrError)\s+$',line):continue
   depth=0;state=None;esc=False;end=None
   for i in range(m.end()-1,len(original)):
    c=original[i]
    if state:
     if esc:esc=False
     elif c=='\\':esc=True
     elif c==state:state=None
     continue
    if c in ('"',"'"):state=c;continue
    if c=='(':depth+=1
    elif c==')':
     depth-=1
     if not depth:end=i+1;break
   assert end;old=original[m.start():end];changes.append({'start':m.start(),'end':end,'original':old,'replacement':f'DIAG_{kind}({n}, {old})','stage':n,'line':original.count('\n',0,m.start())+1})
 changes.sort(key=lambda x:x['start']);assert all(a['end']<=c['start'] for a,c in zip(changes,changes[1:]));parts=[];cursor=0
 for c in changes:parts.extend([original[cursor:c['start']],c['replacement']]);cursor=c['end']
 parts.append(original[cursor:]);changed=''.join(parts);insertions=[]
 if top:
  marker='static int s_preprocess_active;';assert changed.count(marker)==1;changed=changed.replace(marker,header+'\n'+marker);insertions.append((header+'\n',''))
  marker='static void process_one_slot(const EdrEventSlot *slot) {';new=marker+'\n  diag_current_incoming_slot_type=(unsigned)slot->type;';assert changed.count(marker)==1;changed=changed.replace(marker,new);insertions.append((new,marker))
 else:
  addition='#include "diag_api.h"\n';changed=addition+changed;insertions.append((addition,''))
 restored=changed
 for new,old in insertions:restored=restored.replace(new,old,1)
 for c in reversed(changes):assert c['replacement'] in restored;restored=restored.replace(c['replacement'],c['original'],1)
 assert restored==original
 (base/filename).write_bytes(changed.encode('utf-8'))
 return {'source':str(source),'original_sha256':hashlib.sha256(original_bytes).hexdigest(),'instrumented_sha256':hashlib.sha256(changed.encode()).hexdigest(),'inverse_exact':True,'changes':changes,'insertions':insertions}
result={'schema':'edr.private.pipeline-diag-source.v2','stages':[{'id':i,'name':n,'kind':k} for i,(n,k) in enumerate(stages,1)],'sources':[transform('src/preprocess/preprocess_pipeline.c','pipeline.instrumented.c',True),transform('src/preprocess/p0_rule_direct_emit.c','p0.instrumented.c',False)],'limitations':['timings inclusive; never sum stage totals','one synchronous worker only; metrics read after loop returns, no live read on join failure','stage29 callback has no direct invocation wrapper; zero does not prove callback not executed','slot type describes incoming slot, not nested coalescer record']}
(base/'SOURCE-TRANSFORM-v2.json').write_bytes((json.dumps(result,indent=2)+'\n').encode('utf-8'))
if base!=template_base:(base/'fixture-main.inc').write_bytes((template_base/'fixture-main.inc').read_bytes())
(base/'pipeline.diag.c').write_bytes(b'#include "pipeline.instrumented.c"\n#include "fixture-main.inc"\n')
print(json.dumps({'source_count':len(result['sources']),'calls':sum(len(s['changes']) for s in result['sources']),'inverse_exact':all(s['inverse_exact'] for s in result['sources'])}))
