import copy
import json
import unittest
from evidence_ownership_contract import digest_parts, evaluate, source_candidate


def fixture():
    scope = {'tenant_id': 'fixture-tenant', 'endpoint_id': 'fixture-endpoint'}
    parent = {'pid': 50, 'process_start_key': '500', 'process_creation_filetime_100ns': '100'}
    r = {'scope': scope, 'processes': [], 'candidates': [], 'alerts': [], 'parent_facts': [],
         'no_alert_sources': [], 'candidates_complete': True, 'alerts_complete': True,
         'sources_complete': True}
    for i in range(10):
        child = {'pid': 100+i, 'process_start_key': str(1000+i),
                 'process_creation_filetime_100ns': str(200+i)}
        r['processes'].append(dict(child, parent=parent))
        source = 'fixture-source-' + str(i)
        cid = source_candidate(scope, source)
        r['candidates'].append(dict(child, scope=scope, candidate_id=cid, type=1,
            event_time_ns=str(100000+i), local_retention_state='retained',
            source_event_ids=[source], source_event_ids_complete=True,
            bundle_source_event_id=source, alert_context_protect_until_active_ms=72000))
        r['alerts'].append(dict(child, scope=scope, source_event_id=source, alert_id='alert-'+str(i)))
        fact = {'schema': 'edr.local-alert-parent-context.v1', 'source_event_id': source,
                'candidate_id': None, 'event_time_ns': str(100000+i), 'child': child,
                'parent': dict(parent, parent_pid_state=1), 'parent_pid': 50,
                'parent_pid_state': 1, 'parent_generation_conflict': False}
        raw = json.dumps(fact, separators=(',', ':'))
        r['parent_facts'].append({'scope': scope, 'candidate_id': cid,
            'artifact_id': cid+':alert_parent_context', 'manifest_template_json': raw,
            'fact_id': digest_parts('edr-local-evidence-context-fact-v1', scope['endpoint_id'],
                scope['tenant_id'], digest_parts('edr-local-evidence-artifact-source-id-v1', source), raw)})
    # Two extra ordinary source observations share OS births, not alert ownership.
    for i in (3, 4):
        source = 'fixture-extra-' + str(i)
        r['candidates'].append(dict(r['candidates'][i],
            candidate_id=source_candidate(scope, source), source_event_ids=[source],
            bundle_source_event_id=source, alert_context_protect_until_active_ms=0))
        r['no_alert_sources'].append({'scope': scope, 'source_event_id': source,
                                     'reason': 'ordinary_only', 'evidence_receipt': 'fixture-disposition'})
    return r


class OwnershipContract(unittest.TestCase):
    def test_all_ten_births_and_twelve_candidates_preserved(self):
        result = evaluate(fixture())
        self.assertEqual(result['ownership_status'], 'passed')
        self.assertEqual(result['counts'], {'os_births': 10, 'observed_births': 10,
            'source_events': 12, 'physical_candidates': 12, 'alerts': 10,
            'alert_sources': 10, 'parent_references': 10, 'sources_without_alert': 2})
        self.assertFalse(result['prior_acceptance_overridden'])
        self.assertEqual(result['consumer_acceptance'], 'requires_new_signed_query_receipt')

    def test_unknown_origin_is_not_inferred_from_latest_enrichment(self):
        r = fixture(); r['no_alert_sources'] = []
        result = evaluate(r)
        self.assertEqual(result['ownership_status'], 'unknown')
        self.assertEqual(len(result['unknown']), 2)

    def test_ambiguous_latest_bundle_is_not_a_hash_corruption(self):
        r = fixture(); c = r['candidates'][10]; source = r['alerts'][3]['source_event_id']
        c['source_event_ids'].append(source); c['bundle_source_event_id'] = source
        result = evaluate(r)
        self.assertEqual(result['ownership_status'], 'passed')
        self.assertEqual(result['errors'], [])
        self.assertEqual(len(result['historical_alias_overlaps']), 1)
        self.assertEqual(result['historical_alias_overlaps'][0]['exact_owner'],
                         r['candidates'][3]['candidate_id'])

    def test_multiple_alias_owners_without_exact_owner_fail(self):
        r = fixture(); source = 'ambiguous-alias'
        for row in r['candidates'][10:]:
            row['source_event_ids'].append(source)
        result = evaluate(r)
        self.assertIn('ambiguous_source_owners:'+source, result['errors'])

    def test_single_ordinary_bridge_hashes_to_original_alias(self):
        r = fixture(); c = r['candidates'][10]; source = 'fixture-extra-alias'
        c['source_event_ids'].append(source); c['bundle_source_event_id'] = source
        r['no_alert_sources'].append(dict(r['no_alert_sources'][0], source_event_id=source))
        self.assertEqual(evaluate(r)['ownership_status'], 'passed')

    def test_missing_birth_is_failed(self):
        r = fixture(); r['candidates'].pop(0)
        self.assertIn('missing_OS_birth', evaluate(r)['errors'])

    def test_actual_alert_requires_its_own_parent_fact(self):
        r = fixture(); r['parent_facts'].pop(3)
        self.assertTrue(any(x.startswith('alert_parent_reference_absent') for x in evaluate(r)['errors']))

    def test_bad_hash_and_wrong_parent_are_failed(self):
        r = fixture(); f = r['parent_facts'][0]
        obj = json.loads(f['manifest_template_json']); obj['parent']['pid'] = 51
        f['manifest_template_json'] = json.dumps(obj)
        result = evaluate(r)
        self.assertTrue(any(x.startswith('parent_fact_hash_or_source') for x in result['errors']))
        self.assertTrue(any(x.startswith('parent_identity_mismatch') for x in result['errors']))

    def test_generation_and_tenant_do_not_cross(self):
        for field, value in [('process_creation_filetime_100ns', '999'),
                             ('process_start_key', '999'), ('scope', {})]:
            r = fixture(); r['candidates'][0][field] = value
            self.assertEqual(evaluate(r)['ownership_status'], 'failed')

    def test_truncation_is_unknown(self):
        for field in ('candidates_complete', 'alerts_complete', 'sources_complete'):
            r = fixture(); r[field] = False
            self.assertEqual(evaluate(r)['ownership_status'], 'unknown')
        r = fixture(); r['candidates'][0]['source_event_ids_complete'] = False
        self.assertEqual(evaluate(r)['ownership_status'], 'unknown')

    def test_missing_floor_and_invalid_numeric_identity_fail(self):
        r = fixture(); r['candidates'][0]['alert_context_protect_until_active_ms'] = 0
        self.assertTrue(any(x.startswith('alert_floor_missing:') for x in evaluate(r)['errors']))
        for field, value in [('pid', True), ('pid', 2**32), ('type', True),
                             ('event_time_ns', str(2**63)), ('process_start_key', '01')]:
            r = fixture(); r['candidates'][0][field] = value
            self.assertEqual(evaluate(r)['ownership_status'], 'failed')

    def test_duplicate_reference_is_failed(self):
        r = fixture(); r['parent_facts'].append(copy.deepcopy(r['parent_facts'][0]))
        self.assertEqual(evaluate(r)['ownership_status'], 'failed')

    def test_missing_fields_and_duplicate_json_fail_closed(self):
        for key in ('scope', 'processes', 'candidates', 'alerts', 'parent_facts'):
            r = fixture(); del r[key]
            self.assertEqual(evaluate(r)['ownership_status'], 'failed')
        r = fixture(); r['parent_facts'][0]['manifest_template_json'] = '{"a":1,"a":2}'
        self.assertEqual(evaluate(r)['ownership_status'], 'failed')

    def test_cannot_label_an_alert_source_as_no_alert(self):
        r = fixture(); r['no_alert_sources'][0]['source_event_id'] = r['alerts'][0]['source_event_id']
        self.assertEqual(evaluate(r)['ownership_status'], 'failed')


if __name__ == '__main__':
    unittest.main()
