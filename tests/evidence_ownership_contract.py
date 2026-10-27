"""Offline acceptance of scoped receipts; never edits or queries a live cache.

Keep OS births, source observations, physical candidates and actual alerts as
separate denominators. This storage check cannot certify a UI consumer, timing,
capacity or retention window. See evidence_ownership_acceptance.txt.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct


def digest_parts(*parts):
    digest = hashlib.sha256()
    for part in parts:
        raw = part.encode('utf-8')
        digest.update(struct.pack('<I', len(raw)))
        digest.update(raw)
    return digest.hexdigest()


def source_candidate(scope, source):
    return 'p0-' + scope['endpoint_id'] + '-e-' + digest_parts(
        'edr-local-evidence-candidate-v3', scope['endpoint_id'],
        scope['tenant_id'], 'source-event', source)


def uint(value, bits=64, allow_zero=False):
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise ValueError('invalid numeric identity')
    text = str(value)
    if not text.isascii() or not text.isdecimal() or str(int(text)) != text:
        raise ValueError('invalid numeric identity')
    result = int(text)
    if not (0 if allow_zero else 1) <= result < 2**bits:
        raise ValueError('unbound numeric identity')
    return result


def birth(row):
    return (uint(row['pid'], bits=32), uint(row['process_creation_filetime_100ns']))


def unique_json(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate JSON key')
        result[key] = value
    return result


def evaluate(receipt):
    """Validate every supplied row; truncated discovery is unknown, never passed."""
    errors, unknown, overlaps = [], [], []
    counts = {}
    try:
        scope = receipt['scope']
        if not all(isinstance(scope[k], str) and scope[k] for k in ('tenant_id', 'endpoint_id')):
            raise ValueError('missing scope')
        expected = receipt['processes']
        candidates = receipt['candidates']
        alerts = receipt['alerts']
        refs = receipt['parent_facts']
        if not expected or any(len(rows) > 4096 for rows in (expected, candidates, alerts, refs)):
            raise ValueError('empty truth or receipt exceeds bound')
        truth = {birth(row): row for row in expected}
        if len(truth) != len(expected):
            raise ValueError('duplicate OS birth')
        for row in expected:
            uint(row['process_start_key'])
            parent = row['parent']
            uint(parent['process_start_key'])
            if birth(parent)[1] > birth(row)[1] or parent['pid'] == row['pid']:
                raise ValueError('invalid OS parent truth')
        for field in ('candidates_complete', 'alerts_complete', 'sources_complete'):
            if receipt.get(field) is not True:
                unknown.append(field)
        owners, sources, observed_births = {}, set(), set()
        source_owners = {}
        for row in candidates:
            key = birth(row)
            cid = row['candidate_id']
            if cid in owners:
                raise ValueError('duplicate physical candidate')
            owners[cid] = row
            if row['scope'] != scope or key not in truth or type(row['type']) is not int or row['type'] != 1:
                raise ValueError('candidate scope or birth mismatch')
            if uint(row['process_start_key']) != uint(truth[key]['process_start_key']):
                raise ValueError('candidate generation mismatch')
            if row['local_retention_state'] != 'retained':
                errors.append('candidate_not_retained:' + cid)
            aliases = row['source_event_ids']
            if not aliases or len(aliases) > 16 or len(set(aliases)) != len(aliases):
                raise ValueError('invalid source alias set')
            if row.get('source_event_ids_complete') is not True:
                unknown.append('source_aliases_incomplete:' + cid)
            if any(not isinstance(x, str) or not x for x in aliases):
                raise ValueError('invalid source identity')
            if sum(source_candidate(scope, x) == cid for x in aliases) != 1:
                errors.append('candidate_source_hash_mismatch:' + cid)
            if row['bundle_source_event_id'] not in aliases:
                errors.append('bundle_source_not_retained:' + cid)
            for source in aliases:
                source_owners.setdefault(source, []).append(cid)
            sources.update(aliases)
            observed_births.add(key)
        if observed_births != set(truth):
            errors.append('missing_OS_birth')
        alert_sources, alert_ids = set(), set()
        for alert in alerts:
            source = alert['source_event_id']
            if alert['scope'] != scope or birth(alert) not in truth or alert['alert_id'] in alert_ids:
                raise ValueError('alert scope, birth or identity mismatch')
            alert_ids.add(alert['alert_id']); alert_sources.add(source)
            cid = source_candidate(scope, source)
            row = owners.get(cid)
            if row is None or birth(row) != birth(alert):
                errors.append('alert_exact_owner_missing:' + source)
        # A historical bridge may precede a later exact alert snapshot.
        # Keep every alias visible; only the exact source key owns its query.
        for source, ids in source_owners.items():
            if len(ids) != 1:
                exact = source_candidate(scope, source)
                overlaps.append({'source_event_id': source, 'candidate_ids': ids,
                                 'exact_owner': exact if exact in ids else None})
                if exact not in ids:
                    errors.append('ambiguous_source_owners:' + source)
        by_owner = {}
        for ref in refs:
            cid = ref['candidate_id']
            if ref['scope'] != scope or cid not in owners or ref['artifact_id'] != cid + ':alert_parent_context':
                raise ValueError('parent reference ownership mismatch')
            by_owner.setdefault(cid, []).append(ref)
            raw = ref['manifest_template_json']
            if not isinstance(raw, str) or not 0 < len(raw.encode('utf-8')) <= 65536:
                raise ValueError('parent fact exceeds bound')
            fact = json.loads(raw, object_pairs_hook=unique_json)
            source = fact['source_event_id']
            source_hash = digest_parts('edr-local-evidence-artifact-source-id-v1', source)
            if (ref['fact_id'] != digest_parts('edr-local-evidence-context-fact-v1',
                    scope['endpoint_id'], scope['tenant_id'], source_hash, raw)
                    or source_candidate(scope, source) != cid):
                errors.append('parent_fact_hash_or_source_mismatch:' + cid)
            row, child, parent = owners[cid], fact['child'], fact['parent']
            target = truth[birth(row)]
            if (fact['schema'] != 'edr.local-alert-parent-context.v1'
                    or birth(child) != birth(row)
                    or uint(child['process_start_key']) != uint(row['process_start_key'])
                    or uint(fact['event_time_ns'], bits=63) != uint(row['event_time_ns'], bits=63)
                    or fact['parent_generation_conflict'] is not False
                    or fact['parent_pid_state'] != 1 or parent['parent_pid_state'] != 1
                    or uint(fact['parent_pid']) != uint(parent['pid'])
                    or birth(parent) != birth(target['parent'])
                    or uint(parent['process_start_key']) != uint(target['parent']['process_start_key'])):
                errors.append('parent_identity_mismatch:' + cid)
            if uint(row['alert_context_protect_until_active_ms'], allow_zero=True) == 0:
                errors.append('alert_floor_missing:' + cid)
        for source in alert_sources:
            cid = source_candidate(scope, source)
            if len(by_owner.get(cid, [])) != 1:
                errors.append('alert_parent_reference_absent_or_ambiguous:' + source)
        no_alert = set()
        for disposition in receipt.get('no_alert_sources', []):
            source = disposition['source_event_id']
            if (disposition['scope'] != scope or source not in sources or source in alert_sources
                    or source in no_alert or not disposition['reason'] or not disposition['evidence_receipt']):
                raise ValueError('unsupported no-alert disposition')
            no_alert.add(source)
        for source in sorted(sources - alert_sources - no_alert):
            unknown.append('source_disposition_unknown:' + source)
        for cid in by_owner:
            if len(by_owner[cid]) != 1:
                errors.append('ambiguous_parent_references:' + cid)
        counts = {'os_births': len(truth), 'observed_births': len(observed_births),
                  'source_events': len(sources), 'physical_candidates': len(owners),
                  'alerts': len(alert_ids), 'alert_sources': len(alert_sources),
                  'parent_references': len(refs), 'sources_without_alert': len(no_alert)}
    except (KeyError, TypeError, ValueError, OverflowError, UnicodeError, RecursionError):
        errors.append('malformed_or_unbound_receipt')
    return {'ownership_status': 'failed' if errors else 'unknown' if unknown else 'passed',
            'counts': counts, 'errors': errors, 'unknown': unknown,
            'historical_alias_overlaps': overlaps,
            'consumer_acceptance': 'requires_new_signed_query_receipt',
            'prior_acceptance_overridden': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('receipt', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    if args.receipt.stat().st_size > 16 * 1024 * 1024:
        parser.error('receipt exceeds 16 MiB')
    with args.receipt.open(encoding='utf-8') as file:
        report = evaluate(json.load(file, object_pairs_hook=unique_json))
    with args.output.open('x', encoding='utf-8') as file:
        json.dump(report, file, ensure_ascii=False, indent=2)
        file.write('\n')
    print(report['ownership_status'])
    return 0 if report['ownership_status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
