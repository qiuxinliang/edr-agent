"""The offline comparison must not hide an isolated loss behind its median."""
import copy
import unittest

from run_evidence_cache_cost_comparison import (DIGESTS, observable_inventory,
    profile_status, repeated_recall_consistency)


class ObservableInventoryTest(unittest.TestCase):
    def samples(self):
        row={key:'same-digest' for key in DIGESTS}
        row.update({key:'1' for key in ('candidates','post_refs','recall_rows',
                    'reopened_recall_rows','required_pre','required_post','required_command')})
        row.update(rejected='0',dangling_refs='0',recall_queries='64',
                   recall_consistent='1',recall_first_mismatch_query='0')
        return {variant:[copy.deepcopy(row) for _ in range(7)] for variant in ('baseline','current')}

    def test_equal_and_independent_facts_present(self):
        equal,required,_=observable_inventory(self.samples())
        self.assertTrue(equal)
        self.assertTrue(all(required.values()))

    def test_one_bad_count_is_not_hidden_by_median(self):
        rows=self.samples();rows['current'][3]['reopened_recall_rows']='0'
        self.assertFalse(observable_inventory(rows)[0])

    def test_each_content_boundary_is_compared(self):
        for key in DIGESTS:
            with self.subTest(boundary=key):
                rows=self.samples();rows['current'][3][key]='different-content'
                self.assertFalse(observable_inventory(rows)[0])

    def test_equal_broken_readers_do_not_pass_independent_oracle(self):
        for key in ('required_pre','required_post','required_command'):
            with self.subTest(fact=key):
                rows=self.samples()
                for samples in rows.values():
                    for row in samples:row[key]='0'
                equal,required,_=observable_inventory(rows)
                self.assertTrue(equal)
                self.assertFalse(any(required.values()))

    def test_single_failed_required_fact_is_visible(self):
        rows=self.samples();rows['current'][0]['required_command']='0'
        _,required,_=observable_inventory(rows)
        self.assertTrue(required['baseline'])
        self.assertFalse(required['current'])

    def test_empty_or_unpaired_receipts_are_not_success(self):
        for samples in ({}, {'baseline':[], 'current':[]},
                        {'baseline':[{}], 'current':[]}):
            with self.assertRaises(ValueError):observable_inventory(samples)

    def test_equal_reopen_failure_is_not_success(self):
        self.assertEqual(profile_status(True,{'baseline':True,'current':True},
                                       {'baseline':False,'current':False},
                                       {'baseline':True,'current':True}),
                         'WORKLOAD_RECOVERY_FAILED')

    def test_equal_missing_fact_is_not_success(self):
        self.assertEqual(profile_status(True,{'baseline':False,'current':False},
                                       {'baseline':True,'current':True},
                                       {'baseline':True,'current':True}),
                         'REQUIRED_FACTS_MISSING')

    def test_one_bad_recall_cannot_be_hidden_by_final_good_response(self):
        rows=self.samples()
        rows['current'][0].update(recall_first_mismatch_query='2',recall_consistent='0')
        repeated=repeated_recall_consistency(rows)
        self.assertEqual(repeated,{'baseline':True,'current':False})
        self.assertEqual(profile_status(True,{'baseline':True,'current':True},
                                       {'baseline':True,'current':True},repeated),
                         'REPEATED_RECALL_DIFFERENCE')

    def test_incomplete_or_inconsistent_recall_receipt_fails(self):
        for key,value in (('recall_queries','63'),('recall_consistent','0'),
                          ('recall_first_mismatch_query','63')):
            with self.subTest(field=key):
                rows=self.samples();rows['current'][0][key]=value
                self.assertFalse(repeated_recall_consistency(rows)['current'])


if __name__=='__main__':unittest.main()
