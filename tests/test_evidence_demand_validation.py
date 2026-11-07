"""The offline counterfactual must reject drift instead of patching loosely."""
import hashlib
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import sys

from run_evidence_demand_validation import PATCHES, apply_variant, explain_actions, compare, boundary_exit_code, main


class CounterfactualPatchTests(unittest.TestCase):
    def invariants(self, delayed=False):
        return [dict(stage=stage,fact=fact,expected=0,actual=0,**{"pass":True})
            for stage,fact in [("isolation","wrong tenant rows"),("isolation","wrong generation rows"),
                ("integrity","all-layout dangling references"),("integrity","projection versus physical refs"),
                ("reopened","returned identity/type/time field violations")]
                + ([("delayed","returned identity/type/time field violations")] if delayed else [])]

    def test_each_patch_is_exact_and_source_scoped(self):
        for variant, (old, new) in PATCHES.items():
            with self.subTest(variant=variant), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                source = root / "src/storage/local_evidence_cache.c"
                source.parent.mkdir(parents=True)
                original = "prefix\n" + old + "\nsuffix\n"
                source.write_text(original)
                receipt = apply_variant(root, variant)
                self.assertEqual(source.read_text(), "prefix\n" + new + "\nsuffix\n")
                self.assertEqual(receipt["before_sha256"], hashlib.sha256(original.encode()).hexdigest())
                self.assertEqual(receipt["after_sha256"], hashlib.sha256(source.read_bytes()).hexdigest())

    def test_missing_or_duplicate_anchor_fails_without_mutating(self):
        for variant, (old, _) in PATCHES.items():
            for occurrences in (0, 2):
                with self.subTest(variant=variant, occurrences=occurrences), tempfile.TemporaryDirectory() as folder:
                    root = Path(folder)
                    source = root / "src/storage/local_evidence_cache.c"
                    source.parent.mkdir(parents=True)
                    original = (old + "\n") * occurrences
                    source.write_text(original)
                    with self.assertRaisesRegex(ValueError, "not unique"):
                        apply_variant(root, variant)
                    self.assertEqual(source.read_text(), original)

    def test_control_and_short_retention_do_not_patch_source(self):
        for variant in ("baseline", "short"):
            with self.subTest(variant=variant), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                source = root / "src/storage/local_evidence_cache.c"
                source.parent.mkdir(parents=True); source.write_text("unchanged\n")
                receipt = apply_variant(root, variant)
                self.assertEqual(source.read_text(), "unchanged\n")
                self.assertEqual(receipt["before_sha256"], receipt["after_sha256"])

    def test_duplicate_representation_is_not_a_second_action(self):
        base=1793100000000000000
        rows=[]
        for path,stamp in [("required-pre.bin",base-1000000000),
                           ("required-anchor.exe",base),
                           ("required-post.bin",base+1000000000),
                           ("required-post.bin",base+1001000000)]:
            rows.append(dict(file_path="C:\\UserData\\"+path,event_time_ns=stamp,
                type=11,pid=97000,endpoint_id="demand-endpoint",process_start_key="97000",
                process_creation_filetime_100ns="133700000000097000",source="context_post"))
        rows[1]["source"]="p0_candidates"
        rows[1]["file_path"]="C:\\Temp\\required-anchor.exe"
        duplicate=copy.deepcopy(rows[1]);duplicate["source"]="context_pre";rows.append(duplicate)
        second=copy.deepcopy(rows[1]);second["file_path"]="C:\\Temp\\second-anchor.exe"
        second["event_time_ns"]=base+100000000;rows.append(second)
        raw=[dict(stage="reopened",fact="required-anchor.exe",expected=1,actual=2,pass_=False)]
        raw[0]["pass"]=raw[0].pop("pass_")
        raw += self.invariants()
        with tempfile.TemporaryDirectory() as folder:
            p=Path(folder);(p/"query-reopened.json").write_text(json.dumps(dict(rows=rows)))
            result=explain_actions(dict(scene="shared_anchor",delay_minutes=0,checks=copy.deepcopy(raw)),p)
            self.assertEqual(result["checks"],raw)
            self.assertEqual(compare(result),"PASS_SYNTHETIC_CONTRACT")
            self.assertEqual(sum(x["duplicate_representation"] for x in result["action_explanations"]),1)
            # Replacing post-two with another copy of post-one must still fail.
            rows[3]=copy.deepcopy(rows[2]);(p/"query-reopened.json").write_text(json.dumps(dict(rows=rows)))
            missing=explain_actions(dict(scene="shared_anchor",delay_minutes=0,checks=copy.deepcopy(raw)),p)
            self.assertEqual(compare(missing,result),"FAIL")
            self.assertEqual(missing["regressions"][0]["fact"],"action:post-two")
            rows[3]=copy.deepcopy(rows[2]);rows[3]["event_time_ns"]=base+1001000000
            rows.pop();(p/"query-reopened.json").write_text(json.dumps(dict(rows=rows)))
            missing=explain_actions(dict(scene="shared_anchor",delay_minutes=0,checks=copy.deepcopy(raw)),p)
            self.assertEqual(compare(missing,result),"FAIL")
            self.assertEqual(missing["regressions"][0]["fact"],"action:second-anchor")

    def test_same_basename_wrong_directory_cannot_satisfy_action(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)
            row=dict(file_path="C:\\UserData\\required-anchor.exe",event_time_ns=1793100000000000000,
                     type=11,pid=97000,endpoint_id="demand-endpoint",process_start_key="97000",
                     process_creation_filetime_100ns="133700000000097000")
            (path/"query-reopened.json").write_text(json.dumps(dict(rows=[row])))
            value=explain_actions(dict(scene="file_anchor",delay_minutes=0,checks=self.invariants()),path)
            self.assertFalse(next(x for x in value["functional_checks"] if x["fact"]=="action:anchor")["pass"])

    def test_required_query_files_and_invariants_cannot_be_skipped(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder);value=dict(scene="file_anchor",delay_minutes=120,checks=self.invariants(delayed=True))
            with self.assertRaisesRegex(ValueError,"required query"):explain_actions(value,path)
            (path/"query-reopened.json").write_text('{"rows":[]}')
            with self.assertRaisesRegex(ValueError,"delayed"):explain_actions(value,path)
            (path/"query-delayed.json").write_text('{"rows":[]}')
            for checks in ([],self.invariants(delayed=True)[:-1]):
                with self.assertRaises(ValueError):explain_actions(dict(value,checks=checks),path)
            for bad in (None,{},[None]):
                (path/"query-delayed.json").write_text(json.dumps(dict(rows=bad)))
                with self.assertRaises(ValueError):explain_actions(value,path)

    def test_empty_duplicate_or_mismatched_check_sets_rejected(self):
        check=self.invariants()[0]
        for checks in ([],[check,check],[{"stage":"x","fact":"y","pass":True}]):
            with self.assertRaises(ValueError):compare(dict(functional_checks=checks))
        with self.assertRaisesRegex(ValueError,"keys differ"):
            compare(dict(functional_checks=self.invariants()),dict(functional_checks=[check]))

    def test_boundary_failure_incomplete_or_duplicate_configuration_is_nonzero(self):
        rows=[dict(variant=v,scene=s,minute=m,status="PASS") for v in ("baseline","tier","short")
              for s in ("file_anchor","priority_anchor","network_anchor") for m in (0,59,60,61)]
        self.assertEqual(boundary_exit_code(rows),0)
        self.assertEqual(boundary_exit_code([]),1)
        self.assertEqual(boundary_exit_code(rows[:-1]),1)
        self.assertEqual(boundary_exit_code(rows[:-1]+[rows[0]]),1)
        rows[-1]["status"]="FAIL";self.assertEqual(boundary_exit_code(rows),1)

    def test_main_propagates_boundary_nonzero(self):
        with tempfile.TemporaryDirectory() as folder, mock.patch("run_evidence_demand_validation.boundary_experiment",return_value=1), \
             mock.patch.object(sys,"argv",["runner","--boundary-from",folder,"--output",str(Path(folder)/"out")]), \
             mock.patch.object(sys,"excepthook",sys.excepthook):
            self.assertEqual(main(),1)


if __name__ == "__main__":
    unittest.main()
