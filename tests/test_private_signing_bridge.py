import importlib.util
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("bridge", Path(__file__).parents[1] / "scripts/private_signing_bridge.py")
b = importlib.util.module_from_spec(spec)
spec.loader.exec_module(b)
SHA = "a" * 40
NONCE = "b" * 32


def source():
    return dict(repository=dict(full_name=b.SOURCE), head_repository=dict(full_name=b.SOURCE),
                path=b.RELEASE_WORKFLOW, id=123, run_attempt=2, head_sha=SHA,
                status="in_progress", event="push", head_branch="win_3.2.500")


class BridgeTests(unittest.TestCase):
    def args(self):
        return types.SimpleNamespace(run="123", attempt="2", commit=SHA, version="3.2.500", phase="native", request_id=NONCE)

    def test_supported_release_sources(self):
        b.validate_request("123", "2", SHA, "3.2.500", "native", NONCE)
        for event, branch in (("push", "win_3.2.500"), ("workflow_dispatch", "main")):
            info = source() | dict(event=event, head_branch=branch)
            b.validate_source("123", "2", SHA, "3.2.500", info)

    def test_reject_fork_pr_branch_cancelled_and_stale(self):
        mutations = [dict(repository=dict(full_name="other/repo")), dict(head_repository=dict(full_name="fork/edr-agent")),
                     dict(event="pull_request"), dict(event="workflow_dispatch", head_branch="untrusted"),
                     dict(head_branch="win_3.2.499"), dict(status="completed"), dict(run_attempt=1),
                     dict(head_sha="c" * 40), dict(path=".github/workflows/other.yml"), dict(id=124)]
        for mutation in mutations:
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                b.validate_source("123", "2", SHA, "3.2.500", source() | mutation)

    def test_input_injection_and_unknown_phase(self):
        valid = ["123", "2", SHA, "3.2.500", "native", NONCE]
        for index, value in ((0, "../1"), (1, "0"), (2, "main"), (3, "3.2.500\nX=Y"), (4, "shell"), (5, "abc")):
            args = valid.copy()
            args[index] = value
            with self.subTest(index=index), self.assertRaises(ValueError):
                b.validate_request(*args)

    def artifacts(self):
        return [dict(id=i, name=f"usb-native-request-{arch}", expired=False,
                     workflow_run=dict(id=123, head_sha=SHA)) for i, arch in enumerate(("amd64", "arm64"), 1)]

    def test_artifacts_both_arches_bound_to_source(self):
        self.assertEqual(b.select_artifacts(self.artifacts(), 123, SHA, "native"), ["1", "2"])
        bad = [[], self.artifacts()[:1], self.artifacts() + self.artifacts()[:1],
               [self.artifacts()[0] | dict(expired=True), self.artifacts()[1]],
               [self.artifacts()[0] | dict(workflow_run=dict(id=124, head_sha=SHA)), self.artifacts()[1]],
               [self.artifacts()[0] | dict(workflow_run=dict(id=123, head_sha="c"*40)), self.artifacts()[1]]]
        for items in bad:
            with self.subTest(items=items), self.assertRaises(ValueError):
                b.select_artifacts(items, 123, SHA, "native")

    def test_successful_dispatch_requires_private_completion(self):
        replies = [source(), None, dict(workflow_runs=[dict(id=456, display_title=b.title(123, 2, "native", NONCE))]),
                   dict(status="completed", conclusion="success")]
        with tempfile.TemporaryDirectory() as root, patch.dict(b.os.environ, {"GITHUB_OUTPUT": root+"/output"}), \
                patch.object(b.uuid, "uuid4", return_value=types.SimpleNamespace(hex=NONCE)), \
                patch.object(b, "api", side_effect=replies) as api, patch.object(b.signal, "signal"):
            b.dispatch(self.args())
            self.assertIn("signing_run_id=456", Path(root+"/output").read_text())
            self.assertEqual(api.call_args_list[1].args[1]["inputs"]["source_commit"], SHA)

    def test_failure_and_timeout_cancel_without_success(self):
        for conclusion in ("failure", "cancelled", "timed_out"):
            replies = [source(), None, dict(workflow_runs=[dict(id=456, display_title=b.title(123, 2, "native", NONCE))]),
                       dict(status="completed", conclusion=conclusion), None]
            with patch.object(b.uuid, "uuid4", return_value=types.SimpleNamespace(hex=NONCE)), \
                    patch.object(b, "api", side_effect=replies) as api, patch.object(b, "output") as output, \
                    patch.object(b.signal, "signal"), self.assertRaises(RuntimeError):
                b.dispatch(self.args())
            output.assert_not_called()
            self.assertTrue(api.call_args.args[0].endswith("/456/cancel"))

    def test_timeout_is_bounded(self):
        with patch.object(b.uuid, "uuid4", return_value=types.SimpleNamespace(hex=NONCE)), \
                patch.object(b, "api", side_effect=[source(), None]), patch.object(b.signal, "signal"), \
                patch.object(b.time, "monotonic", side_effect=[0, 1801]), self.assertRaises(TimeoutError):
            b.dispatch(self.args())

    def test_bridge_has_no_usb_host_and_all_callers_pass_secret(self):
        root = Path(__file__).parents[1]
        bridge = (root/".github/workflows/windows-usb-sign-files.yml").read_text()
        self.assertNotIn("runs-on: [self-hosted", bridge)
        self.assertIn("repository: qiuxinliang/edr-agent-signing", bridge)
        release = (root/".github/workflows/edr-agent-client-release.yml").read_text()
        self.assertEqual(release.count("USB_SIGNING_TOKEN: ${{ secrets.USB_SIGNING_TOKEN }}"), 3)


if __name__ == "__main__":
    unittest.main()
