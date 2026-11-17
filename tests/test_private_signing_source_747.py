import importlib.util
from pathlib import Path
import unittest
spec = importlib.util.spec_from_file_location("bridge", Path(__file__).parents[1] / "scripts/private_signing_bridge.py")
b = importlib.util.module_from_spec(spec)
spec.loader.exec_module(b)
class Source747Tests(unittest.TestCase):
    def test_exact_manual_candidate_and_existing_trust(self):
        for branch, version, accepted in [("codex/cache-deploy-compat-registry", "3.2.747", True), ("codex/cache-deploy-compat-registry", "3.2.748", False), ("other", "3.2.747", False), ("main", "3.2.748", True)]:
            info = dict(repository=dict(full_name=b.SOURCE), head_repository=dict(full_name=b.SOURCE), path=b.RELEASE_WORKFLOW, id=123, run_attempt=1, head_sha="a"*40, status="in_progress", event="workflow_dispatch", head_branch=branch)
            with self.subTest(branch=branch, version=version):
                if accepted:
                    b.validate_source("123", "1", "a"*40, version, info)
                else:
                    with self.assertRaises(ValueError): b.validate_source("123", "1", "a"*40, version, info)
