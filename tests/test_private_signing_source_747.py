import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch
spec = importlib.util.spec_from_file_location("bridge", Path(__file__).parents[1] / "scripts/private_signing_bridge.py")
b = importlib.util.module_from_spec(spec)
spec.loader.exec_module(b)
class Source747Tests(unittest.TestCase):
    validation = {
        "EDR_AGENT_RELEASE_TAG": "win_3.2.751",
        "WINDOWS_RELEASE_MODE": "usb",
        "EDR_RELEASE_PACKAGE_SCOPE": "full",
        "EDR_RELEASE_CANDIDATE": "true",
        "EDR_RELEASE_VALIDATION_ONLY": "true",
    }

    def test_exact_manual_candidate_and_existing_trust(self):
        for branch, version, accepted in (
            ("codex/cache-deploy-compat-registry", "3.2.747", True),
            ("codex/cache-deploy-compat-registry", "3.2.748", False),
            ("codex/utm-cache-recall-748", "3.2.748", True),
            ("codex/utm-cache-recall-748", "3.2.747", False),
            ("codex/utm-cache-recall-749", "3.2.749", True),
            ("codex/utm-cache-recall-749", "3.2.748", False),
            ("codex/utm-cache-recall-748", "3.2.749", False),
            ("other", "3.2.749", False),
            ("codex/utm-cache-recall-751", "3.2.751", True),
            ("codex/utm-cache-recall-751", "3.2.750", False),
            ("codex/utm-cache-recall-751", "3.2.752", False),
            ("codex/utm-cache-recall-752", "3.2.751", False),
            ("codex/utm-cache-recall-752", "3.2.752", True),
            ("other", "3.2.752", False),
            ("codex/utm-cache-recall-752", "3.2.753", False),
            ("codex/utm-cache-recall-753", "3.2.752", False),
            ("codex/utm-cache-recall-753", "3.2.753", True),
            ("codex/utm-cache-recall-753", "3.2.754", False),
            ("other", "3.2.753", False),
            ("codex/utm-cache-recall-750", "3.2.751", False),
            ("other", "3.2.751", False),
            ("main", "3.2.748", True),
        ):
            info = dict(repository=dict(full_name=b.SOURCE), head_repository=dict(full_name=b.SOURCE), path=b.RELEASE_WORKFLOW, id=123, run_attempt=1, head_sha="a"*40, status="in_progress", event="workflow_dispatch", head_branch=branch)
            validation = {**self.validation, "EDR_AGENT_RELEASE_TAG": f"win_{version}"}
            with self.subTest(branch=branch, version=version), patch.dict(b.os.environ, validation, clear=True):
                if accepted:
                    b.validate_source("123", "1", "a"*40, version, info)
                else:
                    with self.assertRaises(ValueError): b.validate_source("123", "1", "a"*40, version, info)

    def experimental_candidate(self, patch_version):
        version = f"3.2.{patch_version}"
        validation = {**self.validation, "EDR_AGENT_RELEASE_TAG": f"win_{version}"}
        info = dict(repository=dict(full_name=b.SOURCE), head_repository=dict(full_name=b.SOURCE),
                    path=b.RELEASE_WORKFLOW, id=123, run_attempt=1, head_sha="a"*40,
                    status="in_progress", event="workflow_dispatch",
                    head_branch=f"codex/utm-cache-recall-{patch_version}")
        return version, validation, info

    def test_candidate_requires_matching_release_run_identity(self):
        for patch_version in (751, 752, 753):
            version, validation, info = self.experimental_candidate(patch_version)
            with patch.dict(b.os.environ, validation, clear=True):
                for change in (dict(path=".github/workflows/not-release.yml"), dict(id=124), dict(run_attempt=2),
                               dict(head_sha="c"*40), dict(status="completed"),
                               dict(head_repository=dict(full_name="different/fork"))):
                    with self.subTest(version=version, change=change), self.assertRaises(ValueError):
                        b.validate_source("123", "1", "a"*40, version, {**info, **change})

    def test_experimental_branch_accepts_only_frozen_manual_validation_inputs(self):
        wrong_values = dict(EDR_AGENT_RELEASE_TAG="win_3.2.750", WINDOWS_RELEASE_MODE="signed",
                            EDR_RELEASE_PACKAGE_SCOPE="headless", EDR_RELEASE_CANDIDATE="false",
                            EDR_RELEASE_VALIDATION_ONLY="false")
        for patch_version in (751, 752, 753):
            version, validation, info = self.experimental_candidate(patch_version)
            for key, other in wrong_values.items():
                with self.subTest(version=version, missing=key), patch.dict(b.os.environ, validation, clear=True):
                    del b.os.environ[key]
                    with self.assertRaises(ValueError):
                        b.validate_source("123", "1", "a"*40, version, info)
                with self.subTest(version=version, wrong=key), patch.dict(b.os.environ, {**validation, key: other}, clear=True):
                    with self.assertRaises(ValueError):
                        b.validate_source("123", "1", "a"*40, version, info)
            with patch.dict(b.os.environ, validation, clear=True), self.assertRaises(ValueError):
                b.validate_source("123", "1", "a"*40, version, {**info, "event": "push"})
