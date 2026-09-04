import importlib.util
from pathlib import Path
import unittest


SCRIPT = Path(__file__).parents[1] / "scripts" / "classify_windows_upgrade.py"
SPEC = importlib.util.spec_from_file_location("classify_windows_upgrade", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


class ClassifyWindowsUpgradeTests(unittest.TestCase):
    def test_source_only_change_defaults_to_runtime_bundle(self):
        result, _ = MODULE.classify_paths([
            "include/edr/collector.h",
            "scripts/classify_windows_upgrade.py",
            "src/collector/collector_win.c",
            "tests/test_collector.c",
        ])
        self.assertEqual("runtime_bundle", result)

    def test_automatic_classification_never_claims_binary_hot(self):
        samples = [
            ["src/core/agent.c"],
            ["src/installer_worker/installer_worker_win.c"],
            ["README.md", "VERSION"],
            ["CMakeLists.txt"],
            [],
        ]
        for paths in samples:
            with self.subTest(paths=paths):
                result, _ = MODULE.classify_paths(paths)
                self.assertNotEqual("binary_hot", result)

    def test_lifecycle_helper_change_requires_runtime_bundle(self):
        result, _ = MODULE.classify_paths(["src/installer_worker/installer_worker_win.c"])
        self.assertEqual("runtime_bundle", result)

    def test_updater_and_layout_changes_require_installer(self):
        for path in ("scripts/edr_agent_inplace_update.ps1", "CMakeLists.txt", "package-capabilities.json"):
            with self.subTest(path=path):
                result, _ = MODULE.classify_paths([path])
                self.assertEqual("installer_required", result)

    def test_mixed_changes_choose_highest_risk(self):
        result, _ = MODULE.classify_paths([
            "src/collector/collector_win.c",
            "src/installer_worker/installer_worker_win.c",
            "install/windows-inno/EDRAgentSetup.bundled.iss",
        ])
        self.assertEqual("installer_required", result)

    def test_missing_diff_fails_closed(self):
        result, _ = MODULE.classify_paths([])
        self.assertEqual("installer_required", result)

    def test_unknown_build_or_workflow_change_fails_closed(self):
        result, _ = MODULE.classify_paths([".github/workflows/edr-agent-client-release.yml"])
        self.assertEqual("installer_required", result)

    def test_operator_cannot_downgrade_installer_required_change(self):
        for override in ("binary_hot", "runtime_bundle"):
            with self.subTest(override=override):
                with self.assertRaises(ValueError):
                    MODULE.resolve_upgrade_class(["CMakeLists.txt"], override)

    def test_binary_hot_override_requires_post_build_proof(self):
        for path in (
            "include/edr/agent.h",
            "scripts/classify_windows_upgrade.py",
            "src/core/agent.c",
        ):
            with self.subTest(path=path):
                result, reasons = MODULE.resolve_upgrade_class([path], "binary_hot")
                self.assertEqual("binary_hot", result)
                self.assertIn("post-build component identity proof", reasons[0])

    def test_operator_can_promote_runtime_change_to_installer(self):
        result, _ = MODULE.resolve_upgrade_class(["src/core/agent.c"], "installer_required")
        self.assertEqual("installer_required", result)


if __name__ == "__main__":
    unittest.main()
