import importlib.util
from pathlib import Path
import unittest


SCRIPT = Path(__file__).parents[1] / "scripts" / "classify_windows_upgrade.py"
SPEC = importlib.util.spec_from_file_location("classify_windows_upgrade", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


class ClassifyWindowsUpgradeTests(unittest.TestCase):
    def test_binary_only_change_is_hot(self):
        result, _ = MODULE.classify_paths(["src/collector/collector_win.c", "tests/test_collector.c"])
        self.assertEqual("binary_hot", result)

    def test_lifecycle_helper_change_requires_runtime_bundle(self):
        result, _ = MODULE.classify_paths(["src/installer_worker/installer_worker_win.c"])
        self.assertEqual("runtime_bundle", result)

    def test_updater_and_layout_changes_require_installer(self):
        for path in ("scripts/edr_agent_inplace_update.ps1", "CMakeLists.txt", "models/static.onnx"):
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


if __name__ == "__main__":
    unittest.main()
