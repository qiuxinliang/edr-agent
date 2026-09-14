import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
from typing import Optional
import unittest
import zipfile


SCRIPT = Path(__file__).parents[1] / "scripts" / "verify_binary_hot_compatibility.py"
SPEC = importlib.util.spec_from_file_location("verify_binary_hot_compatibility", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


class VerifyBinaryHotCompatibilityTests(unittest.TestCase):
    def package(
        self,
        root: Path,
        name: str,
        *,
        worker: bytes = b"worker",
        dll: bytes = b"dll",
        collector: Optional[bytes] = b"collector",
    ) -> Path:
        components = {
            "FDSecurityInstallerWorker.exe": worker,
            "uninstall.exe": b"uninstaller",
            "runtime.dll": dll,
        }
        if collector is not None:
            components[MODULE.FORENSIC_BUILTIN] = collector
        manifest = {
            "schema": "edr.windows.native-package-integrity.v1",
            "files": [
                {"name": component, "sha256": hashlib.sha256(content).hexdigest()}
                for component, content in components.items()
            ],
        }
        path = root / name
        with zipfile.ZipFile(path, "w") as archive:
            for component, content in components.items():
                archive.writestr(component, content)
            archive.writestr("native-package-integrity.json", json.dumps(manifest))
            archive.writestr("FDSensor.exe", name.encode())
            archive.writestr("VERSION", name)
        return path

    def test_allows_only_agent_binary_and_version_change(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            MODULE.verify_binary_hot_compatibility(
                self.package(root, "previous.zip"), self.package(root, "current.zip")
            )

    def test_rejects_lifecycle_component_change(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            previous = self.package(root, "previous.zip")
            current = self.package(root, "current.zip", worker=b"new worker")
            with self.assertRaisesRegex(ValueError, "hashes changed"):
                MODULE.verify_binary_hot_compatibility(previous, current)

    def test_rejects_runtime_dll_change(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            previous = self.package(root, "previous.zip")
            current = self.package(root, "current.zip", dll=b"new dll")
            with self.assertRaisesRegex(ValueError, "hashes changed"):
                MODULE.verify_binary_hot_compatibility(previous, current)

    def test_accepts_legacy_packages_without_forensic_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            MODULE.verify_binary_hot_compatibility(
                self.package(root, "previous.zip", collector=None),
                self.package(root, "current.zip", collector=None),
            )

    def test_rejects_forensic_component_addition_or_change(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            legacy = self.package(root, "legacy.zip", collector=None)
            current = self.package(root, "current.zip")
            with self.assertRaisesRegex(ValueError, "component set changed"):
                MODULE.verify_binary_hot_compatibility(legacy, current)

            changed = self.package(root, "changed.zip", collector=b"new collector")
            with self.assertRaisesRegex(ValueError, "hashes changed"):
                MODULE.verify_binary_hot_compatibility(current, changed)

    def test_rejects_forensic_component_missing_from_manifest_or_zip(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            package = self.package(root, "package.zip")
            with zipfile.ZipFile(package, "r") as archive:
                entries = {info.filename: archive.read(info) for info in archive.infolist()}

            manifest = json.loads(entries["native-package-integrity.json"])
            manifest["files"] = [
                item for item in manifest["files"] if item["name"] != MODULE.FORENSIC_BUILTIN
            ]
            entries["native-package-integrity.json"] = json.dumps(manifest).encode("utf-8")
            unbound = root / "unbound.zip"
            with zipfile.ZipFile(unbound, "w") as archive:
                for name, content in entries.items():
                    archive.writestr(name, content)
            with self.assertRaisesRegex(ValueError, "forensic runtime component is missing or unbound"):
                MODULE.runtime_identity(unbound)

            del entries[MODULE.FORENSIC_BUILTIN]
            manifest["files"].append(
                {
                    "name": MODULE.FORENSIC_BUILTIN,
                    "sha256": hashlib.sha256(b"collector").hexdigest(),
                }
            )
            entries["native-package-integrity.json"] = json.dumps(manifest).encode("utf-8")
            missing = root / "missing.zip"
            with zipfile.ZipFile(missing, "w") as archive:
                for name, content in entries.items():
                    archive.writestr(name, content)
            with self.assertRaisesRegex(ValueError, "forensic runtime component is missing or unbound"):
                MODULE.runtime_identity(missing)

    def test_rejects_runtime_dll_not_bound_by_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            original = self.package(root, "original.zip")
            unbound = root / "unbound.zip"
            with zipfile.ZipFile(original) as source, zipfile.ZipFile(unbound, "w") as target:
                for info in source.infolist():
                    data = source.read(info)
                    if info.filename == "native-package-integrity.json":
                        manifest = json.loads(data)
                        manifest["files"] = [entry for entry in manifest["files"] if entry["name"] != "runtime.dll"]
                        data = json.dumps(manifest).encode()
                    target.writestr(info, data)
            with self.assertRaisesRegex(ValueError, "not bound"):
                MODULE.runtime_identity(unbound)


if __name__ == "__main__":
    unittest.main()
