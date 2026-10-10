"""Exercise real redirected descriptors, backup retention, restart and failure."""
import argparse
from pathlib import Path
import stat
import subprocess
import sys
import tempfile

parser = argparse.ArgumentParser()
parser.add_argument("--client", required=True)
args = parser.parse_args()


def run_client(root, mode):
    try:
        subprocess.run([args.client, str(root), mode], check=True)
    except (OSError, subprocess.SubprocessError):
        # Only this test's fresh synthetic fixture is inspected. Never read
        # installed-agent logs, configuration, or external/private inputs.
        for name in ("agent.log", "headless.trace"):
            path = root / name
            try:
                info = path.lstat()
                if not stat.S_ISREG(info.st_mode) or getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0):
                    continue
                with path.open("rb") as stream:
                    stream.seek(max(0, info.st_size - 2048))
                    tail = stream.read(2048).decode("utf-8", errors="replace")
                print(f"synthetic logging fixture {mode}: {name} tail (max 2048 bytes):\n{tail}", file=sys.stderr)
            except OSError as error:
                print(f"synthetic logging fixture diagnostic unavailable: {name}: {type(error).__name__}", file=sys.stderr)
        raise


with tempfile.TemporaryDirectory(prefix="edr-log-rotation-") as temp:
    root = Path(temp)
    run_client(root, "rotate")
    assert (root / "agent.log").read_text() == "after-rotation\n"
    assert (root / "agent.log.1").read_text().startswith("cycle-2\n")
    assert (root / "agent.log.2").read_text().startswith("cycle-1\n")
    assert not (root / "agent.log.3").exists()
    run_client(root, "restart")
    assert (root / "agent.log").read_text() == "after-rotation\nafter-restart\nafter-failed-config\n"
    run_client(root, "reduce-retention")
    assert (root / "agent.log.1").exists() and not (root / "agent.log.2").exists()
with tempfile.TemporaryDirectory(prefix="edr-log-rotation-failure-") as temp:
    root = Path(temp)
    # A nonempty backup directory rejects removal/rename on every platform.
    (root / "agent.log.2").mkdir()
    (root / "agent.log.2" / "preserved").write_text("fixture")
    run_client(root, "rename-failure")
    data = (root / "agent.log").read_text()
    assert "rotation failed" in data and data.endswith("after-failed-rotation\n")

with tempfile.TemporaryDirectory(prefix="edr-log-zero-backup-") as temp:
    root = Path(temp)
    run_client(root, "zero-backups")
    assert (root / "agent.log").read_text() == "after-truncation\n"
    assert not (root / "agent.log.1").exists()

with tempfile.TemporaryDirectory(prefix="edr-log-rebind-retention-") as temp:
    root = Path(temp)
    run_client(root, "replacement-failure-retention")
    assert not (root / "agent.log").exists()
    assert (root / "agent.log.1").read_text().endswith("after-pending-retention-failure\n")

with tempfile.TemporaryDirectory(prefix="edr-log-buffering-failure-") as temp:
    root = Path(temp)
    run_client(root, "buffering-failure-config")
    data = (root / "agent.log").read_text()
    assert data.startswith("before-buffering-failure\n")
    assert "configuration failed" in data
    assert data.endswith("after-buffering-failure\nstdout-after-buffering-failure\n")
    assert (root / "replacement" / "agent.log").read_bytes() == b""
